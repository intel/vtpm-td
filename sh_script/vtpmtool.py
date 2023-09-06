# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

import inspect
import json
import logging
import os
import shutil
import socket
import subprocess
import threading
import paramiko
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List

import psutil
import tomli

LOG = logging.getLogger(__name__)

@contextmanager
def vtpm_context():
    """
    Create a VtpmTool instance with default user id. Cleanup when out of scope.

    In most cases that are not necessary to run multiple pairs of TDs at the same time, use this method with `with` statement.
    """
    tool = VtpmTool(use_default_user_id=True)
    try:
        yield tool
    finally:
        tool.cleanup()


class VtpmTool:
    log_dir_name = f"log_{int(time.time())}"
    max_stdout_save_size = 4096
    short_id_counter = 0

    def __init__(self, use_default_user_id: bool = False):
        self.use_default_user_id = use_default_user_id

        # variables from the config file
        self.qemu: str = None
        self.vtpm_td_script: str = None
        self.user_td_script: str = None
        self.vtpm_td_bios_img: str = None
        self.user_td_bios_img: str = None
        self.kernel_img: str = None
        self.guest_img: str = None
        self.guest_username: str = None
        self.guest_password: str = None
        self.vtpm_test_img: str = None
        self.vtpm_test_img_mount_path: str = None
        self.default_user_id: str = None
        self.default_startup_cmds: List[str] = None
        self.default_wait_tools_run_seconds: int = None
        cfg = self._parse_toml_config()
        for k, v in cfg.items():
            setattr(self, k, v)

        # other variables to init
        self._threads: Dict[str, threading.Thread] = {}
        self._host_procs: Dict[str, subprocess.Popen] = {}
        self._td_stdout_saved: Dict[str, dict] = {}
        self._lock = threading.Lock() # to safely access `_td_stdout_saved`

        self.startup_cmds = self.default_startup_cmds
        self.wait_tools_run_seconds = self.default_wait_tools_run_seconds
        self.user_id = self.default_user_id if use_default_user_id else self._new_guid()
        
        self.ssh = None

        LOG.debug(f"Read config from file: {cfg}")

    @property
    def use_replica_img(self) -> bool:
        # reserve the same logic with launch script: if pass default user id, qemu uses origial image
        return not self.use_default_user_id

    def default_run_and_terminate(self):
        """
        Launch vtpm td and user td then terminate all tds.

        To simplify the test, use this method in case the test needs to start and stop one vtpm td and one user td simultaneously.
        """
        self.start_vtpm_td()
        self.execute_qmp()
        self.start_user_td()
        self.cleanup()

    def read_log(self, filename: str, auto_delete: bool = True) -> str:
        """
        Read log file in guest file system and return content in string.

        This will mount the qemu image and unmount after reading.
        """
        self.mount_vtpm_test_img()
        file = os.path.join(self.vtpm_test_img_mount_path, filename)
        try:
            # the encoding of `>` redirect ouput is UCS-2 (UTF-16), ref: https://uefi.org/sites/default/files/resources/UEFI_Shell_2_2.pdf 3.4.4.1
            with open(file, "r", encoding="utf-16") as f:
                text = f.read()
            LOG.debug(f"Read '{file}' ok: {len(text)}")
            if auto_delete:
                self._exec_shell_cmd(f"sudo rm -f {file}")
            return text
        except Exception as e:
            LOG.error(f"An error occurred when read '{filename}': {e}")
        finally:
            self.unmount_vtpm_test_img()
        return ""

    def read_console(self) -> str:
        """
        Read console print of a terminated user td and return content in string.
        """
        user_td_thread = self._threads.get("user_td")
        if user_td_thread:
            user_td_thread.join()
        with self._lock:
            user_td_out = self._td_stdout_saved.get("user_td")
        return user_td_out["stdout"] if user_td_out else ""

    def generate_startup_into_vtpm_test_img(self, startup_cmds: List[str] = None) -> bool:
        """
        Create `startup.nsh` with default commands in config, and add the script into qemu image.
        Use this method when the user td is not running.

        Pass `startup_cmds` argument to overwrite default commands.
        """

        if self.use_replica_img:
            replica_img = self._copy_qemu_image()
            self.vtpm_test_img = replica_img
            LOG.debug(f"Image name updated: {self.vtpm_test_img}")

        self.mount_vtpm_test_img()
        startup_nsh = "\n".join(startup_cmds or self.startup_cmds)
        wrote = self._write_uefi_startup_script(startup_file_content=startup_nsh)
        self.unmount_vtpm_test_img()
        LOG.debug(
            f"Write startup.nsh into qemu image '{self.vtpm_test_img}': {len(wrote)}"
        )
        return len(wrote) != 0

    def mount_vtpm_test_img(self):
        """
        Mount QEMU image to host mount point.
        """
        self._exec_shell_cmd(f"sudo mount {self.vtpm_test_img} {self.vtpm_test_img_mount_path}")

    def unmount_vtpm_test_img(self):
        """
        Unmount QEMU image.
        """
        self._exec_shell_cmd(f"sudo umount {self.vtpm_test_img_mount_path}")

    def start_vtpm_td(self):
        """
        Start vtpm td alone.
        """
        thread_vtpm = threading.Thread(
            target=self._exec_shell_cmd,
            args=(
                f"bash {self.vtpm_td_script} -q {self.qemu} -f {self.vtpm_td_bios_img} -u {self.user_id}",
                "vtpm_td",
            ),
        )
        LOG.debug(f"Starting vtpm td ({self.user_id})")
        thread_vtpm.start()
        self._threads["vtpm_td"] = thread_vtpm
        time.sleep(5)

    def start_user_td(self, with_guest_kernel: bool = False, grub_boot = False):
        """
        Start user td alone.
        """
        boot_to = "os" if with_guest_kernel else "shell"

        if grub_boot:
            guest_img=self.guest_img.replace("test", "test-sb")
            thread_user = threading.Thread(
                target=self._exec_shell_cmd,
                args=(
                    f"bash {self.user_td_script} -q {self.qemu} -f {self.user_td_bios_img} -i {guest_img} -v {self.vtpm_test_img} -k {self.kernel_img} -u {self.user_id} -t {boot_to} -g",
                    "user_td",
                ),
            )
        else:
            thread_user = threading.Thread(
                target=self._exec_shell_cmd,
                args=(
                    f"bash {self.user_td_script} -q {self.qemu} -f {self.user_td_bios_img} -i {self.guest_img} -v {self.vtpm_test_img} -k {self.kernel_img} -u {self.user_id} -t {boot_to}",
                    "user_td",
                ),
            )
        LOG.debug(f"Starting user td ({self.user_id})")
        thread_user.start()
        self._threads["user_td"] = thread_user

        # wait for tools run
        time.sleep(self.wait_tools_run_seconds)

    def execute_qmp(self):
        """
        Execute qmp commands alone.
        """
        QMP_SOCK = f"/tmp/qmp-sock-vtpm-{self.user_id}"
        QMP_CMDS = [
            {"execute": "qmp_capabilities"},
            {
                "execute": "tdx-vtpm-create-instance",
                "arguments": {"user-id": self.user_id},
            },
        ]
        self._send_qmp_cmds(QMP_SOCK, QMP_CMDS)
        
    def connect_ssh(self):
        """
        Connect vm with ssh.
        """
        timeout = 60
        if self.ssh == None:
                self.ssh = paramiko.SSHClient()
                self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        while(timeout > 0):
            try:
                self.ssh.connect(hostname="localhost", port=10038, username=self.guest_username, password=self.guest_password)
                return
            except Exception:
                time.sleep(1)
                timeout -= 1
        if timeout == 0:
            raise BaseException("Connection time out")
    
    def exec_ssh_command(self, command):
        """
        Execute shell command.
        """
        stdin, stdout, stderr = self.ssh.exec_command(command)

        return [stdout.read().decode(), stderr.read().decode()]
    
    def create_key_enroll(self, key):

        cmd = f"chmod 777 {self.fd_folder_path}\n"
        self.get_cmd_result(cmd)

        cmd = f"echo sudo /usr/local/bin/ovmfkeyenroll -fd {self.fd_folder_path}/OVMF.fd >> key-enroll.sh \\\\\n"
        self.get_cmd_result(cmd)

        cmd = f"echo -pk {key} {SECURE_BOOT_PATH}/PK.cer >> key-enroll.sh \\\\\n"
        self.get_cmd_result(cmd)

        cmd = f"echo -kek {key} {SECURE_BOOT_PATH}/KEK.cer >> key-enroll.sh \\\\\n"
        self.get_cmd_result(cmd)

        cmd = f"echo -db {key} {SECURE_BOOT_PATH}/DB.cer >> key-enroll.sh\n"
        self.get_cmd_result(cmd)

        cmd = 'ls\n'
        out_result = self.get_cmd_result(cmd)

        if "key-enroll.sh" not in out_result:
            self.case_logger.error("not found 'key-enroll.sh'")
            return False

        cmd = 'chmod 744 key-enroll.sh\n'
        self.get_cmd_result(cmd)
        return True 
    
    def terminate_vtpm_td(self):
        """
        Terminate the vtpm td qemu process with SIGTERM alone.
        """
        root_proc = self._host_procs.get("vtpm_td")
        self._try_terminate_procs(root_proc)

    def terminate_user_td(self):
        """
        Terminate the user td qemu process with SIGTERM alone.
        """
        root_proc = self._host_procs.get("user_td")
        self._try_terminate_procs(root_proc)

    def terminate_all_tds(self):
        """
        Terminate all td qemu processes with SIGTERM.
        """
        if len(self._host_procs) == 0:
            return
        self.terminate_user_td()
        self.terminate_vtpm_td()
        self._host_procs = {}

    def cleanup(self):
        """
        Clear storage of threads and processes. And make sure all qemu procs have been terminated.
        """
        self.terminate_all_tds()
        self._wait_td_threads()
        self._threads = {}
        self._host_procs = {}
        self._td_stdout_saved = {}

    def _parse_toml_config(self) -> dict:
        with open("conf/pyproject.toml", "rb") as f:
            cfg = tomli.load(f)
        return cfg["vtpm"]["config"]

    def _try_terminate_procs(self, popen: subprocess.Popen):
        if not popen:
            return
        try:
            root = psutil.Process(popen.pid)
            root_cmd = " ".join(root.cmdline())
            childs = root.children(recursive=True)
            LOG.debug(
                f"Terminate subprocess {list(map(lambda p: p.cmdline()[0], childs))} launched by '{root_cmd}'"
            )
        except psutil.NoSuchProcess:
            LOG.debug("Failed to terminate subprocess: NoSuchProcess")
            return
        for child in childs:
            child.terminate()
        root.terminate()

    def _wait_td_threads(self):
        for _, thread in self._threads.items():
            thread.join()
        self._threads = {}

    def _write_uefi_startup_script(self, startup_file_content: str) -> str:
        file = os.path.join("/tmp", "tmp-usertd-startup")
        try:
            with open(file, "w+") as f:
                f.write(startup_file_content)
        except Exception as e:
            LOG.error(f"An error occurred when write 'tmp-usertd-startup': {e}")
            return ""
        _, stderr = self._exec_shell_cmd(
            command=f"sudo cp {file} {os.path.join(self.vtpm_test_img_mount_path, 'startup.nsh')}"
        )
        if len(stderr) != 0:
            LOG.error(f"An error occurred when copy file: {stderr}")
            return ""
        return startup_file_content

    def _exec_shell_cmd(self, command: str, tag: str = None) -> tuple:
        proc = subprocess.Popen(
            command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if tag:
            self._host_procs[tag] = proc
        output, error = proc.communicate()
        stdout, stderr = output.decode().strip(), error.decode().strip()

        if tag in ["vtpm_td", "user_td"]:
            with self._lock:
                self._td_stdout_saved[tag] = {
                    "stdout": stdout[: self.max_stdout_save_size],
                    "stderr": stderr[: self.max_stdout_save_size],
                }
        log_msg = f"Execute `{command}`, stdout: {stdout or 'null'}, stderr: {stderr or 'null'}"
        if stderr:
            LOG.warning(log_msg)
        else:
            LOG.debug(log_msg)
        return (stdout, stderr)

    def _send_qmp_cmds(self, unix_sock: str, cmds: List[dict]):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(unix_sock)
        LOG.debug(f"Socket connected: {unix_sock}")
        # receive hello msg
        r = sock.recv(1024)
        r_str = r.decode("utf-8").replace("\n", "").replace("\r", "")
        LOG.debug(f"QMP recv: {r_str}")
        # send commands
        for command_json in cmds:
            send_str = json.dumps(command_json)
            send_str += "\n"
            LOG.debug(f"QMP send: {send_str.encode('utf-8')}")
            sock.sendall(send_str.encode("utf-8"))
            time.sleep(0.5)

            r = sock.recv(1024)
            r_str = r.decode("utf-8").replace("\n", "").replace("\r", "")
            LOG.debug(f"QMP recv: {r_str}")
        sock.close()

    def _inspect_pytest_tc_name(self):
        func_list = list(map(lambda frame: frame.function, inspect.stack()))
        # search test case name by pytest convention
        tc_func_idx = func_list.index("pytest_pyfunc_call") - 1
        if tc_func_idx > 0 and func_list[tc_func_idx].startswith("test_"):
            return func_list[tc_func_idx]
        else:
            return ""

    def _copy_qemu_image(self) -> str:
        # check if vtpm_test_img is already a replica img
        if self.vtpm_test_img.endswith(self.user_id):
            return self.vtpm_test_img  # no need to copy

        prototype_img = self.vtpm_test_img
        replica_img = f"{os.path.basename(prototype_img)}.{self.user_id}"
        if Path(replica_img).exists():
            LOG.debug(
                f"Replica image won't be created because '{replica_img}' exists"
            )
            return replica_img
        try:
            dst = shutil.copy2(prototype_img, replica_img)
            LOG.debug(f"Replica image created: {dst}")
        except Exception as e:
            LOG.error(
                f"An error occurred when copy from {prototype_img} to {replica_img}"
            )
            return None
        return replica_img

    def _new_guid(self) -> str:
        id = uuid.uuid4()
        VtpmTool.short_id_counter += 1
        return f"{VtpmTool.short_id_counter:03d}{str(id)[3:]}"
