import inspect
import json
import logging
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Dict, List

import psutil
import tomli


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
        # self.workdir: str = None
        self.vtpm_td_script: str = None
        self.user_td_script: str = None
        self.vtpm_td_bios_img: str = None
        self.user_td_bios_img: str = None
        self.kernel_img: str = None
        self.guest_img: str = None
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

        # setup logger
        self.logger = self._get_unique_logger()
        self.logger.debug(f"Read config from file: {cfg}")

    @property
    def use_replica_img(self) -> bool:
        # reserve the same logic with launch script: if pass default user id, qemu uses origial image
        return not self.use_default_user_id

    def default_run_and_terminate(self):
        """
        Launch vtpm td and user td then terminate all tds.

        To simplify the test, use this method in case the test needs to start and stop one vtpm td and one user td simultaneously.
        """
        # os.chdir(self.workdir)
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
            self.logger.debug(f"Read '{file}' ok: {len(text)}")
            if auto_delete:
                self._exec_shell_cmd(f"sudo rm -f {file}")
            return text
        except Exception as e:
            self.logger.error(f"An error occurred when read '{filename}': {e}")
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
            self.logger.debug(f"Image name updated: {self.vtpm_test_img}")

        self.mount_vtpm_test_img()
        startup_nsh = "\n".join(startup_cmds or self.startup_cmds)
        wrote = self._write_uefi_startup_script(startup_file_content=startup_nsh)
        self.unmount_vtpm_test_img()
        self.logger.debug(
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
                f"bash {self.vtpm_td_script} -f {self.vtpm_td_bios_img} -u {self.user_id}",
                "vtpm_td",
            ),
        )
        self.logger.debug(f"Starting vtpm td ({self.user_id})")
        thread_vtpm.start()
        self._threads["vtpm_td"] = thread_vtpm
        time.sleep(5)

    def start_user_td(self, with_guest_kernel: bool = False):
        """
        Start user td alone.
        """
        boot_to = "os" if with_guest_kernel else "shell"

        thread_user = threading.Thread(
            target=self._exec_shell_cmd,
            args=(
                f"bash {self.user_td_script} -f {self.user_td_bios_img} -i {self.guest_img} -k {self.kernel_img} -u {self.user_id} -t {boot_to}",
                "user_td",
            ),
        )
        self.logger.debug(f"Starting user td ({self.user_id})")
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
        with open("pyproject.toml", "rb") as f:
            cfg = tomli.load(f)
        return cfg["vtpm"]["config"]

    def _get_unique_logger(self) -> logging.Logger:
        fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        lg = logging.getLogger(f"{__name__}_{self.user_id}")
        lg.setLevel(logging.DEBUG)

        log_path = Path(os.path.join(self.log_dir_name, self._inspect_pytest_tc_name()))
        log_path.mkdir(parents=True, exist_ok=True)
        log_name = f"{self.user_id}.log"
        file_handler = logging.FileHandler(os.path.join(log_path, log_name), "w+")
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(fmt)
        lg.addHandler(file_handler)
        return lg

    def _try_terminate_procs(self, popen: subprocess.Popen):
        if not popen:
            return
        try:
            root = psutil.Process(popen.pid)
            root_cmd = " ".join(root.cmdline())
            childs = root.children(recursive=True)
            self.logger.debug(
                f"Terminate subprocess {list(map(lambda p: p.cmdline()[0], childs))} launched by '{root_cmd}'"
            )
        except psutil.NoSuchProcess:
            self.logger.error("Failed to terminate subprocess: NoSuchProcess")
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
            self.logger.error(f"An error occurred when write 'tmp-usertd-startup': {e}")
            return ""
        _, stderr = self._exec_shell_cmd(
            command=f"sudo cp {file} {os.path.join(self.vtpm_test_img_mount_path, 'startup.nsh')}"
        )
        if len(stderr) != 0:
            self.logger.error(f"An error occurred when copy file: {stderr}")
            return ""
        return startup_file_content

    def _exec_shell_cmd(self, command: str, tag: str = None) -> tuple:
        # os.chdir(self.workdir)
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
            self.logger.warning(log_msg)
        else:
            self.logger.debug(log_msg)
        return (stdout, stderr)

    def _send_qmp_cmds(self, unix_sock: str, cmds: List[dict]):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(unix_sock)
        self.logger.debug(f"Socket connected: {unix_sock}")
        # receive hello msg
        r = sock.recv(1024)
        r_str = r.decode("utf-8").replace("\n", "").replace("\r", "")
        self.logger.debug(f"QMP recv: {r_str}")
        # send commands
        for command_json in cmds:
            send_str = json.dumps(command_json)
            send_str += "\n"
            self.logger.debug(f"QMP send: {send_str.encode('utf-8')}")
            sock.sendall(send_str.encode("utf-8"))
            time.sleep(0.5)

            r = sock.recv(1024)
            r_str = r.decode("utf-8").replace("\n", "").replace("\r", "")
            self.logger.debug(f"QMP recv: {r_str}")
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

        # os.chdir(self.workdir)
        prototype_img = self.vtpm_test_img
        replica_img = f"{prototype_img}.{self.user_id}"
        if Path(replica_img).exists():
            self.logger.debug(
                f"Replica image won't be created because '{replica_img}' exists"
            )
            return replica_img
        try:
            dst = shutil.copy2(prototype_img, replica_img)
            self.logger.debug(f"Replica image created: {dst}")
        except Exception as e:
            self.logger.error(
                f"An error occurred when copy from {prototype_img} to {replica_img}"
            )
            return None
        return replica_img

    def _new_guid(self) -> str:
        id = uuid.uuid4()
        VtpmTool.short_id_counter += 1
        return f"{VtpmTool.short_id_counter:03d}{str(id)[3:]}"
