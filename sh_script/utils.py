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
        self.quote_verification_sample_path: str = None
        self.stress_test_cycles: str = None
        self.default_user_id: str = None
        self.default_startup_cmds: List[str] = None
        cfg = self._parse_toml_config()
        for k, v in cfg.items():
            setattr(self, k, v)

        # other variables to init
        self._threads: Dict[str, threading.Thread] = {}
        self._host_procs: Dict[str, subprocess.Popen] = {}

        self.startup_cmds = self.default_startup_cmds
        self.wait_tools_run_seconds = 0
        self.user_id = self.default_user_id if use_default_user_id else self._new_guid()
        
        self.ssh = None
        # terminate all tds before test execution
        self.cleanup()

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
        time.sleep(2)

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
        if not with_guest_kernel:
            time.sleep(self.wait_tools_run_seconds)

    def execute_qmp(self, is_create=True):
        """
        Execute qmp commands alone.
        """
        if is_create:
            cmd = "tdx-vtpm-create-instance"
        else:
            cmd = "tdx-vtpm-destroy-instance"
        
        QMP_SOCK = f"/tmp/qmp-sock-vtpm-{self.user_id}"
        QMP_CMDS = [
            {"execute": "qmp_capabilities"},
            {
                "execute": cmd,
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
    
    def exec_ssh_command(self, command, encodingtype:str = 'utf-8'):
        """
        Execute shell command.
        """
        stdin, stdout, stderr = self.ssh.exec_command(command)

        return [stdout.read().decode(encoding=encodingtype), stderr.read().decode(encoding=encodingtype)]

    
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

        log_msg = f"Execute `{command}`, stdout: {stdout or 'null'}, stderr: {stderr or 'null'}"
        if stderr:
            LOG.warning("\n".join(log_msg.split("\n")[-20:-1]))
        else:
            LOG.debug("\n".join(log_msg.split("\n")[-20:-1]))
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
    
    def pcr_replay(self):
        # pcr 0 1 2 3 4 5 6 7 9
        pcr_num = 10
        # Read PCR value sha256
        cmd = f'tpm2_pcrread sha256'
        runner = self.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr256_values = []
        for num in range(pcr_num):
            pcr256_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value sha384
        cmd = f'tpm2_pcrread sha384'
        runner = self.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr384_values = []
        for num in range(pcr_num):
            pcr384_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value in event log
        cmd = f'tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements'
        runner = self.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        event_log_pcr = runner[0]
        
        for num in range(pcr_num):
            if num != 8:
                assert pcr256_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)
                assert pcr384_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)

    def vtpm_simple_attestation(self):
        # Device-Node creating the endorsement-key and the attestation-identity-key
        LOG.info("Creating the EK and AIK")
        cmd0_list = [
            f'tpm2_createek \
                --ek-context ecc_ek.ctx \
                --key-algorithm ecc \
                --public ecc_ek.pub',
            f'tpm2_createak --ek-context ecc_ek.ctx \
                --ak-context ecc_ak.ctx \
                --key-algorithm ecc \
                --hash-algorithm sha256 \
                --signing-algorithm ecdsa \
                --public ecc_ak.pub --private ecc_ak.priv --ak-name ecc_ak.name'
        ]

        for cmd in cmd0_list:
            LOG.info(cmd)
            runner = self.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"

        # Device-Node retrieving the endorsement-key-certificate to send to the Privacy-CA
        LOG.info("Retrieving EK and send to Provacy-CA") 
        cmd2_script = '''
                  #!/bin/bash\n
                  ECC_EK_CERT_NV_INDEX=0x01C00016\n
                  NV_SIZE=`tpm2_nvreadpublic $ECC_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ecc_ek_cert.bin $ECC_EK_CERT_NV_INDEX\n
                  sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' ecc_ek_cert.bin | base64 --decode > ecc_ek_cert.bin'''
        cmd2_list = [
            f'echo {cmd2_script} > cmd2.sh',
            f'bash cmd2.sh'
        ] 

        for cmd in cmd2_list:
            LOG.info(cmd)
            runner = self.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"

        # “Privacy-CA“ and the “Device-Node“ performing a credential activation challenge in order to verify 
        # the AIK is bound to the EK from the EK-certificate originally shared by the “Device-Node“
        LOG.info("Verify AIK is bound to the EK") 
        cmd3_script = '''
                #!/bin/bash\n
                file_size=`stat --printf="%s" ecc_ak.name`\n
                loaded_key_name=`cat ecc_ak.name | xxd -p -c $file_size`\n
                echo "this is my secret" > file_input.data\n
                tpm2_makecredential --tcti none --encryption-key ecc_ek.pub --secret file_input.data --name $loaded_key_name --credential-blob cred.out\n
                tpm2_startauthsession --policy-session --session session.ctx\n
                TPM2_RH_ENDORSEMENT=0x4000000B\n
                tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT\n
                tpm2_activatecredential --credentialedkey-context ecc_ak.ctx --credentialkey-context ecc_ek.ctx --credential-blob cred.out --certinfo-data actcred.out --credentialkey-auth "session:session.ctx"\n
                tpm2_flushcontext session.ctx'''
        cmd3_list = [
            f'echo {cmd3_script} > cmd3.sh',
            f'bash cmd3.sh'
        ] 

        for cmd in cmd3_list:
            LOG.info(cmd)
            runner = self.exec_ssh_command(cmd)
            LOG.info(runner[1])
            if "WARN: Tool optionally uses SAPI. Continuing with tcti=none" not in runner[1]:
                assert runner[1] == "", "Failed to execute remote command"

        # “Device-Node“ generating the PCR attestation quote on request from the “Service-Provider“ 
        # and verifying the attestation quote generated and signed by the “Device-Node“
        LOG.info("Gen PCR attestation quote and verify attestation quote") 
        cmd4_list = [
            f'echo "12345678" > SERVICE_PROVIDER_NONCE',
            f'tpm2_quote \
                --key-context ecc_ak.ctx \
                --pcr-list sha256:0,1,2 \
                --message pcr_quote.plain \
                --signature pcr_quote.signature \
                --qualification SERVICE_PROVIDER_NONCE \
                --hash-algorithm sha256 \
                --pcr pcr.bin',
            f'tpm2_checkquote \
                --public ecc_ak.pub \
                --message pcr_quote.plain \
                --signature pcr_quote.signature \
                --qualification SERVICE_PROVIDER_NONCE \
                --pcr pcr.bin'
        ] 
        for cmd in cmd4_list:
            LOG.info(cmd)
            runner = self.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
