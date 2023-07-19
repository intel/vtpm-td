"""
test_vtpm.py

Readme:
--------------
A vtpm test framework to help startup vtpm user td and check dump logs.

- Please edit vtpm.config variables in `pyproject.toml` before use.
- Please note vtpmtool requires sudo permission without being prompted to input a password.
- Please don't run with root user otherwise there will be a env var issue that causes the launch of qemu to fail.

Example:
--------------
$ python3 -m venv .venv
$ source .venv/bin/active
$ (.venv) pip install pytest psutil paramiko
$ (.venv) vim pyproject.toml
$ (.venv) pytest

"""

import time
import logging
from vtpmtool import VtpmTool, vtpm_context

LOG = logging.getLogger(__name__)

def test_launch_tdvf_without_vtpm():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(["fs0:", "Tcg2DumpLog.efi > event.log"])
        ctx.start_user_td()
        ctx.terminate_user_td()
        content = ctx.read_log(filename="event.log")
    assert content and Utils.EVENT_ERR_FLAG in content


def test_launch_tdvf_with_vtpm_shell():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(
            [
                "fs0:",
                "Tcg2DumpLog.efi > event.log",
                "RtmrDump.efi > rtmrdump.log",
                "acpidump.efi -n tdtk > acpidump.log",
            ],
            )
        ctx.default_run_and_terminate()
        eventlog_content = ctx.read_log(filename="event.log")
        acpi_content = ctx.read_log(filename="acpidump.log")
        rtmr_content = ctx.read_log(filename="rtmrdump.log")
        
    rtmr0, rtmr1, rtmr2, rtmr3 = [
        Utils.extract_rtmr_value(rtmr_content, i) for i in range(4)
    ]

    assert eventlog_content and Utils.EVENT_ERR_FLAG not in eventlog_content
    assert acpi_content and Utils.TDTK_FLAG in acpi_content
    # check RTMR0 and RTMR3 - should not be zero
    assert rtmr0 and any(c != "0" for c in rtmr0)
    assert rtmr3 and any(c != "0" for c in rtmr3)

    # check RTMR1 and RTMR2 - are equal with fixed value
    expected_value = "879606558AC3776B815615CE42F361976430D931D5DA09D77E0C5EC08CC76D00F5D6CF5EB704B9ED19FF7CCCF47C9083"
    assert rtmr1 == rtmr2 and rtmr1 == expected_value    
    
def test_reset_tdvm():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(
            ["fs0:", "Tcg2DumpLog.efi > event0.log", "reset"]
        )
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td()  # user td will be terminated because `reset` is not supported
        content_before = ctx.read_log(filename="event0.log", auto_delete=False)

        ctx.generate_startup_into_vtpm_test_img(["fs0:", "Tcg2DumpLog.efi > event1.log", "reset"])
        ctx.start_user_td()
        ctx.terminate_all_tds()
        content_after = ctx.read_log(filename="event1.log", auto_delete=False)

    assert content_before and content_before == content_after

def test_2_vtpm_2_user(count_overwrite: int = None):
    total = count_overwrite or 2
    results = []
    envs = []

    # start N pairs of vtpm_td + user_td
    for i in range(total):
        env = VtpmTool(use_default_user_id=False) # generate different user id for each
        env.generate_startup_into_vtpm_test_img(
            [
                "fs0:",
                "Tcg2DumpLog.efi > event.log",
                "RtmrDump.efi > rtmrdump.log",
                "acpidump.efi -n tdtk > acpidump.log",
            ],
        )
        env.start_vtpm_td()
        env.execute_qmp()

        # no need to wait user td boot except the last user td
        if i < (total - 1):
            env.wait_tools_run_seconds = 0
        env.start_user_td()
        envs.append(env)

    # terminate these pairs and read td logs
    for env in envs:
        env.cleanup()
        time.sleep(1)
        event_log = env.read_log(filename="event.log")
        rtmr_log = env.read_log(filename="rtmrdump.log")
        rtmr_values = [Utils.extract_rtmr_value(rtmr_log, i) for i in range(4)]
        acpi_log = env.read_log(filename="acpidump.log")
        results.append((event_log, rtmr_values, acpi_log))

    # check results
    for i in range(total - 1):
        current, next = results[i], results[i + 1]

        # check event log - not error
        event, next_event = current[0], next[0]
        assert Utils.EVENT_ERR_FLAG not in event

def test_10_vtpm_10_user():
    test_2_vtpm_2_user(count_overwrite=10)


def test_stress_reset_500_cycles(cycle_overwrite: int = None):
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(
            ["fs0:", "Tcg2DumpLog.efi > event.log", "reset"]
        )
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td()

        cycle = cycle_overwrite or 500
        for i in range(cycle):
            event_log = ctx.read_log(filename="event.log")
            assert event_log and Utils.EVENT_ERR_FLAG not in event_log
            ctx.start_user_td()

        ctx.terminate_all_tds()

def test_send_create_command_twice_with_qmp():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(["fs0:", "Tcg2DumpLog.efi > event.log"])
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.execute_qmp()
        ctx.start_user_td()
        event_log = ctx.read_log(filename="event.log")
    assert event_log and Utils.EVENT_ERR_FLAG not in event_log


class Utils:
    EVENT_ERR_FLAG = "ERROR: Locate Tcg2Protocol - Not Found"
    TDTK_FLAG = "TDTK checks passed!"
    KERNEL_VTPM_FLAG = "tpm: TDX vTPM 2.0 device"

    @staticmethod
    def extract_rtmr_value(s: str, index: int) -> str:
        try:
            rtmr_start = s.index(f"RTMR{index}")
        except ValueError:
            return ""
        rtmr_end = s.index("\n", rtmr_start)
        return s[rtmr_start + 7 : rtmr_end]

def test_vtpm_command_nvread():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command tpm2_nvread
    """
    LOG.info("Create TDVM with vTPM device")
    
    # Run tpm command to check connectivity between user TD and vTPM TD
    # Encrypt and decrypt some data
    cmd_list = [
        f'tpm2_nvdefine -C o -s 32 -a "ownerread|policywrite|ownerwrite" 1',
        f'echo "please123abc" > nv.dat',
        f'tpm2_nvwrite -C o -i nv.dat 1',
        f'tpm2_nvread -C o -s 12 1'
    ] 
    
    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command" 
        ctx.terminate_all_tds() 

def test_vtpm_command_nvextend():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command tpm2_extend
    """

    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        # Run tpm command to check connectivity between user TD and vTPM TD
        # Encrypt and decrypt some data
        cmd_list = [
            f'tpm2_nvdefine -C o -a "nt=extend|ownerread|policywrite|ownerwrite|writedefine" 1',
            f'echo "my data" | tpm2_nvextend -C o -i- 1',
            f'tpm2_nvread -C o 1 | xxd -p -c32'
        ] 
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "" or "WARN" in runner[1], "Failed to execute remote command" 
        
        assert runner[0].strip('\n') == 'db7472e3fe3309b011ec11565bce4ea6668cc8ecdef7e6fdcda5206687af3f43'
        ctx.terminate_all_tds() 

def test_vtpm_command_unseal():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command tpm2_unseal
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    # Run tpm command to check connectivity between user TD and vTPM TD
    # Encrypt and decrypt some data
    cmd_list = [
        f'tpm2_createprimary -c primary.ctx -Q',
        f'tpm2_pcrread -Q -o pcr.bin sha256:0,1,2,3',
        f'tpm2_createpolicy -Q --policy-pcr -l sha256:0,1,2,3 -f pcr.bin -L pcr.policy',
        f'echo "secret" > data.dat',
        f'tpm2_create -C primary.ctx -L pcr.policy -i data.dat -u seal.pub -r seal.priv -c seal.ctx -Q',
        f'tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3'
    ] 
    
    with vtpm_context() as ctx:
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"  
        assert runner[0].strip('\n') == 'secret'
        ctx.terminate_all_tds() 

def test_vtpm_command_load():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command tpm2_loadexternal
    """
    LOG.info("Create TDVM with vTPM device")
    
    # Run tpm command to check connectivity between user TD and vTPM TD
    # Encrypt and decrypt some data
    cmd_list = [
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -C primary.ctx -u pub.dat -r priv.dat',
        f'tpm2_loadexternal -C o -u pub.dat -c pub.ctx'
    ]
    
    with vtpm_context() as ctx:
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        ctx.terminate_all_tds() 

def test_vtpm_command_pcrread():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR and replay by evnet_logs
    """
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        # Read PCR[0]
        cmd = f'tpm2_pcrread sha256:0'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr0 = runner[0].split(":")[-1].strip()
        
        # Read PCR[0] in event log
        cmd = f'tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        event_log_pcr0 = runner[0]
        
        # PCR[0] should be replayed by event log
        LOG.debug("PCR[0]: %s", pcr0)
        LOG.debug("PCR[0] in eventlog: %s", event_log_pcr0)
        assert pcr0.lower() in event_log_pcr0, "Fail to replay PCR[0] in event logs"
        ctx.terminate_all_tds() 

def test_vtpm_command_pcrextend():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to extend and read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:    
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        cmd = f'tpm2_pcrread sha256:8'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        assert "0x0000000000000000000000000000000000000000000000000000000000000000" in runner[0]
        
        # Extend PCR 8 and read PCR
        cmd_list = [
            f'echo "foo" > data',
            f'tpm2_pcrevent 8 data',
            f'tpm2_pcrread sha256:8'
        ]
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # New value of PCR[8] should be old one extended with sha256 of "foo"
        assert "0x44F12027AB81DFB6E096018F5A9F19645F988D45529CDED3427159DC0032D921" in runner[0]
        ctx.terminate_all_tds() 
    
def test_vtpm_command_quote():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        # Provide and verify quote
        cmd_list = [
            f'tpm2_createek -c 0x81010001 -G rsa -u ekpub.pem -f pem',
            f'tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -s rsassa -g sha256 -u akpub.pem -f pem -n ak.name',
            f'tpm2_quote -c ak.ctx -l sha256:15,16,22 -q abc123 -m quote.msg -s quote.sig -o quote.pcrs -g sha256',
            f'tpm2_checkquote -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q abc123'
        ] 
        for cmd in cmd_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        ctx.terminate_all_tds() 