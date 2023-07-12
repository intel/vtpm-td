import time
import logging
from vtpmtool import VtpmTool, vtpm_context

LOG = logging.getLogger(__name__)

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
        ctx.wait_tools_run_seconds = 60
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
        ctx.wait_tools_run_seconds = 80
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
        ctx.wait_tools_run_seconds = 60
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"  
        assert runner[0].strip('\n') == 'secret'

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
        ctx.wait_tools_run_seconds = 60
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"  

def test_vtpm_command_pcrread():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR and replay by evnet_logs
    """
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 60
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

def test_vtpm_command_pcrextend():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to extend and read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 60
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
    
def test_vtpm_command_quote():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 60
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