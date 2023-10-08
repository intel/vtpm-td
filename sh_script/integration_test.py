# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

"""
integration_test.py

Readme:
--------------
A vtpm test framework to help startup vtpm user td and check dump logs.

- Please edit vtpm.config variables in `pyproject.toml` before use.
- Please note vtpmtool requires sudo permission without being prompted to input a password.
- Please don't run with root user otherwise there will be a env var issue that causes the launch of qemu to fail.

Example:
Recommend to use python 3.10
--------------
$ python3 -m venv .venv
$ source .venv/bin/activate
$ (.venv) pip install pytest psutil paramiko pytest-html
$ (.venv) vim conf/pyproject.toml
$ (.venv) pytest

"""

import time
import logging
from utils import VtpmTool, vtpm_context

LOG = logging.getLogger(__name__)

def test_config_A_launch_tdvf_without_vtpm():
    cmd = f'tpm2_pcrread sha256'
    
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM should not be exists" 
        
        ctx.terminate_user_td()

def test_config_A_launch_tdvf_with_vtpm_shell():
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 30
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

def test_config_A_2_vtpm_2_user(count_overwrite: int = None):
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
        env.wait_tools_run_seconds = 30
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

def test_config_A_10_vtpm_10_user():
    test_config_A_2_vtpm_2_user(count_overwrite=10)

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

def test_config_A_verify_CA_and_EK_certificate():
    export_ca_cmd = '''
                  #!/bin/bash\n
                  CA_CERT_NV_INDEX=0x01c00100\n
                  NV_SIZE=`tpm2_nvreadpublic $CA_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ca_cert.bin $CA_CERT_NV_INDEX'''
    
    export_ek_cmd = '''
                  #!/bin/bash\n
                  EK_CERT_NV_INDEX=0x01c00016\n
                  NV_SIZE=`tpm2_nvreadpublic $EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ek_cert.bin $EK_CERT_NV_INDEX'''

    convert_ca2pem_cmd = "openssl x509 -inform DER -in ca_cert.bin -outform PEM -out ca_cert.pem"
    convert_ek2pem_cmd = "openssl x509 -inform DER -in ek_cert.bin -outform PEM -out ek_cert.pem"
    verify_ca_cmd = "openssl verify -CAfile ca_cert.pem ca_cert.pem"
    verify_ek_cmd = "openssl verify -CAfile ca_cert.pem ek_cert.pem"
    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()

        LOG.debug(export_ca_cmd)
        runner = ctx.exec_ssh_command(export_ca_cmd)
        assert runner[1] == "", "Failed to export CA certificate: {}".format(runner[1])
        
        LOG.debug(export_ek_cmd)
        runner = ctx.exec_ssh_command(export_ek_cmd)
        assert runner[1] == "", "Failed to export EK certificate: {}".format(runner[1])  
        
        LOG.debug(convert_ca2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ca2pem_cmd)
        assert runner[1] == "", "Failed to convert CA from der to pem: {}".format(runner[1]) 
        
        LOG.debug(convert_ek2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ek2pem_cmd)
        assert runner[1] == "", "Failed to convert EK from der to pem: {}".format(runner[1]) 
        
        LOG.debug(verify_ca_cmd)
        runner = ctx.exec_ssh_command(verify_ca_cmd)
        assert runner[1] == "", "Verify CA fail: {}".format(runner[1])  
        
        LOG.debug(verify_ek_cmd)
        runner = ctx.exec_ssh_command(verify_ek_cmd)
        assert runner[1] == "", "Verify EK fail: {}".format(runner[1])  
      
        ctx.terminate_all_tds()

def test_config_A_create_instance_twice():
    cmd = f'tpm2_pcrread sha256'
    
    with vtpm_context() as ctx:
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.execute_qmp()
        
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        ctx.terminate_all_tds()

def test_config_A_create_destroy_instance():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        # Destroy instance
        ctx.execute_qmp(is_create=False)
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after detroy instance" 
        
        ctx.terminate_user_td()
        # Create instance
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        ctx.terminate_all_tds()

def test_config_A_reset_usertd():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner1 = ctx.exec_ssh_command(cmd)
        assert runner1[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner2 = ctx.exec_ssh_command(cmd)
        assert runner2[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        # Compare the pcr values of 2 times, should be same
        assert runner1[0] == runner2[0], "First time pcr value is not equal the second time's"
            
    ctx.terminate_all_tds()

def test_config_A_kill_vtpm_td():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Kill vtpm-td, check user TD status, tpm command should not work
    3. Relaunch vtpm-td and create instance, check user TD status, tpm command should not work
    """
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        ctx.terminate_vtpm_td()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 
        
        # Relaunch vtpm-td and create instance
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 

        ctx.terminate_all_tds()

def test_config_A_vtpm_command_nvread():
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

def test_config_A_vtpm_command_nvextend():
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

def test_config_A_vtpm_command_unseal():
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

def test_config_A_vtpm_command_load():
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

def test_config_A_vtpm_command_pcrread():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR and replay by evnet_logs
    """
    # pcr 0 1 2 3 4 5 6 7 9
    pcr_num = 10
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        # Read PCR value sha256
        cmd = f'tpm2_pcrread sha256'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr256_values = []
        for num in range(pcr_num):
            pcr256_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value sha384
        cmd = f'tpm2_pcrread sha384'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr384_values = []
        for num in range(pcr_num):
            pcr384_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value in event log
        cmd = f'tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        event_log_pcr = runner[0]
        
        # PCR value should be replayed by event log
        LOG.debug("PCR[0] in eventlog: %s", event_log_pcr)
        LOG.debug("PCR[0]: %s", pcr256_values)
        LOG.debug("PCR[0]: %s", pcr384_values)

        for num in range(pcr_num):
            if num != 8:
                assert pcr256_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)
                assert pcr384_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)

        ctx.terminate_all_tds()

def test_config_A_vtpm_command_pcrextend():
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
    
def test_config_A_vtpm_command_quote():
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
        
def test_config_A_vtpm_simple_attestation_with_tpm2_tools():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run simple attestation with tpm2-tools
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        ctx.terminate_all_tds()
        
"""
Config-B:
CC Measurement
"""
def test_config_B_no_sb_launch_tdvf_without_vtpm():
    cmd = f'tpm2_pcrread sha256'
    
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM should not be exists" 
        
        ctx.terminate_user_td()

def test_config_B_no_sb_verify_CA_and_EK_certificate():
    export_ca_cmd = '''
                  #!/bin/bash\n
                  CA_CERT_NV_INDEX=0x01c00100\n
                  NV_SIZE=`tpm2_nvreadpublic $CA_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ca_cert.bin $CA_CERT_NV_INDEX'''
    
    export_ek_cmd = '''
                  #!/bin/bash\n
                  EK_CERT_NV_INDEX=0x01c00016\n
                  NV_SIZE=`tpm2_nvreadpublic $EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ek_cert.bin $EK_CERT_NV_INDEX'''

    convert_ca2pem_cmd = "openssl x509 -inform DER -in ca_cert.bin -outform PEM -out ca_cert.pem"
    convert_ek2pem_cmd = "openssl x509 -inform DER -in ek_cert.bin -outform PEM -out ek_cert.pem"
    verify_ca_cmd = "openssl verify -CAfile ca_cert.pem ca_cert.pem"
    verify_ek_cmd = "openssl verify -CAfile ca_cert.pem ek_cert.pem"
    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()

        LOG.debug(export_ca_cmd)
        runner = ctx.exec_ssh_command(export_ca_cmd)
        assert runner[1] == "", "Failed to export CA certificate: {}".format(runner[1])
        
        LOG.debug(export_ek_cmd)
        runner = ctx.exec_ssh_command(export_ek_cmd)
        assert runner[1] == "", "Failed to export EK certificate: {}".format(runner[1])  
        
        LOG.debug(convert_ca2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ca2pem_cmd)
        assert runner[1] == "", "Failed to convert CA from der to pem: {}".format(runner[1]) 
        
        LOG.debug(convert_ek2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ek2pem_cmd)
        assert runner[1] == "", "Failed to convert EK from der to pem: {}".format(runner[1]) 
        
        LOG.debug(verify_ca_cmd)
        runner = ctx.exec_ssh_command(verify_ca_cmd)
        assert runner[1] == "", "Verify CA fail: {}".format(runner[1])  
        
        LOG.debug(verify_ek_cmd)
        runner = ctx.exec_ssh_command(verify_ek_cmd)
        assert runner[1] == "", "Verify EK fail: {}".format(runner[1])  
      
        ctx.terminate_all_tds()

def test_config_B_no_sb_create_destroy_instance():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        # Destroy instance
        ctx.execute_qmp(is_create=False)
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after detroy instance" 
        
        ctx.terminate_user_td()
        # Create instance
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        ctx.terminate_all_tds()

def test_config_B_no_sb_reset_usertd():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner1 = ctx.exec_ssh_command(cmd)
        assert runner1[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner2 = ctx.exec_ssh_command(cmd)
        assert runner2[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        # Compare the pcr values of 2 times, should be same
        assert runner1[0] == runner2[0], "First time pcr value is not equal the second time's"
            
    ctx.terminate_all_tds()

def test_config_B_no_sb_kill_vtpm_td():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Kill vtpm-td, check user TD status, tpm command should not work
    3. Relaunch vtpm-td and create instance, check user TD status, tpm command should not work
    """
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        ctx.terminate_vtpm_td()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 
        
        # Relaunch vtpm-td and create instance
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 

        ctx.terminate_all_tds()

def test_config_B_no_sb_vtpm_command_nvread():
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

def test_config_B_no_sb_vtpm_command_nvextend():
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

def test_config_B_no_sb_vtpm_command_unseal():
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

def test_config_B_no_sb_vtpm_command_load():
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

def test_config_B_no_sb_vtpm_command_pcrread():
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
        ctx.pcr_replay()
        ctx.terminate_all_tds() 

def test_config_B_no_sb_vtpm_command_pcrextend():
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
    
def test_config_B_no_sb_vtpm_command_quote():
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
        
def test_config_B_no_sb_vtpm_simple_attestation_with_tpm2_tools():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run simple attestation with tpm2-tools
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        ctx.terminate_all_tds()

"""
Config-B:
CC Measurement + Secure Boot
"""
def test_config_B_sb_launch_tdvf_without_vtpm_grub_boot():
    cmd = f'tpm2_pcrread sha256'
    
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM should not be exists" 
        
        ctx.terminate_user_td()

def test_config_B_sb_verify_CA_and_EK_certificate():
    export_ca_cmd = '''
                  #!/bin/bash\n
                  CA_CERT_NV_INDEX=0x01c00100\n
                  NV_SIZE=`tpm2_nvreadpublic $CA_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ca_cert.bin $CA_CERT_NV_INDEX'''
    
    export_ek_cmd = '''
                  #!/bin/bash\n
                  EK_CERT_NV_INDEX=0x01c00016\n
                  NV_SIZE=`tpm2_nvreadpublic $EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output ek_cert.bin $EK_CERT_NV_INDEX'''

    convert_ca2pem_cmd = "openssl x509 -inform DER -in ca_cert.bin -outform PEM -out ca_cert.pem"
    convert_ek2pem_cmd = "openssl x509 -inform DER -in ek_cert.bin -outform PEM -out ek_cert.pem"
    verify_ca_cmd = "openssl verify -CAfile ca_cert.pem ca_cert.pem"
    verify_ek_cmd = "openssl verify -CAfile ca_cert.pem ek_cert.pem"
    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()

        LOG.debug(export_ca_cmd)
        runner = ctx.exec_ssh_command(export_ca_cmd)
        assert runner[1] == "", "Failed to export CA certificate: {}".format(runner[1])
        
        LOG.debug(export_ek_cmd)
        runner = ctx.exec_ssh_command(export_ek_cmd)
        assert runner[1] == "", "Failed to export EK certificate: {}".format(runner[1])  
        
        LOG.debug(convert_ca2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ca2pem_cmd)
        assert runner[1] == "", "Failed to convert CA from der to pem: {}".format(runner[1]) 
        
        LOG.debug(convert_ek2pem_cmd)
        runner = ctx.exec_ssh_command(convert_ek2pem_cmd)
        assert runner[1] == "", "Failed to convert EK from der to pem: {}".format(runner[1]) 
        
        LOG.debug(verify_ca_cmd)
        runner = ctx.exec_ssh_command(verify_ca_cmd)
        assert runner[1] == "", "Verify CA fail: {}".format(runner[1])  
        
        LOG.debug(verify_ek_cmd)
        runner = ctx.exec_ssh_command(verify_ek_cmd)
        assert runner[1] == "", "Verify EK fail: {}".format(runner[1])  
      
        ctx.terminate_all_tds()

def test_config_B_sb_create_destroy_instance():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        # Destroy instance
        ctx.execute_qmp(is_create=False)
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after detroy instance" 
        
        ctx.terminate_user_td()
        # Create instance
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        ctx.terminate_all_tds()

def test_config_B_sb_reset_usertd():
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        # Create instance
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner1 = ctx.exec_ssh_command(cmd)
        assert runner1[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        runner2 = ctx.exec_ssh_command(cmd)
        assert runner2[1] == "", "Failed to execute remote command" 
        ctx.terminate_user_td()
        
        # Compare the pcr values of 2 times, should be same
        assert runner1[0] == runner2[0], "First time pcr value is not equal the second time's"
            
    ctx.terminate_all_tds()

def test_config_B_sb_kill_vtpm_td():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Kill vtpm-td, check user TD status, tpm command should not work
    3. Relaunch vtpm-td and create instance, check user TD status, tpm command should not work
    """
    cmd = f'tpm2_pcrread sha256'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        ctx.pcr_replay()
        
        ctx.terminate_vtpm_td()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 
        
        # Relaunch vtpm-td and create instance
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        
        LOG.debug(cmd)
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] != "", "vTPM is still work after kill vTPM" 

        ctx.terminate_all_tds()

def test_config_B_sb_vtpm_command_nvread():
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
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command" 
        ctx.terminate_all_tds() 

def test_config_B_sb_vtpm_command_nvextend():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command tpm2_extend
    """

    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
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

def test_config_B_sb_vtpm_command_unseal():
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
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"  
        assert runner[0].strip('\n') == 'secret'
        ctx.terminate_all_tds() 

def test_config_B_sb_vtpm_command_load():
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
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        ctx.terminate_all_tds() 

def test_config_B_sb_vtpm_command_pcrread():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR and replay by evnet_logs
    """
    # pcr 0 1 2 3 4 5 6 7 9
    pcr_num = 10
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        # Read PCR value sha256
        cmd = f'tpm2_pcrread sha256'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr256_values = []
        for num in range(pcr_num):
            pcr256_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value sha384
        cmd = f'tpm2_pcrread sha384'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == ""
        pcr384_values = []
        for num in range(pcr_num):
            pcr384_values.append(runner[0].split("\n")[num + 1].split(":")[-1].strip().lower())
        
        # Read PCR value in event log
        cmd = f'tpm2_eventlog /sys/kernel/security/tpm0/binary_bios_measurements'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        event_log_pcr = runner[0]
        
        # PCR value should be replayed by event log
        LOG.debug("PCR[0] in eventlog: %s", event_log_pcr)
        LOG.debug("PCR[0]: %s", pcr256_values)
        LOG.debug("PCR[0]: %s", pcr384_values)

        for num in range(pcr_num):
            if num != 8:
                assert pcr256_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)
                assert pcr384_values[num] in event_log_pcr, "Fail to replay PCR[{}] in event logs".format(num)

        ctx.terminate_all_tds()

def test_config_B_sb_vtpm_command_pcrextend():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to extend and read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:    
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        cmd = f'tpm2_pcrread sha256:15'
        runner = ctx.exec_ssh_command(cmd)
        assert runner[1] == "", "Failed to execute remote command"  
        assert "0x0000000000000000000000000000000000000000000000000000000000000000" in runner[0]
        
        # Extend PCR 8 and read PCR
        cmd_list = [
            f'echo "foo" > data',
            f'tpm2_pcrevent 15 data',
            f'tpm2_pcrread sha256:15'
        ]
        for cmd in cmd_list:
            LOG.debug(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # New value of PCR[8] should be old one extended with sha256 of "foo"
        assert "0x44F12027AB81DFB6E096018F5A9F19645F988D45529CDED3427159DC0032D921" in runner[0]
        ctx.terminate_all_tds() 
    
def test_config_B_sb_vtpm_command_quote():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run tpm command to read PCR
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
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
        
def test_config_B_sb_vtpm_simple_attestation_with_tpm2_tools():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run simple attestation with tpm2-tools
    """
    
    LOG.info("Create TDVM with vTPM device")
    
    with vtpm_context() as ctx:  
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
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
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        ctx.terminate_all_tds()

def test_stress_test_reset_user_td():
    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        for time in range(ctx.stress_test_cycles):
            LOG.debug("###### {}  Cycle ######".format(time + 1))
            ctx.start_user_td(with_guest_kernel=True)
            ctx.connect_ssh()
            ctx.pcr_replay()
            # reset user td
            ctx.terminate_user_td()
            
    ctx.terminate_all_tds()

def test_tpm_cmd_with_vtpm():
    """
    1. Create TDVM with vTPM device - vTPM TD and user TD should be running
    2. Run all tpm commands (Tpm2 Command Coverage 91/99 ~ 91.9%):
        tpm2_activatecredential
        tpm2_certify
        tpm2_certifycreation
        tpm2_certifyX509certutil --> not test in this case
        tpm2_changeauth 
        tpm2_changeeps
        tpm2_changepps
        tpm2_checkquote
        tpm2_clear
        tpm2_clearcontrol
        tpm2_clockrateadjust
        tpm2_commit
        tpm2_create
        tpm2_createak
        tpm2_createek
        tpm2_createpolicy
        tpm2_createprimary
        tpm2_dictionarylockout
        tpm2_duplicate
        tpm2_ecdhkeygen
        tpm2_ecdhzgen
        tpm2_ecephemeral
        tpm2_encryptdecrypt
        tpm2_eventlog --> not test in this case
        tpm2_evictcontrol
        tpm2_flushcontext
        tpm2_getcap
        tpm2_getcommandauditdigest --> not ready
        tpm2_geteccparameters
        tpm2_getekcertificate --> not ready
        tpm2_getrandom
        tpm2_getsessionauditdigest
        tpm2_gettestresult
        tpm2_gettime 
        tpm2_hash 
        tpm2_hierarchycontrol
        tpm2_hmac
        tpm2_import
        tpm2_incrementalselftest
        tpm2_load
        tpm2_loadexternal 
        tpm2_makecredential 
        tpm2_nvcertify 
        tpm2_nvdefine 
        tpm2_nvextend 
        tpm2_nvincrement
        tpm2_nvread
        tpm2_nvreadlock
        tpm2_nvreadpublic
        tpm2_nvsetbits
        tpm2_nvundefine
        tpm2_nvwrite
        tpm2_nvwritelock
        tpm2_pcrallocate 
        tpm2_pcrevent 
        tpm2_pcrextend 
        tpm2_pcrread 
        tpm2_pcrreset
        tpm2_policyauthorize
        tpm2_policyauthorizenv
        tpm2_policyauthvalue
        tpm2_policycommandcode
        tpm2_policycountertimer
        tpm2_policycphash
        tpm2_policyduplicationselect
        tpm2_policylocality
        tpm2_policynamehash
        tpm2_policynv --> not ready
        tpm2_policynvwritten
        tpm2_policyor
        tpm2_policypassword
        tpm2_policypcr
        tpm2_policyrestart
        tpm2_policysecret
        tpm2_policysigned
        tpm2_policytemplate
        tpm2_policyticket --> not ready
        tpm2_print
        tpm2_quote
        tpm2_rc_decode --> not test in this case
        tpm2_readclock
        tpm2_readpublic
        tpm2_rsadecrypt
        tpm2_rsaencrypt
        tpm2_selftest
        tpm2_send
        tpm2_sessionconfig
        tpm2_setclock
        tpm2_setcommandauditstatus
        tpm2_setprimarypolicy
        tpm2_shutdown --> not test in this case
        tpm2_sign
        tpm2_startauthsession
        tpm2_startup --> not test in this case
        tpm2_stirrandom
        tpm2_testparms
        tpm2_unseal
        tpm2_verifysignature
        tpm2_zgen2phase
    """
    LOG.info("Create TDVM with vTPM device")
    # Run tpm command to check connectivity between user TD and vTPM TD

    cmd_certify_list = [
        f'tpm2_createprimary -Q -C e -g sha256 -G rsa -c primary.ctx',
        f'tpm2_create -Q -g sha256 -G rsa -u certify.pub -r certify.priv -C primary.ctx',
        f'tpm2_load -Q -C primary.ctx -u certify.pub -r certify.priv -n certify.name -c certify.ctx',
        f'tpm2_certify -Q -c primary.ctx -C certify.ctx -g sha256 -o attest.out -s sig.out'
    ] 

    cmd_certifycreation_list = [
        f'tpm2_createprimary -C o -c prim.ctx --creation-data create.dat -d create.dig -t create.ticket',
        f'tpm2_create -G rsa -u rsa.pub -r rsa.priv -C prim.ctx -c signing_key.ctx',
        f'tpm2_certifycreation -C signing_key.ctx -c prim.ctx -d create.dig -t create.ticket -g sha256 -o sig.nature --attestation attestat.ion -f plain -s rsassa'
    ] 

    cmd_tpm2_dictionarylockout_list = [
        f'tpm2_dictionarylockout --setup-parameters --max-tries=4294967295 --clear-lockout'
    ]

    ## can use tpm2_getcap properties-variable to check the value
    cmd_set_and_clear_authorization_list = [
        f'tpm2_changeauth -c owner newpass',
        f'tpm2_clockrateadjust -p newpass ss',
        f'tpm2_changeauth -c endorsement newpass',
        f'tpm2_changeauth -c lockout newpass',
        f'tpm2_clear -c p'
    ] 

    cmd_change_seed_list = [
        f'tpm2_changeeps',
        f'tpm2_changepps'
    ] 

    cmd_checkquote_list = [
        f'tpm2_createek -c 0x81010001 -G rsa -u ekpub.pem -f pem',
        f'tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -s rsassa -g sha256 \
        -u akpub.pem -f pem -n ak.name',
        f'tpm2_quote -c ak.ctx -l sha256:15,16,22 -q abc123 -m quote.msg -s quote.sig \
        -o quote.pcrs -g sha256',
        f'tpm2_checkquote -u akpub.pem -m quote.msg -s quote.sig -f quote.pcrs -g sha256 -q abc123'
    ] 

    ## can use tpm2_getcap properties-variable to check the "disableClear"
    cmd_clearcontrl_list = [
        f'tpm2_clearcontrol -C l s',
        f'tpm2_clearcontrol -C p c'
    ] 

    cmd_commit_list = [
        f'tpm2_createprimary -C o -c prim.ctx -Q',
        f'tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdaa',
        f'tpm2_commit -c key.ctx -t count.er --eccpoint-K K.bin --eccpoint-L L.bin -u E.bin'
    ]

    cmd_duplicate_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate',
        f'tpm2_flushcontext session.dat',
        f'tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctxt',
        f'tpm2_create -C primary.ctxt -g sha256 -G rsa -r key.prv -u key.pub  -c key.ctxt -L policy.dat -a "sensitivedataorigin|userwithauth|decrypt|sign" ',
        f'tpm2_createprimary -C o -g sha256 -G ecc -c new_parent.ctxt',
        f'tpm2_startauthsession \--policy-session -S session.dat',
        f'tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate',
        f'tpm2_duplicate -C new_parent.ctxt -c key.ctxt -G null -p "session:session.dat" -r duprv.bin -s seed.dat',
        f'tpm2_flushcontext session.dat'
    ] 

    cmd_ecd_gen_key_list = [
        f'tpm2_createprimary -C o -c prim.ctx -Q',
        f'tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdh',
        f'tpm2_ecdhkeygen -u ecdh.pub -o ecdh.priv -c key.ctx',
        f'tpm2_ecdhzgen -u ecdh.pub -o ecdh.dat -c key.ctx'
    ]

    cmd_eephemeral_list = [
        f'tpm2_ecephemeral -u ecc.q -t ecc.ctr ecc256'
    ]

    cmd_encryptdecrypt_list = [
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -C primary.ctx -Gaes128 -u key.pub -r key.priv',
        f'tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx',
        f'echo "my secret" > secret.dat',
        f'tpm2_encryptdecrypt -c key.ctx -o secret.enc secret.dat',
        f'tpm2_encryptdecrypt -d -c key.ctx -o secret.dec secret.enc',
        f'cat secret.dec'## should be "my secret"
    ]

    cmd_get_data_list = [
        f'tpm2_getcap -l',
        f'tpm2_getcap properties-variable',
        f'tpm2_getcap properties-fixed',
        f'tpm2_geteccparameters ecc256 -o ecc.params',
        f'tpm2_getrandom 8 -o random.out',
        f'tpm2_gettestresult'
    ]

    cmd_getsessionauditdigest_list = [
        f'tpm2_createprimary -Q -C e -c prim.ctx',
        f'tpm2_create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub -r signing_key.priv',
        f'tpm2_startauthsession -S session.ctx --audit-session',
        f'tpm2_getrandom 8 -S session.ctx',
        f'tpm2_getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig -S session.ctx'
    ]

    cmd_gettime_list = [
        f'tpm2_createprimary -C e -c primary.ctx',
        f'tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx',
        f'tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx',
        f'tpm2_gettime -c rsa.ctx -o attest.sig --attestation attest.data'
    ]

    cmd_hash_list =[
        f'echo "text" > data.txt',
        f'tpm2_hash -C e -g sha256 -o hash.bin -t ticket.bin data.txt'
    ]

    cmd_hierarchycontrol_list = [
        f'tpm2_hierarchycontrol -C p shEnable clear',
        f'tpm2_getcap properties-variable', ##check the value 'shEnable'
        f'tpm2_hierarchycontrol -C p shEnable set',
        f'tpm2_getcap properties-variable'      
    ]

    cmd_hmac_list = [
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -C primary.ctx -G hmac -c hmac.key',
        f'echo "0x" > data.in', 
        f'tpm2_hmac -c hmac.key --hex data.in'   
    ]

    cmd_tpm_test_list = [
        f'tpm2_incrementalselftest rsa ecc',
        f'tpm2_selftest',
        f'tpm2_testparms rsa ecc'
    ]

    cmd_loadexternal_list = [
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -C primary.ctx -u pub.dat -r priv.dat',
        f'tpm2_loadexternal -C o -u pub.dat -c pub.ctx'
    ]

    cmd_nvcertify_list = [
        f'tpm2_nvdefine -s 32 -a "authread|authwrite" 1',
        f'dd if=/dev/urandom bs=1 count=32 status=none| \
          tpm2_nvwrite 1 -i-',
        f'tpm2_createprimary -C o -c primary.ctx -Q',
        f'tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx -c signing_key.ctx -Q',
        f'tpm2_readpublic -c signing_key.ctx -f pem -o sslpub.pem -Q',
        f'tpm2_nvcertify -C signing_key.ctx -g sha256 -f plain -s rsassa \
          -o signature.bin --attestation attestation.bin --size 32 1',
        f'tpm2_nvundefine 1'
    ]

    cmd_nvextend_list = [
        f'tpm2_nvdefine -C o -a "nt=extend|ownerread|policywrite|ownerwrite|writedefine" 1',
        f'echo "my data" | tpm2_nvextend -C o -i- 1',
        f'tpm2_nvread -C o 1 | xxd -p -c32',
        f'tpm2_nvundefine 1' 
    ]

    cmd_nv_read_list = [
        f'tpm2_nvdefine -C o -s 32 -a "ownerread|policywrite|ownerwrite" 1',
        f'echo "please123abc" > nv.dat',
        f'tpm2_nvwrite -C o -i nv.dat 1',
        f'tpm2_nvread -C o -s 12 1',
        f'tpm2_nvundefine 1'
    ] 

    cmd_nvincrement_list = [
        f'tpm2_nvdefine -C o -s 8 -a "ownerread|authread|authwrite|nt=1" 0x1500016 -p index',
        f'tpm2_nvincrement -C 0x1500016  0x1500016 -P "index"',
        f'tpm2_nvread 0x1500016 -P index | xxd -p',
        f'tpm2_nvundefine 0x1500016'
    ]

    cmd_nv_readlock_list = [
        f'tpm2_nvdefine -Q  1 -C o -s 32 -a "ownerread|policywrite|ownerwrite|read_stclear" ',
        f'echo "foobar" > nv.readlock',
        f'tpm2_nvwrite -Q   0x01000001 -C o -i nv.readlock',
        f'tpm2_nvread -Q   1 -C o -s 6 -o 0',
        f'tpm2_nvreadlock -Q   1 -C o',
        # f'tpm2_nvread -Q   1 -C o -s 6 -o 0',##should be error with NV access locked
        f'tpm2_nvundefine 1'
    ]

    cmd_nvsetbits_list = [
        f'tpm2_nvdefine -C o -a "nt=bits|ownerread|policywrite|ownerwrite|writedefine" 1 ',
        f'tpm2_nvsetbits -C o -i 0xbadc0de 1',
        f'tpm2_nvread -C o 1 ',
        f'tpm2_nvundefine 1'
    ] 

    cmd_nvwritelock_list = [
        f'tpm2_nvdefine -C o -s 32 -a "ownerread|policywrite|ownerwrite|writedefine" 1 ',
        f'echo "foobar" > nv.writelock',
        f'tpm2_nvwrite -C o -i nv.writelock 1 ',
        f'tpm2_nvwritelock -C o 1 ',
        # f'tpm2_nvwrite -C o -i nv.writelock 1 ',##should be error with NV access locked
        f'tpm2_nvundefine 1'
    ]

    cmd_pcr_list = [
        f'tpm2_pcrallocate sha256:all',
        f'tpm2_pcrread sha256',
        f'tpm2_pcrextend 23:sha256=b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c ',#pcr 23 no-empty
        f'tpm2_pcrreset 23',#pcr 23 empty , can only reset pcr 16 and 23
        f'echo "foo" > data',
        f'tpm2_pcrevent 8 data',
        f'tpm2_pcrread sha256:8'
    ] 


    cmd_policyauthorize_list = [
        f'openssl genrsa -out signing_key_private.pem 2048',
        f'openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout',
        f'tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_policyauthorize_nv_list = [
        f'tpm2_nvdefine -C o -p nvpass 0x01500001 -a "authread|authwrite" -s 34',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policypassword -S session.ctx -L policy.pass',
        f'tpm2_flushcontext session.ctx',
        f'echo "000b" | xxd -p -r | cat - policy.pass | \
        tpm2_nvwrite -C 0x01500001 -P nvpass 0x01500001 -i-',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policyauthorizenv -S session.ctx -C 0x01500001 -P nvpass \
        -L policyauthorizenv.1500001 0x01500001',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_nvundefine 0x01500001'
    ]

    #create password policy
    cmd_policyauthvalue_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policyauthvalue -S session.dat -L policy.dat',
        f'tpm2_flushcontext session.dat'
    ]

    cmd_policycommandcode_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Unseal',
        f'tpm2_flushcontext session.dat'
    ]

    cmd_policycountertimer_list = [
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policycountertimer -S session.ctx -L policy.countertimer --ult 60000',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_policycphash_list = [
        f'openssl genrsa -out signing_key_private.pem 2048',
        f'openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout',
        f'tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_nvdefine 1 -a "policywrite|authwrite|ownerread|nt=bits" -L authorized.policy',
        f'tpm2_nvsetbits 1 -i 1 --cphash cp.hash',
        f'tpm2_startauthsession -S session.ctx -g sha256',
        f'tpm2_policycphash -S session.ctx -L policy.cphash --cphash cp.hash',
        f'tpm2_flushcontext session.ctx',
        f'openssl dgst -sha256 -sign signing_key_private.pem \
        -out policycphash.signature policy.cphash',
        f'tpm2_verifysignature -c signing_key.ctx -g sha256 -m policy.cphash \
        -s policycphash.signature -t verification.tkt -f rsassa',
        f'tpm2_nvundefine 1'
    ]

    cmd_policyduplicationselect_list = [
        f'tpm2_createprimary -C n -g sha256 -G rsa -c dst_n.ctx -Q',
        f'tpm2_createprimary -C o -g sha256 -G rsa -c src_o.ctx -Q',
        f'tpm2_readpublic -c dst_n.ctx -n dst_n.name -Q',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policyduplicationselect -S session.ctx  -N dst_n.name \
        -L policydupselect.dat -Q',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_policylocality_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policylocality -S session.dat -L policy.dat three',
        f'tpm2_flushcontext session.dat'
    ]


    cmd_tpm2_policynamehash_list = [
        f'openssl genrsa -out signing_key_private.pem 2048',
        f'openssl rsa -in signing_key_private.pem -out signing_key_public.pem -pubout',
        f'tpm2_loadexternal -G rsa -C o -u signing_key_public.pem -c signing_key.ctx -n signing_key.name',
        f'tpm2_startauthsession -S session.ctx -g sha256',
        f'tpm2_policyauthorize -S session.ctx -L authorized.policy -n signing_key.name',
        f'tpm2_policycommandcode -S session.ctx -L policy.dat TPM2_CC_Duplicate',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctx -Q',
        f'tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r key.prv -u key.pub \
        -L policy.dat -a "sensitivedataorigin|sign|decrypt"',
        f'tpm2_load -Q -C primary.ctx -r key.prv -u key.pub -c key.ctx',
        f'tpm2_create -Q -C primary.ctx -g sha256 -G rsa -r new_parent.prv \
        -u new_parent.pub -a "decrypt|fixedparent|fixedtpm|restricted|sensitivedataorigin" ',
        f'tpm2_loadexternal -Q -C o -u new_parent.pub -c new_parent.ctx',
        f'tpm2_readpublic -Q -c new_parent.ctx -n new_parent.name',
        f'tpm2_readpublic -Q -c key.ctx -n key.name',
        f'cat key.name new_parent.name | openssl dgst -sha256 -binary > name.hash',
        f'tpm2_startauthsession -S session.ctx -g sha256',
        f'tpm2_policynamehash -L policy.namehash -S session.ctx -n name.hash',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_policynvwritten_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policycommandcode -S session.dat TPM2_CC_NV_Write',
        f'tpm2_policynvwritten -S session.dat -L nvwrite.policy c',
        f'tpm2_flushcontext session.dat'
    ] 

    cmd_policyor_list = [
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policypcr -S session.ctx -L policy.pcr -l sha256:0,1,2,3',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policypassword -S session.ctx -L policy.pass',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policyor -S session.ctx -L policy.or sha256:policy.pass,policy.pcr',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_tpm2_policyrestart_list = [
        f'tpm2_startauthsession -S session.dat',
        f'tpm2_policypcr -S session.dat -l "sha256:0,1,2,3" -L policy.dat',
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -Cprimary.ctx -u key.pub -r key.priv -L policy.dat -i- <<< "secret"',
        f'tpm2_load -C primary.ctx -c key.ctx -u key.pub -r key.priv',
        f'tpm2_flushcontext session.dat',
        f'tpm2_startauthsession --policy -S session.dat',
        f'tpm2_policypcr -S session.dat -l "sha256:0,1,2,3" ',
        f'tpm2_pcrevent 0 <<< "event data" ',
        # f'tpm2_unseal -psession:session.dat -c key.ctx ', #should be tpm:error(2.0): PCR have changed since checked
        f'tpm2_policyrestart -S session.dat',
        # f'tpm2_unseal -psession:session.dat -c key.ctx' #should be tpm:session(1):a policy check failed
    ] 

    cmd_policysigned_list = [
        f'openssl genrsa -out private.pem 2048',
        f'openssl rsa -in private.pem -outform PEM -pubout -out public.pem',
        f'echo "00 00 00 00" | xxd -r -p | \
        openssl dgst -sha256 -sign private.pem -out signature.dat',
        f'tpm2_loadexternal -C o -G rsa -u public.pem -c signing_key.ctx',
        f'tpm2_startauthsession -S session.ctx',
        f'tpm2_policysigned -S session.ctx -g sha256 -s signature.dat -f rsassa \
        -c signing_key.ctx -L policy.signed',
        f'tpm2_flushcontext session.ctx'
    ] 



    cmd_tpm2_policytemplate_list = [
        f'tpm2_createprimary -C o -c prim.ctx --template-data template.data',
        f'cat template.data | openssl dgst -sha256 -binary -out template.hash',
        f'tpm2_startauthsession -S session.ctx -g sha256',
        f'tpm2_policytemplate -S session.ctx -L policy.template \
        --template-hash template.hash',
        f'tpm2_flushcontext session.ctx',
        f'tpm2_setprimarypolicy -C o -g sha256 -L policy.template',
        f'tpm2_startauthsession -S session.ctx -g sha256 --policy-session',
        f'tpm2_policytemplate -S session.ctx --template-hash template.hash',
        f'tpm2_createprimary -C o -c prim2.ctx -P session:session.ctx',
        f'tpm2_flushcontext session.ctx'
    ]

    cmd_tpm2_print_list = [
        f'tpm2_createprimary -C e -c primary.ctx',
        f'tpm2_create -C primary.ctx -u key.pub -r key.priv',
        f'tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx',
        f'tpm2_quote -c key.ctx -l 0x000b:16,17,18 -g sha256 -m msg.dat',
        f'tpm2_print -t TPMS_ATTEST msg.dat',
        f'tpm2_print -t TPM2B_PUBLIC key.pub',
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_evictcontrol -c primary.ctx -o primary.tr',
        f'tpm2_print -t ESYS_TR primary.tr'
    ] 

    cmd_tpm2_clock_list = [
        f'tpm2_changeauth -c owner newpass',
        f'tpm2_setclock -p newpass 13673142',
        f'tpm2_readclock',
        f'tpm2_clear -c p'
    ]  

    cmd_tpm2_rsaencrypt_decrypt_list = [
        f'tpm2_createprimary -c primary.ctx',
        f'tpm2_create -C primary.ctx -Grsa2048 -u key.pub -r key.priv',
        f'tpm2_load -C primary.ctx -u key.pub -r key.priv -c key.ctx',
        f'echo "my message" > msg.dat',
        f'tpm2_rsaencrypt -c key.ctx -o msg.enc msg.dat',
        f'tpm2_rsadecrypt -c key.ctx -o msg.ptext msg.enc',
        f'cat msg.ptext' #should be my message
    ] 


    cmd_tpm2_sessionconfig_list = [
        f'tpm2 createprimary -c prim.ctx',
        f'tpm2 startauthsession -S session.ctx --policy-session -c prim.ctx',
        f'tpm2 sessionconfig session.ctx',
        f'tpm2 sessionconfig session.ctx --disable-continuesession',
        f'tpm2 sessionconfig session.ctx',
        f'tpm2_flushcontext session.ctx'
    ] 

    cmd_tpm2_setcommandauditstatus_list = [
        f'tpm2_setcommandauditstatus TPM2_CC_Unseal'
    ] 

    cmd_tpm2_sign_list = [
        f'tpm2_createprimary -C e -c primary.ctx',
        f'tpm2_create -G rsa -u rsa.pub -r rsa.priv -C primary.ctx',
        f'tpm2_load -C primary.ctx -u rsa.pub -r rsa.priv -c rsa.ctx',
        f'echo "my message" > message.dat',
        f'tpm2_sign -c rsa.ctx -g sha256 -o sig.rssa message.dat',
        f'tpm2_verifysignature -c rsa.ctx -g sha256 -s sig.rssa -m message.dat',
    ]

    cmd_tpm2_stirrandom_list = [
        f'echo -n "myrandomdata" | tpm2_stirrandom'
    ]

    cmd_zgen2phase_list = [
        f'tpm2_createprimary -C o -c prim.ctx -Q',
        f'tpm2_create -C prim.ctx -c key.ctx -u key.pub -r key.priv -G ecc256:ecdh -Q',
        f'tpm2_ecephemeral -u ecc.q -t ecc.ctr ecc256',
        f'tpm2_ecdhkeygen -u ecdh.pub -o ecdh.priv -c key.ctx',
        f'tpm2_zgen2phase -c key.ctx --static-public ecdh.pub --ephemeral-public ecc.q -t 0 --output-Z1 z1.bin --output-Z2 z2.bin'
    ]

    cmd_unsea_list = [
        f'tpm2_createprimary -c primary.ctx -Q',
        f'tpm2_pcrread -Q -o pcr.bin sha256:0,1,2,3',
        f'tpm2_createpolicy -Q --policy-pcr -l sha256:0,1,2,3 -f pcr.bin -L pcr.policy',
        f'echo "secret" > data.dat',
        f'tpm2_create -C primary.ctx -L pcr.policy -i data.dat -u seal.pub -r seal.priv -c seal.ctx -Q',
        f'tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3'
    ]

    cmd_tpm2_send_list = [
        f'echo 0x80 > test.bin',
        f'tpm2_send < test.bin -o res.bin'
    ] 

    cmd_tpm2_import_list = [
        f'tpm2_createprimary -Grsa2048:aes128cfb -C o -c parent.ctx',
        f'openssl ecparam -name prime256v1 -genkey -noout -out private.ecc.pem',
        f'tpm2_import -C parent.ctx -G ecc -i private.ecc.pem -u key.pub -r key.priv'
    ]



    cmd_list = [
        cmd_policyauthorize_nv_list,
        cmd_certify_list,
        cmd_certifycreation_list,
        cmd_tpm2_dictionarylockout_list,
        cmd_set_and_clear_authorization_list,
        cmd_change_seed_list,
        cmd_checkquote_list,
        cmd_clearcontrl_list,
        cmd_commit_list,
        cmd_duplicate_list,
        cmd_ecd_gen_key_list,
        cmd_eephemeral_list,
        cmd_encryptdecrypt_list,
        cmd_get_data_list,
        cmd_getsessionauditdigest_list,
        cmd_gettime_list,
        cmd_hierarchycontrol_list,
        cmd_hmac_list,
        cmd_tpm_test_list,
        cmd_loadexternal_list,
        cmd_nvcertify_list,
        cmd_nvextend_list,
        cmd_nv_read_list,
        cmd_nvincrement_list,
        cmd_nv_readlock_list,
        cmd_nvsetbits_list,
        cmd_nvwritelock_list,
        cmd_pcr_list,
        cmd_hash_list,
        cmd_policyauthorize_list,
        cmd_policyauthvalue_list,
        cmd_policycommandcode_list,
        cmd_policycountertimer_list,
        cmd_policycphash_list,
        cmd_policyduplicationselect_list,
        cmd_policylocality_list,
        cmd_tpm2_policynamehash_list,
        cmd_policynvwritten_list,
        cmd_policyor_list,
        cmd_tpm2_policyrestart_list,
        cmd_policysigned_list,
        cmd_tpm2_policytemplate_list,
        cmd_tpm2_print_list,
        cmd_tpm2_clock_list,
        cmd_tpm2_rsaencrypt_decrypt_list,
        cmd_tpm2_sessionconfig_list,
        cmd_tpm2_setcommandauditstatus_list,
        cmd_tpm2_stirrandom_list,
        cmd_zgen2phase_list,
        cmd_unsea_list,
        cmd_tpm2_sign_list,
        cmd_tpm2_send_list,
        cmd_tpm2_import_list
    ]

    cmd_mktest = f'rm -rf test_tpm_cmd && mkdir test_tpm_cmd && pushd test_tpm_cmd'
    cmd_clear_file = f'rm -rf *'

    with vtpm_context() as ctx:     
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        ctx.exec_ssh_command(cmd_mktest)
        print("vtpm_simple_attestation start ...\n")
        ctx.vtpm_simple_attestation()
        print("vtpm_simple_attestation pass\n")
        for cmd_case in cmd_list:
            for cmd in cmd_case:
                LOG.debug(cmd)
                runner = ctx.exec_ssh_command(cmd,encodingtype='ISO-8859-1')
                print(cmd)
                if runner[1] != "":
                    print("stdout: \n")
                    print(runner[0])
                    print("stderr: \n")
                    print(runner[1])
                    if "ERROR" in runner[1]:
                        assert False
            ctx.exec_ssh_command(cmd_clear_file)
        ctx.execute_qmp(is_create=False)
        ctx.terminate_all_tds() 