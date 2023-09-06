# Copyright (c) 2022 - 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

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
$ source .venv/bin/activate
$ (.venv) pip install pytest psutil paramiko
$ (.venv) vim pyproject.toml
$ (.venv) pytest

"""

import time
import logging
from vtpmtool import VtpmTool, vtpm_context

LOG = logging.getLogger(__name__)

def test_config_A_launch_tdvf_without_vtpm():
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()

def test_config_A_launch_tdvf_with_vtpm_shell():
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
    
def test_config_A_reset_tdvm():
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 30
        ctx.generate_startup_into_vtpm_test_img(
            ["fs0:", "Tcg2DumpLog.efi > event0.log", "reset"]
        )
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td()  # user td will be terminated because `reset` is not supported
        
        ctx.generate_startup_into_vtpm_test_img(
            ["fs0:", "Tcg2DumpLog.efi > event1.log", "reset"]
        )
        ctx.start_user_td()
        ctx.terminate_all_tds()
        content0 = ctx.read_log(filename="event0.log", auto_delete=False)
        content1 = ctx.read_log(filename="event1.log", auto_delete=False)
        
        assert content0 and Utils.EVENT_ERR_FLAG not in content0
        assert content1 and Utils.EVENT_ERR_FLAG not in content1

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

def test_config_A_send_create_command_twice_with_qmp():
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 30
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
                --ek-context rsa_ek.ctx \
                --key-algorithm rsa \
                --public rsa_ek.pub',
            f'tpm2_createak --ek-context rsa_ek.ctx \
                --ak-context rsa_ak.ctx \
                --key-algorithm rsa \
                --hash-algorithm sha256 \
                --signing-algorithm rsassa \
                --public rsa_ak.pub --private rsa_ak.priv --ak-name rsa_ak.name'
        ] 
        for cmd in cmd0_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # EK WA
        LOG.info("EK provision WA") 
        cmd1_list = [
            # f'openssl genrsa -out ek.key 2048',
            # f'openssl req -new-key ek.key -out ek.csr',
            # f'openssl x509 -req -days 365 -in ek.csr -signkey ek.key -out ek.crt',
            f'tpm2_nvdefine 0x01c00002 -C o -a "ownerread|policyread|policywrite|ownerwrite|authread|authwrite"',
            f'tpm2_nvwrite 0x01c00002  -C o -i ek.crt'
        ] 
        for cmd in cmd1_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # Device-Node retrieving the endorsement-key-certificate to send to the Privacy-CA
        LOG.info("Retrieving EK and send to Provacy-CA") 
        cmd2_script = '''
                  #!/bin/bash\n
                  RSA_EK_CERT_NV_INDEX=0x01C00002\n
                  NV_SIZE=`tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output rsa_ek_cert.bin $RSA_EK_CERT_NV_INDEX\n
                  sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' rsa_ek_cert.bin | base64 --decode > rsa_ek_cert.bin'''
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
                file_size=`stat --printf="%s" rsa_ak.name`\n
                loaded_key_name=`cat rsa_ak.name | xxd -p -c $file_size`\n
                echo "this is my secret" > file_input.data\n
                tpm2_makecredential --tcti none --encryption-key rsa_ek.pub --secret file_input.data --name $loaded_key_name --credential-blob cred.out\n
                tpm2_startauthsession --policy-session --session session.ctx\n
                TPM2_RH_ENDORSEMENT=0x4000000B\n
                tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT\n
                tpm2_activatecredential --credentialedkey-context rsa_ak.ctx --credentialkey-context rsa_ek.ctx --credential-blob cred.out --certinfo-data actcred.out --credentialkey-auth "session:session.ctx"\n
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
                --key-context rsa_ak.ctx \
                --pcr-list sha256:0,1,2 \
                --message pcr_quote.plain \
                --signature pcr_quote.signature \
                --qualification SERVICE_PROVIDER_NONCE \
                --hash-algorithm sha256 \
                --pcr pcr.bin',
            f'tpm2_checkquote \
                --public rsa_ak.pub \
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
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True)
        ctx.connect_ssh()
        # TBD - Check CCEL table
        # TBD - Do RTMR replay
        ctx.terminate_user_td()

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
                --ek-context rsa_ek.ctx \
                --key-algorithm rsa \
                --public rsa_ek.pub',
            f'tpm2_createak --ek-context rsa_ek.ctx \
                --ak-context rsa_ak.ctx \
                --key-algorithm rsa \
                --hash-algorithm sha256 \
                --signing-algorithm rsassa \
                --public rsa_ak.pub --private rsa_ak.priv --ak-name rsa_ak.name'
        ] 
        for cmd in cmd0_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # EK WA
        LOG.info("EK provision WA") 
        cmd1_list = [
            # f'openssl genrsa -out ek.key 2048',
            # f'openssl req -new-key ek.key -out ek.csr',
            # f'openssl x509 -req -days 365 -in ek.csr -signkey ek.key -out ek.crt',
            f'tpm2_nvdefine 0x01c00002 -C o -a "ownerread|policyread|policywrite|ownerwrite|authread|authwrite"',
            f'tpm2_nvwrite 0x01c00002  -C o -i ek.crt'
        ] 
        for cmd in cmd1_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # Device-Node retrieving the endorsement-key-certificate to send to the Privacy-CA
        LOG.info("Retrieving EK and send to Provacy-CA") 
        cmd2_script = '''
                  #!/bin/bash\n
                  RSA_EK_CERT_NV_INDEX=0x01C00002\n
                  NV_SIZE=`tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output rsa_ek_cert.bin $RSA_EK_CERT_NV_INDEX\n
                  sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' rsa_ek_cert.bin | base64 --decode > rsa_ek_cert.bin'''
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
                file_size=`stat --printf="%s" rsa_ak.name`\n
                loaded_key_name=`cat rsa_ak.name | xxd -p -c $file_size`\n
                echo "this is my secret" > file_input.data\n
                tpm2_makecredential --tcti none --encryption-key rsa_ek.pub --secret file_input.data --name $loaded_key_name --credential-blob cred.out\n
                tpm2_startauthsession --policy-session --session session.ctx\n
                TPM2_RH_ENDORSEMENT=0x4000000B\n
                tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT\n
                tpm2_activatecredential --credentialedkey-context rsa_ak.ctx --credentialkey-context rsa_ek.ctx --credential-blob cred.out --certinfo-data actcred.out --credentialkey-auth "session:session.ctx"\n
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
                --key-context rsa_ak.ctx \
                --pcr-list sha256:0,1,2 \
                --message pcr_quote.plain \
                --signature pcr_quote.signature \
                --qualification SERVICE_PROVIDER_NONCE \
                --hash-algorithm sha256 \
                --pcr pcr.bin',
            f'tpm2_checkquote \
                --public rsa_ak.pub \
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
    with vtpm_context() as ctx:
        ctx.start_user_td(with_guest_kernel=True, grub_boot=True)
        ctx.connect_ssh()
        # TBD - Check CCEL table
        # TBD - Do RTMR replay
        ctx.terminate_user_td()

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
                --ek-context rsa_ek.ctx \
                --key-algorithm rsa \
                --public rsa_ek.pub',
            f'tpm2_createak --ek-context rsa_ek.ctx \
                --ak-context rsa_ak.ctx \
                --key-algorithm rsa \
                --hash-algorithm sha256 \
                --signing-algorithm rsassa \
                --public rsa_ak.pub --private rsa_ak.priv --ak-name rsa_ak.name'
        ] 
        for cmd in cmd0_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # EK WA
        LOG.info("EK provision WA") 
        cmd1_list = [
            # f'openssl genrsa -out ek.key 2048',
            # f'openssl req -new-key ek.key -out ek.csr',
            # f'openssl x509 -req -days 365 -in ek.csr -signkey ek.key -out ek.crt',
            f'tpm2_nvdefine 0x01c00002 -C o -a "ownerread|policyread|policywrite|ownerwrite|authread|authwrite"',
            f'tpm2_nvwrite 0x01c00002  -C o -i ek.crt'
        ] 
        for cmd in cmd1_list:
            LOG.info(cmd)
            runner = ctx.exec_ssh_command(cmd)
            assert runner[1] == "", "Failed to execute remote command"
        
        # Device-Node retrieving the endorsement-key-certificate to send to the Privacy-CA
        LOG.info("Retrieving EK and send to Provacy-CA") 
        cmd2_script = '''
                  #!/bin/bash\n
                  RSA_EK_CERT_NV_INDEX=0x01C00002\n
                  NV_SIZE=`tpm2_nvreadpublic $RSA_EK_CERT_NV_INDEX | grep size |  awk '{print $2}'`\n
                  tpm2_nvread --hierarchy owner --size $NV_SIZE --output rsa_ek_cert.bin $RSA_EK_CERT_NV_INDEX\n
                  sed 's/-/+/g;s/_/\//g;s/%3D/=/g;s/^{.*certificate":"//g;s/"}$//g;' rsa_ek_cert.bin | base64 --decode > rsa_ek_cert.bin'''
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
                file_size=`stat --printf="%s" rsa_ak.name`\n
                loaded_key_name=`cat rsa_ak.name | xxd -p -c $file_size`\n
                echo "this is my secret" > file_input.data\n
                tpm2_makecredential --tcti none --encryption-key rsa_ek.pub --secret file_input.data --name $loaded_key_name --credential-blob cred.out\n
                tpm2_startauthsession --policy-session --session session.ctx\n
                TPM2_RH_ENDORSEMENT=0x4000000B\n
                tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT\n
                tpm2_activatecredential --credentialedkey-context rsa_ak.ctx --credentialkey-context rsa_ek.ctx --credential-blob cred.out --certinfo-data actcred.out --credentialkey-auth "session:session.ctx"\n
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
                --key-context rsa_ak.ctx \
                --pcr-list sha256:0,1,2 \
                --message pcr_quote.plain \
                --signature pcr_quote.signature \
                --qualification SERVICE_PROVIDER_NONCE \
                --hash-algorithm sha256 \
                --pcr pcr.bin',
            f'tpm2_checkquote \
                --public rsa_ak.pub \
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
