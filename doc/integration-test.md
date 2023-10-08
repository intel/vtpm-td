# vtpm-td integration test
## Pre-condition
Current vtpm-td works with [Linux TDX Stack](https://github.com/intel/tdx-tools/releases/tag/2023ww27). Please follow the [readme](https://github.com/intel/tdx-tools/blob/2023ww27/README.md) to prepare TDX environment.
- Install host kernel
- Install QEMU
- Setup attestion environment
- Create guest kernel Image

## Run intergation test
#### Preparation
Build Test Images
- Build [TDVF](https://github.com/tianocore/edk2-staging/tree/TDVF) follow [readme](https://github.com/tianocore/edk2-staging/blob/TDVF/OvmfPkg/IntelTdx/README)
- Build vTPM TD follow [readme](../README.md)

Download test script:
```
git clone https://github.com/intel/vtpm-td.git
```
Go to script folder:
```
cd sh_script
```
Config [test configration file](../sh_script/conf/pyproject.toml), for example:
```
[vtpm.config]
qemu="/usr/mvp/bin/qemu-system-x86_64"
vtpm_td_script = "launch_vtpm_td.sh"
user_td_script = "launch_user_td.sh"
vtpm_td_bios_img = "../../run-vtpm-td/vtpmtd.bin"
user_td_bios_img = "../../run-user-td/OVMF.fd"
kernel_img = "/home/env/vtpm/vmlinuz-jammy"
guest_img = "/home/env/vtpm/td-guest-ubuntu-22.04-test.qcow2"
guest_username = "root"
guest_password = "123456"
vtpm_test_img = "/home/env/vtpm/vtpm.img"
vtpm_test_img_mount_path = "/media/vtpm"
default_user_id = "aabbccdd-2012-2022-1234-123456789123"
default_startup_cmds = [
  "fs0:",
]
stress_test_cycles = 1000
```

#### Setup pytest environment
Please use recommend configuration in [integration_test.py](../sh_script/integration_test.py).

#### Run test with TDVF config-A
```
pytest -k "config_A"
```

#### Run test with TDVF config-B
```
pytest -k "config_B_no_sb"
```

#### Run test with TDVF config-B + Secure Boot
```
pytest -k "config_B_sb"
```

#### Run stress test with TDVF config-B
```
pytest -k "stress"
```

#### Run all tpm commands with tpm2_tools
```
pytest -k "test_tpm_cmd_with_vtpm"
```