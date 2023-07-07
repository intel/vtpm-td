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
$ (.venv) pip install pytest psutil
$ (.venv) vim pyproject.toml
$ (.venv) pytest

"""

import time

from vtpmtool import VtpmTool, vtpm_context


def test_tcs001_negative():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(["fs0:", "Tcg2DumpLog.efi > event.log"])
        ctx.start_user_td()
        ctx.terminate_user_td()
        content = ctx.read_log(filename="event.log")
    assert content and Utils.EVENT_ERR_FLAG in content


def test_tcs002_1_vtpm_1_user():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(["fs0:", "Tcg2DumpLog.efi > event.log"])
        ctx.default_run_and_terminate()
        content = ctx.read_log(filename="event.log")
    assert content and Utils.EVENT_ERR_FLAG not in content


def test_tcs003_1_vtpm_1_user_reset():
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


def test_tcs004_1_vtpm_1_user_check_acpi_table():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(
            ["fs0:", "acpidump.efi -n tdtk > acpidump.log"]
        )
        ctx.default_run_and_terminate()
        content = ctx.read_log(filename="acpidump.log")
    assert content and Utils.TDTK_FLAG in content


def test_tcs005_1_vtpm_1_user_check_rtmr():
    with vtpm_context() as ctx:
        ctx.generate_startup_into_vtpm_test_img(["fs0:", "RtmrDump.efi > rtmrdump.log"])
        ctx.default_run_and_terminate()
        content = ctx.read_log(filename="rtmrdump.log")

    rtmr0, rtmr1, rtmr2, rtmr3 = [
        Utils.extract_rtmr_value(content, i) for i in range(4)
    ]

    # check RTMR0 and RTMR3 - should not be zero
    assert rtmr0 and any(c != "0" for c in rtmr0)
    assert rtmr3 and any(c != "0" for c in rtmr3)

    # check RTMR1 and RTMR2 - are equal with fixed value
    expected_value = "879606558AC3776B815615CE42F361976430D931D5DA09D77E0C5EC08CC76D00F5D6CF5EB704B9ED19FF7CCCF47C9083"
    assert rtmr1 == rtmr2 and rtmr1 == expected_value


def test_tcs006_2_vtpm_2_user(count_overwrite: int = None):
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

        # check event log - not error and should be same
        event, next_event = current[0], next[0]
        assert Utils.EVENT_ERR_FLAG not in event and event == next_event

        # check RTMR[0-2] - should be same and not empty
        rtmrs, next_rtmrs = current[1], next[1]
        assert rtmrs[0] and rtmrs[:3] == next_rtmrs[:3]

        # check acpi table - both have TDTK
        acpi, next_acpi = current[2], next[2]
        assert Utils.TDTK_FLAG in acpi and Utils.TDTK_FLAG in next_acpi


def test_tcs007_10_vtpm_10_user():
    test_tcs006_2_vtpm_2_user(count_overwrite=10)


def test_tcs008_1_vtpm_1_user_stress_reset_500_cycles(cycle_overwrite: int = None):
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


def test_tcs009_1_vtpm_1_user_launch_guest_kernel():
    with vtpm_context() as ctx:
        ctx.wait_tools_run_seconds = 20
        ctx.start_vtpm_td()
        ctx.execute_qmp()
        ctx.start_user_td(with_guest_kernel=True)
        ctx.terminate_all_tds()
        content = ctx.read_console()
    assert content and Utils.KERNEL_VTPM_FLAG in content


def test_tcs010_send_create_command_twice_with_qmp():
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
