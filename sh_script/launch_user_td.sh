#!/bin/bash

QEMU=
BIOS=
KERNEL_IMAGE=
GUEST_IMAGE=
TEST_VTPM_IMAGE=
FORWARD_PORT=10038
TELNET_PORT=9032

now=$(date +"%m%d_%H%M%S")
LOGDIR=log_usertd
LOGFILE=${LOGDIR}/usertd.${now}.log

MEM=8G
TARGET=shell
USERTD_ID=aabbccdd-2012-2022-1234-123456789123

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -f <OVMF image file>      Firmware image file
  -q <QEMU path>            QEMU path
  -i <guest image file>     Guest image file, only for os 
  -k <kernel file>          Kernel file, only for os
  -u <user td id>           User TD ID - GUID
  -v <test vTPM image>      Test vTPM image for shell
  -t <boot to target>       Boot to [Shell/OS]
  -h                        Show this help
EOM
}

process_args() {
    while getopts "f:q:i:k:u:v:t:h" option; do
        case "${option}" in
            f) BIOS=$OPTARG;;
            q) QEMU=$OPTARG;;
            i) GUEST_IMAGE=$OPTARG;;
            k) KERNEL_IMAGE=$OPTARG;;
            u) USERTD_ID=$OPTARG;;
            v) TEST_VTPM_IMAGE=$OPTARG;;
            t) TARGET=$OPTARG;;
            h) usage
               exit 0
               ;;
            *)
               echo "Invalid option '-$OPTARG'"
               usage
               exit 1
               ;;
        esac
    done
    
    if [[ ! -f ${BIOS} ]]; then
        usage
        echo "OVMF image file ${BIOS} not exist, Please specify via option \"-f\""
        exit 1
    fi

    if [[ ! -f ${QEMU} ]]; then
        usage
        echo "QEMU ${QEMU} is not exist, Please specify via option \"-q\""
        exit 1
    fi

    if [[ ! "${USERTD_ID}" = "aabbccdd-2012-2022-1234-123456789123" ]]; then
        TEST_VTPM_IMAGE=${TEST_VTPM_IMAGE}.${USERTD_ID}
    fi

    case $TARGET in
        "shell")
                if [[ ! -f ${TEST_VTPM_IMAGE} ]]; then
                    usage
                    echo "Test vTPM image ${TEST_VTPM_IMAGE} is not exist, Please specify via option \"-v\""
                    exit 1
                fi
                MEM=1G
                QEMU_CMD="$QEMU \
                        -accel kvm \
                        -name process=user-td-ci,debug-threads=on \
                        -smp 1 \
                        -m ${MEM} \
                        -object tdx-guest,id=tdx,debug=on,vtpm-type=client,vtpm-userid=${USERTD_ID},vtpm-path=unix:/tmp/vtpm-server-${USERTD_ID}.sock \
                        -object memory-backend-memfd-private,id=usertd-ram2-${USERTD_ID},size=${MEM} \
                        -bios ${BIOS} \
                        -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,memory-backend=usertd-ram2-${USERTD_ID} \
                        -no-hpet \
                        -cpu host,host-phys-bits,-kvm-steal-time,-arch-lbr  \
                        -hda ${TEST_VTPM_IMAGE} \
                        -serial stdio -nodefaults | tee -a ${LOGFILE}
                        "
                ;;
        "os") 
                if [[ ! -f ${GUEST_IMAGE} ]]; then
                    usage
                    echo "Guest image file ${GUEST_IMG} not exist. Please specify via option \"-i\""
                    exit 1
                fi

                if [[ ! -f ${KERNEL_IMAGE} ]]; then
                    usage
                    echo "Kernel image file ${KERNEL_IMAGE} not exist. Please specify via option \"-k\""
                    exit 1
                fi
                QEMU_CMD="$QEMU \
                        -accel kvm \
                        -no-reboot \
                        -name process=user-td-ci,debug-threads=on \
                        -cpu host,host-phys-bits,-kvm-steal-time,-arch-lbr \
                        -smp 1 \
                        -m ${MEM} \
                        -object tdx-guest,id=tdx,debug=on,vtpm-type=client,vtpm-userid=${USERTD_ID},vtpm-path=unix:/tmp/vtpm-server-${USERTD_ID}.sock \
                        -object memory-backend-memfd-private,id=usertd-ram2-${USERTD_ID},size=${MEM} \
                        -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,memory-backend=usertd-ram2-${USERTD_ID} \
                        -bios ${BIOS} \
                        -nographic \
                        -vga none \
                        -chardev stdio,id=mux,mux=on,signal=off \
                        -device virtio-serial,romfile= \
                        -device virtconsole,chardev=mux \
                        -serial chardev:mux \
                        -monitor chardev:mux \
                        -drive file=${GUEST_IMAGE},if=virtio,format=qcow2 \
                        -device virtio-net-pci,netdev=mynet0 \
                        -netdev user,id=mynet0,hostfwd=tcp::${FORWARD_PORT}-:22 \
                        -kernel ${KERNEL_IMAGE} \
                        -append \"root=/dev/vda1 ro console=hvc0\" \
                        -monitor pty \
                        -monitor telnet:127.0.0.1:${TELNET_PORT},server,nowait \
                        -no-hpet \
                        -nodefaults | tee -a ${LOGFILE}"
                ;;
        *) 
                echo "Invalid ${TARGET}, must be [shell|os]"
                exit 1
                ;;
    esac
}

create_log_dir() {
    if [[ ! -d ${LOGDIR} ]]; then
        echo "Create log folder: ${LOGDIR}"
        mkdir ${LOGDIR}
    fi
}

launch_user_td() {
    create_log_dir
    # echo ${QEMU_CMD}
    eval $QEMU_CMD
}

process_args "$@"
launch_user_td