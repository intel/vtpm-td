#!/bin/bash

QEMU=
BIOS=
USERTD_ID=aabbccdd-2012-2022-1234-123456789123
MEM=256M

now=$(date +"%m%d_%H%M%S")
LOGDIR=log_vtpmtd
LOGFILE=${LOGDIR}/vtpmtd.${now}.log

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -f <vTPM image file>      Firmware image file
  -q <QEMU path>            QEMU path
  -u <user td id>           User TD ID - GUID
  -h                        Show this help
EOM
}

process_args() {
    while getopts "f:q:u:h" option; do
        case "${option}" in
            f) BIOS=$OPTARG;;
            q) QEMU=$OPTARG;;
            u) USERTD_ID=$OPTARG;;
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
        echo "vTPM image file ${BIOS} not exist, Please specify via option \"-f\""
        exit 1
    fi

    if [[ ! -f ${QEMU} ]]; then
        usage
        echo "QEMU ${QEMU} is not exist, Please specify via option \"-q\""
        exit 1
    fi

    QEMU_CMD="$QEMU \
            -accel kvm \
            -name debug-threads=on,process=vtpm-td-ci \
            -cpu host,host-phys-bits,-kvm-steal-time,-arch-lbr \
            -smp 1 -m ${MEM} \
            -object tdx-guest,id=tdx,debug=on,vtpm-type=server,vtpm-userid=${USERTD_ID},vtpm-path=unix:/tmp/vtpm-server-${USERTD_ID}.sock \
            -qmp unix:/tmp/qmp-sock-vtpm-${USERTD_ID},server,nowait \
            -object memory-backend-memfd-private,id=vtpm-ram1-${USERTD_ID},size=${MEM} \
            -machine q35,kernel_irqchip=split,confidential-guest-support=tdx,memory-backend=vtpm-ram1-${USERTD_ID} \
            -bios ${BIOS} \
            -nographic \
            -vga none \
            -no-hpet \
            -nodefaults \
            -chardev stdio,id=mux,mux=on,signal=off,logfile=${LOGFILE} \
            -device virtio-serial,romfile= \
            -device virtconsole,chardev=mux -serial chardev:mux -monitor chardev:mux \
            -d int -no-reboot"  
}

create_log_dir() {
    if [[ ! -d ${LOGDIR} ]]; then
        echo "Create log folder: ${LOGDIR}"
        mkdir ${LOGDIR}
    fi
}

launch_vtpm_td() {
    create_log_dir
    echo ${QEMU_CMD}
    eval $QEMU_CMD
}

process_args "$@"
launch_vtpm_td