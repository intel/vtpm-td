#!/bin/bash
set -e

CURR_DIR=$(readlink -f "$(dirname "$0")")

CREATEEK="tpm2_createek"
NVDEFINE="tpm2_nvdefine"
NVWRITE="tpm2_nvwrite"
OPENSSL="openssl"

EKALG="ecc384"
EKAUTH=""
OWAUTH=""
EKCTX=""
CA=""
CAKEY=""
CAPSW=""
SUBJ=""

EK_CMD="${CREATEEK}"
GENERATE_CMD="${OPENSSL} x509 -new"

EK_NV_INDEX="0x01c00002"
EK_NV_ATTR="ownerread|policyread|policywrite|ownerwrite|authread|authwrite"
EK_PUB="ek.pub"
EK_CERT="ek.crt"

usage() {
    cat << EOM
Usage: $(basename "$0") [OPTION]...
  -g <endorsement key algorithm>     Default is ecc384, supported values: [rsa/rsa2048/rsa3072/ecc/ecc256/ecc384]
  -a <endorsement key auth>          The authorization value for the endorsement hierarchy, default is empty
  -w <owner authorization>           The authorization value for the owner hierarchy, default is empty
  -t <EK context>                    Either a file path or a persistent handle value to save the endorsement key.
  -k <CA signing key>                CA signing key file name
  -c <CA certificate>                CA certficate file name
  -p <CA key password>               The password for the CA key, default is empty
  -j <Certificate subject name>      Set the subject name of EK certificate to the given value when it is created.
EOM
}

error() {
    echo -e "\e[1;31mERROR: $*\e[0;0m"
    exit 1
}

warn() {
    echo -e "\e[1;33mWARN: $*\e[0;0m"
}

process_args() {
    while getopts ":g:a:w:t:k:c:p:j:h:" option; do
        case "$option" in
            g) EKALG=$OPTARG;;
            a) EKAUTH=$OPTARG;;
            w) OWAUTH=$OPTARG;;
            t) EKCTX=$OPTARG;;
            k) CAKEY=$OPTARG;;
            c) CA=$OPTARG;;
            p) CAPSW=$OPTARG;;
            j) SUBJ=$OPTARG;;
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

    if [[ -z ${EKCTX} ]]; then
        error "Please specify the endorsement key context through -t."
    fi

    if [[ -z ${CA} ]]; then
        error "Please specify the CA file through -c."
    fi

    if [[ ! -f ${CA} ]]; then
        error "CA file ${CA} does not exist."
    fi

    if [[ -z ${CAKEY} ]]; then
        error "Please specify the CA key file through -k."
    fi

    if [[ ! -f ${CAKEY} ]]; then
        error "CA key file ${CAKEY} does not exist."
    fi

    if [[ -z ${SUBJ} ]]; then
        error "Please specify the subject name of EK certificate through -j."
    fi
 
    case "${EKALG}" in
        rsa|rsa2048|rsa3072) echo "";;
        ecc|ecc256|ecc384) echo "";;
        *) die "Unspported ek algorithm: ${type}";;
    esac

    if [[ ! -z ${EKAUTH} ]]; then
        EK_CMD+="-P ${EKAUTH}"
    fi
    if [[ ! -z ${OWAUTH} ]]; then
        EK_CMD+="-w ${OWAUTH}"
    fi
    EK_CMD+=" -c ${EKCTX} -G ${EKALG} -u ${EK_PUB} -f pem"

    GENERATE_CMD+=" -force_pubkey ${EK_PUB} -subj ${SUBJ} -CA ${CA} -CAkey ${CAKEY} -out ${EK_CERT}"
}

set_ek_cert() {
    DEFINE="${NVDEFINE} ${EK_NV_INDEX} -C o -a ${EK_NV_ATTR}"
    echo "Run: ${DEFINE}"
    ${DEFINE}

    WRITE="${NVWRITE} ${EK_NV_INDEX}  -C o -i ${EK_CERT}"
    echo "Run: ${WRITE}"
    ${WRITE}
}

ek_cert() {
    echo "Creating endorsement key... ${EK_CMD}"
    ${EK_CMD}
    echo "Generating EK certificate... ${GENERATE_CMD}"
    ${GENERATE_CMD}
    echo "Provisioning EK certificate to TPM... ${PROVISION_CMD}"
    set_ek_cert
}

process_args "$@"
ek_cert
