# Verify vTPM features
After booting up to TD guest OS, vTPM features can be used as normal TPM. It can be verified by:
* [tpm2-tools](#tpm2-tools)
* [LinuxIMA (Integrity Measurement Architecture)](#linux-ima)
* [Keylime](#keylime)
## tpm2-tools
It’s recommended to build and install tpm2-tools in TD guest image.
Please install the following dependencies before building and installing tpm2-tools.
```
$ sudo apt-get -y install \
      autoconf-archive libcmocka0 libcmocka-dev procps iproute2 \
      build-essential git pkg-config gcc libtool automake libssl-dev \
      uthash-dev autoconf doxygen libjson-c-dev libini-config-dev \
      libcurl4-openssl-dev uuid-dev libltdl-dev libusb-1.0-0-dev \
      libarchive-dev clang libglib2.0-dev
```
Follow document: https://tpm2-tools.readthedocs.io/en/latest/INSTALL/ to build and install tpm2-tools.

Run [tpm2_pcrread](https://tpm2-tools.readthedocs.io/en/latest/man/tpm2_pcrread.1/) to read the PCR registers.
![TPM2_PCRREAD](tpm2_pcrread.png)

## Linux IMA
Linux IMA (Integrity Measurement Architecture) is enabled by extending IMA measurement
to RTMR and vTPM PCRs, which enables user space application runtime measurement.
Runtime measurements within TD guest can avoid being compromised and use to attest to
the system's runtime integrity.

## Keylime
vTPM can be used for [Keylime](https://github.com/keylime/rust-keylime) to do remote attestation
with Linux IMA enabled. Keylime verifier will do continually remote attestation with Linux IMA
measurement records protected with vTPM from Keylime agent deployed inside TDVM and compare against
know good values provided by trusted admin or third parties.

Note: Keylime must include the patch#88e033c3a which fixes the SHA1 issue for TPM PCR16.
