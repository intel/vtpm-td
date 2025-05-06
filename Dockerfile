FROM ubuntu:24.04@sha256:6015f66923d7afbc53558d7ccffd325d43b4e249f41a6e93eef074c9505d2233

# Adding rust binaries to PATH.
ENV PATH="$PATH:/root/.cargo/bin"
WORKDIR /root

# Install all required packages in one go to optimize the image
# https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#run
# DEBIAN_FRONTEND is set for tzdata.
RUN apt-get update && \
    DEBIAN_FRONTEND="noninteractive" apt-get install --no-install-recommends -y \
    build-essential unzip ca-certificates curl gcc git libssl-dev pkg-config ssh \
    clang llvm nasm \
    ocaml ocamlbuild wget pkg-config libtool autoconf autotools-dev automake \
    screen expect \
    # cleanup
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install rustup and a fixed version of Rust.
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain nightly-2023-12-31
RUN rustup component add rust-src
RUN cargo install cargo-xbuild

RUN git clone --recursive https://github.com/intel/vtpm-td.git
