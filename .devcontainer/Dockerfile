FROM mcr.microsoft.com/devcontainers/go:1.22-bookworm

RUN apt update

RUN apt install -y build-essential
RUN apt install -y pkg-config
RUN apt install -y clang
RUN apt install -y llvm
RUN apt install -y git
RUN apt install -y libelf-dev
RUN apt install -y libpcap-dev
RUN apt install -y iproute2
RUN apt install -y iputils-ping
RUN apt install -y linux-headers-generic
RUN apt install -y libbpf-dev
RUN apt install -y linux-libc-dev
RUN apt install -y cmake
RUN apt install -y libpcap-dev
RUN apt install -y libcap-ng-dev
RUN apt install -y libbfd-dev
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm
RUN apt install -y libcap-dev
RUN ln -sf /usr/local/go/bin/go /bin/go

RUN cp /usr/include/x86_64-linux-gnu/asm/byteorder.h /usr/include/asm
RUN ln -sf /usr/include/asm-generic/ /usr/include/asm