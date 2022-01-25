FROM python:3.9-slim as compilers

RUN apt-get update && apt-get install -y curl wget

RUN mkdir -p "/ido5.3" && \
    curl -L "https://github.com/ethteck/ido-static-recomp/releases/download/master/ido-5.3-recomp-ubuntu-latest.tar.gz" | \
    tar zx -C "/ido5.3"

RUN mkdir -p "/ido7.1" && \
    curl -L "https://github.com/ethteck/ido-static-recomp/releases/download/master/ido-7.1-recomp-ubuntu-latest.tar.gz" | \
    tar zx -C "/ido7.1"

RUN mkdir -p "/gcc2.8.1" && \
    curl -L "https://github.com/pmret/gcc-papermario/releases/download/master/linux.tar.gz" | \
    tar zx -C "/gcc2.8.1" && \
    curl -L "https://github.com/pmret/binutils-papermario/releases/download/master/linux.tar.gz" | \
    tar zx -C "gcc2.8.1"

RUN mkdir -p /nu64 && \
    wget -P /nu64 "https://github.com/Rainchus/JPDecompPracticeROM/blob/main/tools/build/linux/cc1" && \
    wget -P /nu64 "https://github.com/Rainchus/JPDecompPracticeROM/blob/main/tools/build/linux/mips-nintendo-nu64-as"

# STAGE 2

FROM python:3.9-slim

RUN apt-get update && \
    apt-get install -y \
        binutils-mips-linux-gnu \
        cpp

RUN python3 -m pip install --upgrade \
    pycparser \
    pynacl \
    toml

COPY --from=compilers /ido5.3/usr/bin/ /tools/ido_recomp/linux/5.3
COPY --from=compilers /ido5.3/usr/lib/ /tools/ido_recomp/linux/5.3

COPY --from=compilers /ido7.1/usr/bin/ /tools/ido_recomp/linux/7.1
COPY --from=compilers /ido7.1/usr/lib/ /tools/ido_recomp/linux/7.1

COPY --from=compilers /gcc2.8.1 /tools/cc/gcc

COPY --from=compilers /nu64 /tools/linux

# setup some symlink fakery
RUN cd /tools && ln -nsf . build
RUN cd /tools && ln -nsf ido_recomp/linux/5.3 ido5.3_recomp
RUN cd /tools && ln -nsf ido_recomp/linux/7.1 ido7.1_recomp
RUN cd /tools && ln -nsf linux mac
