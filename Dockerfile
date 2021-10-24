FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get -y --no-install-recommends install \
    build-essential \
    cmake \
    git \
    pkg-config \
    libsodium-dev \
    mingw-w64 \
    wine-stable \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ARG TOXCORE_VERSION=0.2.12
ADD https://github.com/TokTok/c-toxcore/archive/refs/tags/v${TOXCORE_VERSION}.tar.gz /toxcore/
WORKDIR /toxcore
RUN tar xzf v${TOXCORE_VERSION}.tar.gz && \
    cd c-toxcore-${TOXCORE_VERSION} && \
    cmake . -DBOOTSTRAP_DAEMON=OFF && \
    cmake --build . && \
    make install && \
    echo '/usr/local/lib/' >> /etc/ld.so.conf.d/locallib.conf && \
    ldconfig

WORKDIR /toxext
