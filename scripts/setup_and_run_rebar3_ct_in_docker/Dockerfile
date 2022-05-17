ARG BUILD_FROM=ubuntu:22.04
FROM ${BUILD_FROM}

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    apt-utils

RUN apt-get update && apt-get install -y \
    apt-utils \
    apt-transport-https \
    autoconf \
    automake \
    autotools-dev \
    bison \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    debhelper \
    flex \
    g++ \
    gcc \
    git \
    jq \
    libffi-dev \
    libncurses5-dev \
    libssl-dev \
    libtool \
    make \
    python3 \
    python3-pip \
    software-properties-common \
    unzip \
    vim \
    wget \
    zip \
    zlib1g-dev \
    krb5-kdc \
    krb5-admin-server \
    man \
    libkrb5-dev \
    libsasl2-dev \
    libsasl2-modules-gssapi-mit

RUN ln -sf /usr/bin/python3 /usr/bin/python
RUN ln -sf /usr/bin/pip3 /usr/bin/pip

RUN cmake --version

RUN apt-get clean\
 && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /opt/

RUN mkdir kerl

WORKDIR /opt/kerl

RUN curl -O https://raw.githubusercontent.com/kerl/kerl/master/kerl

RUN chmod a+x kerl

RUN ./kerl build 24.2.1

RUN ./kerl install 24.2.1 /opt/kerl/24.2.1

ENV PATH=$PATH:/opt/kerl/24.2.1/bin

RUN . /opt/kerl/24.2.1/activate

ENV LANG=C.UTF-8
#############################################
# Install Rebar3
#############################################

WORKDIR /opt/
RUN git clone https://github.com/erlang/rebar3.git

WORKDIR /opt/rebar3

RUN ./bootstrap
RUN ./rebar3 local install

#############################################
# Set Environment variables
#############################################


ENV PATH=$PATH:/opt/kerl:/opt/rebar3:/opt/kerl/24.2.1/bin
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

