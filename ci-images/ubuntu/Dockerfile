FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
ARG GO_SHA256_LINUX_AMD64
ARG GO_VERSION
ARG TARGETARCH
ARG VAULT_VERSION
ARG VAULT_SHA256_LINUX_AMD64

RUN dpkg --purge unattended-upgrades \
  && apt-get update \
  && apt-get install -y --no-install-recommends \
    bsdutils \
    build-essential \
    clang \
    cmake \
    devscripts \
    git \
    libdw-dev \
    libdwarf-dev \
    libelf-dev \
    llvm \
    pkgconf \
    software-properties-common \
    ubuntu-dev-tools \
    unzip \
    wget \
    zlib1g-dev

# install Go
ENV GO_VERSION=$GO_VERSION
ENV GOPATH=/go
RUN wget -O /tmp/golang.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  && echo "${GO_SHA256_LINUX_AMD64}  /tmp/golang.tar.gz" | sha256sum --check \
  && tar -C /usr/local -xzf /tmp/golang.tar.gz \
  && rm -f /tmp/golang.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV PATH="${GOPATH}/bin:${PATH}"

# build pahole
RUN --mount=type=bind,source=3rdparty/dwarves,target=/tmp/dwarves,readwrite \
  mkdir /tmp/dwarves/build && cd /tmp/dwarves/build \
  && cmake -D__LIB=lib -DDWARF_INCLUDE_DIR=/usr/include -DGIT_SUBMODULE=OFF .. \
  && make -j "$(nproc)" install \
  && echo "/usr/local/lib" | tee /etc/ld.so.conf.d/pahole.conf \
  && ldconfig

# build bpftool
RUN --mount=type=bind,source=3rdparty/bpftool,target=/tmp/bpftool,readwrite \
  cd /tmp/bpftool \
  && make -j "$(nproc)" -C src/ V=1 install-bin

# Install vault: https://github.com/hashicorp/vault/blob/main/CHANGELOG.md https://releases.hashicorp.com/vault
RUN wget -nv -O /tmp/vault.zip "https://releases.hashicorp.com/vault/${VAULT_VERSION}/vault_${VAULT_VERSION}_linux_${TARGETARCH}.zip" \
  && echo "${VAULT_SHA256_LINUX_AMD64}" /tmp/vault.zip | sha256sum --check \
  && unzip -o /tmp/vault.zip -d /usr/bin vault \
  && rm /tmp/vault.zip \
