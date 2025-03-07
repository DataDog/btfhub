FROM registry.access.redhat.com/rhel7:latest

ARG CLANG_SHA256_LINUX_AMD64
ARG CLANG_VERSION
ARG ELFUTILS_SHA256
ARG ELFUTILS_VERSION
ARG GO_SHA256_LINUX_AMD64
ARG GO_VERSION
ARG TAR_PREFIX=/usr
ARG TAR_SHA256
ARG TAR_VERSION
ARG TARGETARCH
ARG VAULT_VERSION
ARG VAULT_SHA256_LINUX_AMD64

RUN rm -rf /etc/rhsm-host
RUN --mount=type=bind,target=/etc/pki/consumer,source=.tmp/${TARGETARCH}/consumer \
  --mount=type=bind,target=/etc/pki/entitlement,source=.tmp/${TARGETARCH}/entitlement \
  subscription-manager repos \
    --enable=rhel-7-server-debug-rpms \
    --enable=rhel-7-server-rpms \
  && yum install -y \
    bzip2 \
    cmake \
    find \
    gzip \
    m4 \
    make \
    wget \
    unzip \
    xz \
    yum-utils \
    zlib-devel

# install clang 5 and gcc 7
RUN --mount=type=bind,target=/etc/pki/consumer,source=.tmp/${TARGETARCH}/consumer \
  --mount=type=bind,target=/etc/pki/entitlement,source=.tmp/${TARGETARCH}/entitlement \
  subscription-manager repos \
    --enable rhel-7-server-devtools-rpms \
    --enable rhel-7-server-optional-rpms \
    --enable rhel-server-rhscl-7-rpms \
  && cd /etc/pki/rpm-gpg \
  && wget -O RPM-GPG-KEY-redhat-devel https://www.redhat.com/security/data/a5787476.txt \
  && rpm --import RPM-GPG-KEY-redhat-devel \
  && yum install -y \
    devtoolset-7 \
    llvm-toolset-7 \
  && subscription-manager repos \
    --disable rhel-7-server-devtools-rpms \
    --disable rhel-7-server-optional-rpms \
    --disable rhel-server-rhscl-7-rpms
ENV PATH="/opt/rh/devtoolset-7/root/usr/bin:/opt/rh/llvm-toolset-7/root/usr/sbin:/opt/rh/llvm-toolset-7/root/usr/bin:$PATH"

# install newer git
RUN --mount=type=bind,target=/etc/pki/consumer,source=.tmp/${TARGETARCH}/consumer \
  --mount=type=bind,target=/etc/pki/entitlement,source=.tmp/${TARGETARCH}/entitlement \
  yum remove -y git \
  && yum install -y https://repo.ius.io/ius-release-el7.rpm https://dl.fedoraproject.org/pub/archive/epel/7/x86_64/Packages/e/epel-release-7-14.noarch.rpm \
  && yum install -y git236

# install Go
ENV GO_VERSION=$GO_VERSION
ENV GOPATH=/go
RUN wget -O /tmp/golang.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  && echo "${GO_SHA256_LINUX_AMD64}  /tmp/golang.tar.gz" | sha256sum --check \
  && tar -C /usr/local -xzf /tmp/golang.tar.gz \
  && rm -f /tmp/golang.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV PATH="${GOPATH}/bin:${PATH}"

# install elfutils
RUN wget -nv -O /tmp/elfutils.tar.bz2 "https://sourceware.org/elfutils/ftp/${ELFUTILS_VERSION}/elfutils-${ELFUTILS_VERSION}.tar.bz2" \
  && echo "${ELFUTILS_SHA256}  /tmp/elfutils.tar.bz2" | sha256sum --check \
  && tar -C /tmp -xf /tmp/elfutils.tar.bz2 \
  && cd "/tmp/elfutils-${ELFUTILS_VERSION}" \
  && ./configure --disable-libdebuginfod --disable-debuginfod --disable-demangler \
  && make -j "$(nproc)" install \
  && install -vm644 config/libelf.pc /usr/lib64/pkgconfig \
  && ldconfig \
  && rm -rf "/tmp/elfutils-${ELFUTILS_VERSION}" \
  && rm /tmp/elfutils.tar.bz2

# build tar
RUN wget -nv -O /tmp/tar.tar.xz "https://gnu.mirror.constant.com/tar/tar-${TAR_VERSION}.tar.xz" \
  && echo "${TAR_SHA256}  /tmp/tar.tar.xz" | sha256sum --check \
  && tar -C /tmp -xf /tmp/tar.tar.xz \
  && cd "/tmp/tar-${TAR_VERSION}" \
  && FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="${TAR_PREFIX}" \
  && make -j "$(nproc)" install \
  && rm -rf "/tmp/tar-${ELFUTILS_VERSION}" \
  && rm /tmp/tar.tar.xz

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
  && rm /tmp/vault.zip
