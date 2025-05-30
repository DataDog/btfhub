FROM amazonlinux:2

ARG CLANG_SHA256_LINUX_AMD64
ARG CLANG_VERSION
ARG GO_SHA256_LINUX_AMD64
ARG GO_VERSION
ARG TAR_PREFIX=/usr
ARG TAR_SHA256
ARG TAR_VERSION
ARG TARGETARCH
ARG VAULT_VERSION
ARG VAULT_SHA256_LINUX_AMD64

RUN yum install -y \
  clang \
  cmake \
  elfutils-devel \
  elfutils-libelf-devel \
  git \
  gzip \
  libdwarf-devel \
  make \
  tar \
  unzip \
  wget \
  xz \
  yum-utils
RUN yum-config-manager -y --enable amzn2-core-debuginfo
# enable access to arm64 repo
RUN echo "[amzn2-core-debuginfo-alt]" >> /etc/yum.repos.d/amzn2-core.repo \
  && awk '/^\[/{found=""} /^\[amzn2-core-debuginfo]$/{found=1;next} found && NF' /etc/yum.repos.d/amzn2-core.repo | sed 's/\$basearch/aarch64/g' >> /etc/yum.repos.d/amzn2-core.repo

COPY .wgetrc /root/

# install Go
ENV GO_VERSION=$GO_VERSION
ENV GOPATH=/go
RUN wget -O /tmp/golang.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" \
  && echo "${GO_SHA256_LINUX_AMD64}  /tmp/golang.tar.gz" | sha256sum --check \
  && tar -C /usr/local -xzf /tmp/golang.tar.gz \
  && rm -f /tmp/golang.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"
ENV PATH="${GOPATH}/bin:${PATH}"

# build tar
RUN wget -nv -O /tmp/tar.tar.xz "https://gnu.mirror.constant.com/tar/tar-${TAR_VERSION}.tar.xz" \
  && echo "${TAR_SHA256}  /tmp/tar.tar.xz" | sha256sum --check \
  && tar -C /tmp -xf /tmp/tar.tar.xz \
  && cd "/tmp/tar-${TAR_VERSION}" \
  && FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="${TAR_PREFIX}" \
  && make -j "$(nproc)" install \
  && rm -rf "/tmp/tar-${ELFUTILS_VERSION}" \
  && rm /tmp/tar.tar.xz

# install clang
RUN wget -O /tmp/clang.tar.xz -nv "https://github.com/llvm/llvm-project/releases/download/llvmorg-${CLANG_VERSION}/clang+llvm-${CLANG_VERSION}-x86_64-linux-gnu-ubuntu-16.04.tar.xz" \
  && echo "${CLANG_SHA256_LINUX_AMD64}  /tmp/clang.tar.xz" | sha256sum --check \
  && mkdir -p /opt/clang \
  && tar -xf /tmp/clang.tar.xz --no-same-owner -C /opt/clang --strip-components=1 \
  && rm /tmp/clang.tar.xz
ENV PATH="/opt/clang/bin:${PATH}"

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

# Install gh CLI
RUN wget -nv -O /tmp/gh.tar.gz "https://github.com/cli/cli/releases/download/v${GH_CLI_VERSION}/gh_${GH_CLI_VERSION}_linux_${TARGETARCH}.tar.gz" \
  && echo "${GH_CLI_SHA256_LINUX_AMD64}" /tmp/gh.tar.gz | sha256sum --check \
  && tar -C /usr/local --strip-components=1 -xzf /tmp/gh.tar.gz \
  && rm -f /tmp/gh.tar.gz
