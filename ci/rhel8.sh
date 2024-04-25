#!/bin/bash
set -eEuo pipefail

declare -xr ARCH="$1" REPO_ARCH="$2" DD_BTFHUB_RHEL_ORG_ID="$3"
NPROC=$(nproc)

function unregister() {
  subscription-manager remove --all
  subscription-manager unregister
  subscription-manager clean
}
trap unregister EXIT

# packages
rm -rf /etc/rhsm-host
subscription-manager register --org="${DD_BTFHUB_RHEL_ORG_ID}" --activationkey="btfhub-ci"
subscription-manager repos --enable="rhel-8-for-${REPO_ARCH}-baseos-debug-rpms"
subscription-manager repos --enable="rhel-8-for-${REPO_ARCH}-baseos-eus-debug-rpms"
subscription-manager release --set=8.1
yum install -y yum-utils clang wget bzip2 zlib-devel m4 xz gzip cmake make gcc ncurses-compat-libs

# go
mkdir -p ~/bin
curl -sL -o ~/bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/bin/gimme
~/bin/gimme 1.21.8
source ~/.gimme/envs/go1.21.8.env

# elfutils
wget -nv https://sourceware.org/elfutils/ftp/0.190/elfutils-0.190.tar.bz2
tar xf elfutils-0.190.tar.bz2
pushd elfutils-0.190
./configure --disable-libdebuginfod --disable-debuginfod --disable-demangler
make -j "${NPROC}" install
ldconfig
popd

# tar
wget -nv https://ftpmirror.gnu.org/tar/tar-1.35.tar.xz
tar xf tar-1.35.tar.xz
pushd tar-1.35
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr
make -j "${NPROC}" install
popd

# clang
yum remove -y clang
if [[ "${ARCH}" == "x86_64" ]]; then
  wget -nv https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
  tar xf clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu-16.04.tar.xz
  mv clang+llvm-12.0.1-x86_64-linux-gnu-ubuntu- clang
else
  wget -nv https://github.com/llvm/llvm-project/releases/download/llvmorg-12.0.1/clang+llvm-12.0.1-aarch64-linux-gnu.tar.xz
  tar xf clang+llvm-12.0.1-aarch64-linux-gnu.tar.xz
  mv clang+llvm-12.0.1-aarch64-linux-gnu clang
fi
PATH="$(pwd)/clang/bin:${PATH}"
export PATH

# pahole
pushd ./3rdparty/dwarves
mkdir build
cd build
cmake -D__LIB=lib -DDWARF_INCLUDE_DIR=/usr/include ..
make -j "${NPROC}" install
echo "/usr/local/lib" >> /etc/ld.so.conf.d/pahole.conf
ldconfig
popd

# bpftool
pushd ./3rdparty/bpftool
make -C src/ V=1 install
popd

# build btfhub
make

# generate BTFs
BTFHUB_NO_SUDO=true ./btfhub -workers 6 -d rhel -r 8 -a "${ARCH}"
