#!/bin/bash
set -eEuo pipefail

declare -xr ARCH="$1" REPO_ARCH="$2" DD_BTFHUB_RHEL_ORG_ID="$3"

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
yum-config-manager --add-repo https://cli.github.com/packages/rpm/gh-cli.repo
yum install -y yum-utils wget bzip2 zlib-devel m4 xz gzip cmake make clang-12.0.1 gcc

# go
mkdir -p ~/bin
curl -sL -o ~/bin/gimme https://raw.githubusercontent.com/travis-ci/gimme/master/gimme
chmod +x ~/bin/gimme
~/bin/gimme 1.21.7
source ~/.gimme/envs/1.21.7.env

# elfutils
wget -nv https://sourceware.org/elfutils/ftp/0.190/elfutils-0.190.tar.bz2
tar xf elfutils-0.190.tar.bz2
pushd elfutils-0.190
./configure --disable-libdebuginfod --disable-debuginfod --disable-demangler
make install
ldconfig
popd

# tar
wget -nv https://ftpmirror.gnu.org/tar/tar-1.35.tar.xz
tar xf tar-1.35.tar.xz
pushd tar-1.35
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix=/usr
make install
popd

# pahole
pushd ./3rdparty/dwarves
mkdir build
cd build
cmake -D__LIB=lib -DDWARF_INCLUDE_DIR=/usr/include ..
make install
echo "/usr/local/lib" >> /etc/ld.so.conf.d/pahole.conf
ldconfig
popd

# build btfhub
make

# generate BTFs
BTFHUB_NO_SUDO=true ./btfhub -workers 6 -d rhel -r 8 -a "${ARCH}"
