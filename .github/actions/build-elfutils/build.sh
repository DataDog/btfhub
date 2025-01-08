#!/bin/bash
set -euxo pipefail

wget -nv "https://sourceware.org/elfutils/ftp/${VERSION}/elfutils-${VERSION}.tar.bz2"
tar xf "elfutils-${VERSION}.tar.bz2"
cd "elfutils-${VERSION}"
./configure --disable-libdebuginfod --disable-debuginfod --disable-demangler
make -j "$(nproc)" install
ldconfig
