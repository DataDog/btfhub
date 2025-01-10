#!/bin/bash
set -euxo pipefail

wget -nv "https://ftpmirror.gnu.org/tar/tar-${VERSION}.tar.xz"
tar xf "tar-${VERSION}.tar.xz"
pushd "tar-${VERSION}"
FORCE_UNSAFE_CONFIGURE=1 ./configure --prefix="${PREFIX}"
make -j "$(nproc)" install
