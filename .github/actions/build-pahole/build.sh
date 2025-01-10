#!/bin/bash
set -exo pipefail

cd ./3rdparty/dwarves
mkdir build
cd build
cmake -D__LIB=lib -DDWARF_INCLUDE_DIR=/usr/include ..
${SUDO} make -j "$(nproc)" install
echo "/usr/local/lib" | ${SUDO} tee /etc/ld.so.conf.d/pahole.conf
${SUDO} ldconfig
