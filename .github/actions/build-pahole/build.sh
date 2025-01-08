#!/bin/bash
set -euxo pipefail

cd ./3rdparty/dwarves
mkdir build
cd build
cmake -D__LIB=lib -DDWARF_INCLUDE_DIR=/usr/include ..
make -j "$(nproc)" install
echo "/usr/local/lib" >> /etc/ld.so.conf.d/pahole.conf
ldconfig
