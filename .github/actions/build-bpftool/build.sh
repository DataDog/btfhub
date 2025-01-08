#!/bin/bash
set -euxo pipefail

cd ./3rdparty/bpftool
make -j "$(nproc)" -C src/ V=1 install
