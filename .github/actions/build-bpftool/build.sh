#!/bin/bash
set -euxo pipefail

cd ./3rdparty/bpftool
sudo -E PATH="$PATH" make -j "$(nproc)" -C src/ V=1 install-bin
