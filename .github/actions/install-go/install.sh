#!/bin/bash
set -euxo pipefail

wget -nv "https://go.dev/dl/go${VERSION}.linux-${ARCH}.tar.gz"
tar -C /workspace -xzf "go${VERSION}.linux-${ARCH}.tar.gz"
