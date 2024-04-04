package utils

import (
	"errors"
	"os"
)

var ErrKernelHasBTF = errors.New("vmlinux has .BTF section")

func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
