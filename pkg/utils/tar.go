package utils

import (
	"archive/tar"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	fastxz "github.com/therootcompany/xz"
)

func TarballHasKernelModules(file string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f.Close()

	unameName := strings.TrimSuffix(filepath.Base(file), ".tar.xz")

	xr, err := fastxz.NewReader(f, 0)
	if err != nil {
		return false, err
	}
	tr := tar.NewReader(xr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return false, err
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Name != unameName && hdr.Name != "vmlinux" {
			log.Printf("TRACE: %s has kernel module BTF", file)
			return true, nil
		}
	}
	return false, nil
}
