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

	vmlinuxName := strings.TrimSuffix(filepath.Base(file), ".tar.xz")

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
		if hdr.Name != vmlinuxName {
			log.Printf("TRACE: %s", hdr.Name)
			return true, nil
		}
	}
	return false, nil
}
