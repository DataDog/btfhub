package pkg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type RHELPackage struct {
	Name          string
	Architecture  string
	KernelVersion kernel.KernelVersion
	NameOfFile    string
}

func (pkg *RHELPackage) Filename() string {
	return pkg.NameOfFile
}

func (pkg *RHELPackage) Version() kernel.KernelVersion {
	return pkg.KernelVersion
}

func (pkg *RHELPackage) String() string {
	return pkg.Name
}

func (pkg *RHELPackage) ExtractKernel(ctx context.Context, pkgpath string, vmlinuxPath string) error {
	return utils.ExtractVmlinuxFromRPM(ctx, pkgpath, vmlinuxPath)
}

func (pkg *RHELPackage) Download(ctx context.Context, dir string) (string, error) {
	localFile := fmt.Sprintf("%s.rpm", pkg.Name)
	rpmpath := filepath.Join(dir, localFile)
	if utils.Exists(rpmpath) {
		return rpmpath, nil
	}

	if err := yumDownload(ctx, pkg.Name, dir); err != nil {
		os.Remove(rpmpath)
		return "", fmt.Errorf("rpm download: %s", err)
	}
	// we don't need the common RPM file
	commonrpmpath := strings.ReplaceAll(localFile, "kernel-debuginfo-", fmt.Sprintf("kernel-debuginfo-common-%s-", pkg.Architecture))
	os.Remove(commonrpmpath)

	return rpmpath, nil
}