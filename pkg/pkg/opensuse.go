package pkg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/utils"
)

type OpenSUSEPackage struct {
	Name          string
	NameOfFile    string
	NameOfBTFFile string
	Architecture  string
	KernelVersion kernel.Version
	Flavor        string
	URL           string
}

func (pkg *OpenSUSEPackage) Filename() string {
	return pkg.NameOfFile
}

func (pkg *OpenSUSEPackage) BTFFilename() string {
	return pkg.NameOfBTFFile
}

func (pkg *OpenSUSEPackage) Version() kernel.Version {
	return pkg.KernelVersion
}

func (pkg *OpenSUSEPackage) String() string {
	return pkg.Name
}

func (pkg *OpenSUSEPackage) ExtractKernel(ctx context.Context, pkgpath string, extractDir string, kernelModules bool) (string, []string, error) {
	// vmlinux at: /usr/lib/debug/boot/vmlinux-<ver>-<type>.debug
	return utils.ExtractVmlinuxFromRPM(ctx, pkgpath, extractDir, kernelModules, nil)
}

func (pkg *OpenSUSEPackage) Download(ctx context.Context, dir string, force bool) (string, error) {
	localFile := fmt.Sprintf("%s.rpm", pkg.NameOfFile)
	rpmpath := filepath.Join(dir, localFile)
	if !force && utils.Exists(rpmpath) {
		return rpmpath, nil
	}

	if err := utils.DownloadFile(ctx, pkg.URL, rpmpath); err != nil {
		os.Remove(rpmpath)
		return "", fmt.Errorf("downloading rpm package: %w", err)
	}
	return rpmpath, nil
}
