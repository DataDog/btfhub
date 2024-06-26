package pkg

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/utils"
)

type CentOSPackage struct {
	Name          string
	Architecture  string
	KernelVersion kernel.Version
	NameOfFile    string
	URL           string
	IgnoredFiles  []string
}

func (pkg *CentOSPackage) Filename() string {
	return pkg.NameOfFile
}

func (pkg *CentOSPackage) BTFFilename() string {
	return pkg.NameOfFile
}

func (pkg *CentOSPackage) Version() kernel.Version {
	return pkg.KernelVersion
}

func (pkg *CentOSPackage) String() string {
	return pkg.Name
}

func (pkg *CentOSPackage) Download(ctx context.Context, dir string, force bool) (string, error) {
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

func (pkg *CentOSPackage) ExtractKernel(ctx context.Context, pkgpath string, extractDir string, kernelModules bool) (string, []string, error) {
	return utils.ExtractVmlinuxFromRPM(ctx, pkgpath, extractDir, kernelModules, pkg.IgnoredFiles)
}
