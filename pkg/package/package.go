package pkg

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type Package interface {
	String() string
	Filename() string
	Version() kernel.KernelVersion
	Download(ctx context.Context, dir string) (string, error)
	ExtractKernel(ctx context.Context, pkgpath string, vmlinuxPath string) error
}

func PackageBTFExists(p Package, dir string) bool {
	fp := filepath.Join(dir, fmt.Sprintf("%s.btf.tar.xz", p.Filename()))
	return utils.Exists(fp)
}

func PackageFailed(p Package, dir string) bool {
	fp := filepath.Join(dir, fmt.Sprintf("%s.failed", p.Filename()))
	return utils.Exists(fp)
}

type ByVersion []Package

func (a ByVersion) Len() int      { return len(a) }
func (a ByVersion) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByVersion) Less(i, j int) bool {
	return a[i].Version().Less(a[j].Version())
}