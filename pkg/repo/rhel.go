package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sort"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type RHELRepo struct {
	archs      map[string]string
	minVersion kernel.Version
}

func NewRHELRepo() Repository {
	return &RHELRepo{
		archs: map[string]string{
			"x86_64": "x86_64",
			"arm64":  "aarch64",
		},
		minVersion: kernel.NewKernelVersion("3.10.0-957"),
	}
}

func (d *RHELRepo) GetKernelPackages(
	ctx context.Context,
	workDir string,
	_ string,
	_ string,
	force bool,
	jobChan chan<- job.Job,
) error {
	searchOut, err := yumSearch(ctx, "kernel-debuginfo")
	if err != nil {
		return err
	}
	pkgs, err := parseYumPackages(searchOut, d.minVersion)
	if err != nil {
		return fmt.Errorf("parse package listing: %s", err)
	}
	sort.Sort(pkg.ByVersion(pkgs))

	for _, pkg := range pkgs {
		err := processPackage(ctx, pkg, workDir, force, jobChan)
		if err != nil {
			if errors.Is(err, utils.ErrHasBTF) {
				log.Printf("INFO: kernel %s has BTF already, skipping later kernels\n", pkg)
				return nil
			}
			return err
		}
	}

	return nil
}
