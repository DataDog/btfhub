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
	arch string,
	opts RepoOptions,
	jobChan chan<- job.Job,
) error {
	altArch := d.archs[arch]
	searchOut, err := repoquery(ctx, "kernel-debuginfo", altArch)
	if err != nil {
		return err
	}
	pkgs, err := parseRepoqueryPackages(searchOut, d.minVersion)
	if err != nil {
		return fmt.Errorf("parse package listing: %s", err)
	}
	sort.Sort(pkg.ByVersion(pkgs))

	for _, p := range pkgs {
		err := processPackage(ctx, p, workDir, opts, jobChan)
		if err != nil {
			if errors.Is(err, utils.ErrKernelHasBTF) {
				log.Printf("INFO: kernel %s has BTF already, skipping later kernels\n", p)
				return nil
			}
			return err
		}
	}

	return nil
}
