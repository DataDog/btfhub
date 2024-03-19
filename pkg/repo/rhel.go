package repo

import (
	"context"
	"fmt"
	"sort"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
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
	chans *JobChannels,
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

	return processPackages(ctx, workDir, pkgs, opts, chans)
}
