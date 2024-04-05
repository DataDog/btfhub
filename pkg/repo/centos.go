package repo

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/pkg"
	"github.com/DataDog/btfhub/pkg/utils"
)

type CentosRepo struct {
	archs      map[string]string
	repos      map[string]string
	minVersion kernel.Version
}

func NewCentOSRepo() Repository {
	return &CentosRepo{
		archs: map[string]string{
			"x86_64": "x86_64",
			"arm64":  "aarch64",
		},
		repos: map[string]string{
			"7": "http://linuxsoft.cern.ch/centos-debuginfo/7/%s/",
			"8": "http://mirror.facebook.net/centos-debuginfo/8/%s/Packages/",
		},
		minVersion: kernel.NewKernelVersion("3.10.0-957"),
	}
}

func (d *CentosRepo) GetKernelPackages(
	ctx context.Context,
	workDir string,
	release string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
) error {
	var pkgs []pkg.Package

	altArch := d.archs[arch]

	// Pick all the links that match the kernel-debuginfo pattern

	repoURL := fmt.Sprintf(d.repos[release], altArch)

	links, err := utils.GetLinks(ctx, repoURL)
	if err != nil {
		return fmt.Errorf("ERROR: list packages: %s", err)
	}

	kre := regexp.MustCompile(fmt.Sprintf(`kernel-debuginfo-([-1-9].*\.%s)\.rpm`, altArch))

	for _, l := range links {
		match := kre.FindStringSubmatch(l)
		if match != nil {
			name := strings.TrimSuffix(match[0], ".rpm")

			// Create a package object from the link and add it to pkgs list

			p := &pkg.CentOSPackage{
				Name:          name,
				NameOfFile:    match[1],
				Architecture:  altArch,
				URL:           l,
				KernelVersion: kernel.NewKernelVersion(match[1]),
			}

			if p.Version().Less(d.minVersion) {
				continue
			}

			pkgs = append(pkgs, p)
		}
	}

	sort.Sort(pkg.ByVersion(pkgs)) // so kernels can be skipped if previous has BTF already

	return processPackages(ctx, workDir, pkgs, opts, chans)
}
