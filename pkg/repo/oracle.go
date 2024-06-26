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

type oracleRepo struct {
	archs      map[string]string
	repos      map[string]string
	minVersion kernel.Version
}

func NewOracleRepo() Repository {
	return &oracleRepo{
		archs: map[string]string{
			"arm64":  "aarch64",
			"x86_64": "x86_64",
		},
		repos: map[string]string{
			"7": "https://oss.oracle.com/ol7/debuginfo/",
			"8": "https://oss.oracle.com/ol8/debuginfo/",
		},
		minVersion: kernel.NewKernelVersion("3.10.0-957"),
	}
}

func (d *oracleRepo) GetKernelPackages(
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

	repoURL := d.repos[release]

	links, err := utils.GetLinks(ctx, repoURL)
	if err != nil {
		return fmt.Errorf("ERROR: list packages: %s", err)
	}

	kre := regexp.MustCompile(fmt.Sprintf(`kernel(?:-uek)?-debuginfo-([0-9].*\.%s)\.rpm`, altArch))

	for _, l := range links {
		match := kre.FindStringSubmatch(l)
		if match != nil {

			// Create a package object from the link and add it to pkgs list

			p := &pkg.CentOSPackage{
				Name:          strings.TrimSuffix(match[0], ".rpm"),
				NameOfFile:    match[1],
				Architecture:  altArch,
				URL:           l,
				KernelVersion: kernel.NewKernelVersion(match[1]),
				IgnoredFiles:  []string{"ctf"},
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
