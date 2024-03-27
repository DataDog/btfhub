package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/repo"
)

var possibleArchs = []string{"x86_64", "arm64"}

var distroReleases = map[string][]string{
	"ubuntu":        {"xenial", "bionic", "focal"},
	"debian":        {"stretch", "buster"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"1", "2"},
	"sles":          {"12.3", "12.4", "12.5", "15.0", "15.1", "15.2", "15.3"},
	"opensuse-leap": {"15.0", "15.1", "15.2", "15.3"},
}

var defaultDistros = []string{"ubuntu", "debian", "fedora", "centos", "ol"}

var defaultReleases = map[string][]string{
	"ubuntu": {"xenial", "bionic", "focal"},
	// no stretch for debian
	"debian":        {"buster"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"1", "2"},
	"sles":          {"12.3", "12.4", "12.5", "15.0", "15.1", "15.2", "15.3"},
	"opensuse-leap": {"15.0", "15.1", "15.2", "15.3"},
}

type repoFunc func() repo.Repository

var repoCreators = map[string]repoFunc{
	"ubuntu":        repo.NewUbuntuRepo,
	"debian":        repo.NewDebianRepo,
	"fedora":        repo.NewFedoraRepo,
	"centos":        repo.NewCentOSRepo,
	"ol":            repo.NewOracleRepo,
	"rhel":          repo.NewRHELRepo,
	"amzn":          repo.NewAmazonRepo,
	"sles":          repo.NewSUSERepo,
	"opensuse-leap": repo.NewOpenSUSERepo,
}

func Generate(ctx context.Context) error {
	distros, releases, archs, err := processArgs(defaultDistros, defaultReleases)
	if err != nil {
		return err
	}
	if fileArg != "" && (len(archs) != 1 || len(distros) != 1 || len(releases) != 1) {
		return fmt.Errorf("invalid use of pkg-file, requires specific distro+release+arch")
	}

	archiveDir, err := archivePath()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}

	if numWorkers == 0 {
		numWorkers = runtime.NumCPU() - 1
	}

	// Workers: job consumers (pool)
	jobChan := make(chan job.Job)
	btfChan := make(chan job.Job)
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, btfChan, jobChan)
		})
	}

	var qre *regexp.Regexp
	if queryArg != "" {
		qre = regexp.MustCompile(queryArg)
	}

	chans := &repo.JobChannels{BTF: btfChan, Default: jobChan}
	// Workers: job producers (per distro, per release)
	produce, prodCtx := errgroup.WithContext(ctx)
	for _, d := range distros {
		for _, r := range releases[d] {
			release := r
			for _, a := range archs {
				arch := a
				distro := d
				produce.Go(func() error {
					// workDir example: ./archive/ubuntu/focal/x86_64
					workDir := filepath.Join(archiveDir, distro, release, arch)
					if err := os.MkdirAll(workDir, 0775); err != nil {
						return fmt.Errorf("arch dir: %s", err)
					}

					// pick the repository creator and get the kernel packages
					rep := repoCreators[distro]()
					opts := repo.RepoOptions{
						Force:         force,
						KernelModules: kernelModules,
						Ordered:       ordered,
						PackageFile:   fileArg,
						DryRun:        dryRun,
						Query:         qre,
					}
					return rep.GetKernelPackages(prodCtx, workDir, release, arch, opts, chans)
				})
			}
		}
	}

	// Cleanup
	err = produce.Wait()
	close(jobChan)
	if err != nil {
		return err
	}
	return consume.Wait()
}
