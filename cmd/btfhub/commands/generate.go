package commands

import (
	"context"
	"fmt"
	"log"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/btfhub/pkg/catalog"
	"github.com/DataDog/btfhub/pkg/job"
	"github.com/DataDog/btfhub/pkg/repo"
)

var possibleArchs = []string{"x86_64", "arm64"}

var distroReleases = map[string][]string{
	"ubuntu":        {"16.04", "18.04", "20.04", "22.04", "23.10", "24.04", "24.10"},
	"debian":        {"9", "10"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"2018", "2", "2023"},
	"sles":          {"12.3", "12.4", "12.5", "15.0", "15.1", "15.2", "15.3"},
	"opensuse-leap": {"15.0", "15.1", "15.2", "15.3"},
}

var defaultDistros = []string{"ubuntu", "debian", "fedora", "centos", "ol"}

var defaultReleases = map[string][]string{
	"ubuntu": {"16.04", "18.04", "20.04", "22.04", "23.10", "24.04", "24.10"},
	// no 9/stretch for debian
	"debian":        {"10", "11", "12"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"2018", "2", "2023"},
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
	seccompChan := make(chan job.Job)
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, btfChan, seccompChan, jobChan)
		})
	}

	var qre *regexp.Regexp
	if queryArg != "" {
		qre = regexp.MustCompile(queryArg)
	}

	var cat *catalog.BTFCatalog
	chans := &repo.JobChannels{BTF: btfChan, Seccomp: seccompChan, Default: jobChan}
	// Workers: job producers (per distro, per release)
	produce, prodCtx := errgroup.WithContext(ctx)

	fmt.Println(distros, releases, archs)
	for _, d := range distros {
		for _, r := range releases[d] {
			release := r
			for _, a := range archs {
				arch := a
				distro := d
				produce.Go(func() error {
					// workDir example: ./archive/ubuntu/20.04/x86_64
					workDir := filepath.Join(archiveDir, distro, release, arch)
					if err := os.MkdirAll(workDir, 0775); err != nil {
						return fmt.Errorf("arch dir: %s", err)
					}
					var repoHashDir string
					if hashDir != "" {
						// order is different to match catalog nesting
						repoHashDir, err = filepath.Abs(filepath.Join(hashDir, arch, distro, release))
						if err != nil {
							return fmt.Errorf("hash dir abs: %s", err)
						}
					}

					fmt.Printf("[DEBUG] processing %s %s %s\n", d, r, a)

					// pick the repository creator and get the kernel packages
					rep := repoCreators[distro]()
					opts := repo.RepoOptions{
						Force:         force,
						KernelModules: false,
						Ordered:       false,
						DryRun:        dryRun,
						Query:         qre,
						Launchpad:     launchpad,
						S3Bucket:      s3bucket,
						S3Prefix:      path.Join(s3prefix, distro, release, arch),
						HashDir:       repoHashDir,
						Catalog:       cat,
						Arch:          arch,
						Release:       release,
						Distro:        distro,
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
