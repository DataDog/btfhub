package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/repo"
)

var distroReleases = map[string][]string{
	"ubuntu":        {"xenial", "bionic", "focal"},
	"debian":        {"stretch", "buster", "bullseye"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"1", "2"},
	"sles":          {"12.3", "12.5", "15.1", "15.2", "15.3"},
	"opensuse-leap": {"15.0", "15.1", "15.2", "15.3"},
}

var defaultReleases = map[string][]string{
	"ubuntu": {"xenial", "bionic", "focal"},
	// no stretch for debian
	"debian":        {"buster", "bullseye"},
	"fedora":        {"24", "25", "26", "27", "28", "29", "30", "31"},
	"centos":        {"7", "8"},
	"ol":            {"7", "8"},
	"rhel":          {"7", "8"},
	"amzn":          {"1", "2"},
	"sles":          {"12.3", "12.5", "15.1", "15.2", "15.3"},
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

var distroArg, releaseArg, archArg string
var numWorkers int
var force, kernelModules, ordered bool

func init() {
	flag.StringVar(&distroArg, "distro", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&distroArg, "d", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&releaseArg, "release", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&releaseArg, "r", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&archArg, "arch", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&archArg, "a", "", "architecture to update (x86_64,arm64)")
	flag.IntVar(&numWorkers, "workers", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.IntVar(&numWorkers, "j", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.BoolVar(&force, "f", false, "force update regardless of existing files (defaults to false)")
	flag.BoolVar(&kernelModules, "kmod", true, "generate BTF for kernel modules, in addition to the base kernel (defaults to true)")
	flag.BoolVar(&ordered, "ordered", true, "process kernels in order so future kernels can be skipped once BTF is detected")
}

func main() {
	flag.Parse()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) error {
	var distros []string
	var releases []string
	if distroArg != "" {
		distros = strings.Split(distroArg, " ")
		for i, d := range distros {
			if _, ok := distroReleases[d]; !ok {
				return fmt.Errorf("invalid distribution %s", d)
			}
			if releaseArg != "" {
				releases = strings.Split(releaseArg, " ")
				found := false
				for _, r := range distroReleases[d] {
					found = r == releases[i]
					if found {
						break
					}
				}
				if !found {
					return fmt.Errorf("invalid release %s for %s", releases[i], d)
				}
			}
		}
	} else {
		distros = []string{"ubuntu", "debian", "fedora", "centos", "ol"}
		releaseArg = "" // no release if no distro is selected
	}

	// Architectures
	archs := []string{"x86_64", "arm64"}
	if archArg != "" {
		archs = []string{archArg}
	}

	// Environment
	basedir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}
	archiveDir := path.Join(basedir, "archive")

	if numWorkers == 0 {
		numWorkers = runtime.NumCPU() - 1
	}

	// Workers: job consumers (pool)
	jobChan := make(chan job.Job)
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, jobChan)
		})
	}

	// Workers: job producers (per distro, per release)
	produce, prodCtx := errgroup.WithContext(ctx)
	for i, d := range distros {
		distroReleases := defaultReleases[d]
		if len(releases) > 0 {
			distroReleases = []string{releases[i]}
		}

		for _, r := range distroReleases {
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
					opts := repo.RepoOptions{Force: force, KernelModules: kernelModules, Ordered: ordered}
					return rep.GetKernelPackages(prodCtx, workDir, release, arch, opts, jobChan)
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
