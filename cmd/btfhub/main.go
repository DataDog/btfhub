package main

import (
	"archive/tar"
	"context"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	fastxz "github.com/therootcompany/xz"
	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/repo"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

var possibleArchs = []string{"x86_64", "arm64"}

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

var defaultDistros = []string{"ubuntu", "debian", "fedora", "centos", "ol"}

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

var distroArg, releaseArg, archArg, fileArg string
var numWorkers int
var force, kernelModules, ordered bool

func init() {
	flag.StringVar(&distroArg, "distro", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&distroArg, "d", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&releaseArg, "release", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&releaseArg, "r", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&archArg, "arch", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&archArg, "a", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&fileArg, "pkg-file", "", "file to use as list of packages rather than reading from repositories (requires distro, release, and arch)")
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
	if fa := flag.Args(); len(fa) > 0 {
		switch fa[0] {
		case "check":
			return check(ctx)
		default:
			log.Fatalf("unknown command %s", fa[0])
		}
	}
	return generate(ctx)
}

func check(ctx context.Context) error {
	distros, releases, archs, err := processArgs(maps.Keys(distroReleases), distroReleases)
	if err != nil {
		return err
	}

	archiveDir, err := archivePath()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}
	for _, distro := range distros {
		for _, release := range releases {
			for _, arch := range archs {
				btfdir := filepath.Join(archiveDir, distro, release, arch)
				if !utils.Exists(btfdir) {
					fmt.Printf("ignoring nonexistent directory %s\n", btfdir)
					continue
				}

				err = filepath.Walk(btfdir, func(path string, info fs.FileInfo, err error) error {
					if cerr := ctx.Err(); cerr != nil {
						return cerr
					}

					if info.IsDir() {
						return nil
					}
					if !strings.HasSuffix(path, ".btf.tar.xz") {
						return nil
					}

					unameName := strings.TrimSuffix(filepath.Base(path), ".tar.xz")
					hasKernelModules := false

					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()

					xr, err := fastxz.NewReader(f, 0)
					if err != nil {
						return err
					}
					tr := tar.NewReader(xr)
					for {
						hdr, err := tr.Next()
						if err == io.EOF {
							break // End of archive
						}
						if err != nil {
							return err
						}

						if hdr.ModTime.Unix() != 0 {
							fmt.Printf("%s: BTF file timestamp is not unix epoch. name=%s time=%s unix=%d\n", path, hdr.Name, hdr.ModTime, hdr.ModTime.Unix())
						}
						if hdr.Mode != 0444 {
							fmt.Printf("%s: BTF file mode is not 0444. name=%s mode=%o\n", path, hdr.Name, hdr.Mode)
						}
						if hdr.Uid != 0 {
							fmt.Printf("%s: BTF file owner is not UID 0. name=%s uid=%d\n", path, hdr.Name, hdr.Uid)
						}
						if hdr.Gid != 0 {
							fmt.Printf("%s: BTF file group is not GID 0. name=%s gid=%d\n", path, hdr.Name, hdr.Gid)
						}

						if hdr.Typeflag != tar.TypeReg {
							continue
						}
						if hdr.Name != unameName && hdr.Name != "vmlinux" {
							hasKernelModules = true
						}
					}

					if !hasKernelModules {
						fmt.Printf("%s: does not have kernel module BTF\n", path)
					}
					return nil
				})
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func processArgs(defDistros []string, defReleases map[string][]string) (distros, releases, archs []string, err error) {
	if distroArg != "" {
		distros = strings.Split(distroArg, " ")
		for i, d := range distros {
			if _, ok := distroReleases[d]; !ok {
				err = fmt.Errorf("invalid distribution %s", d)
				return
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
					err = fmt.Errorf("invalid release %s for %s", releases[i], d)
					return
				}
			} else {
				releases = defReleases[d]
			}
		}
	} else {
		distros = defDistros
		releaseArg = "" // no release if no distro is selected
	}

	// Architectures
	archs = possibleArchs
	if archArg != "" {
		archs = []string{archArg}
	}
	return
}

func archivePath() (string, error) {
	basedir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("pwd: %s", err)
	}
	archiveDir := path.Join(basedir, "archive")
	return archiveDir, nil
}

func generate(ctx context.Context) error {
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
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, jobChan)
		})
	}

	// Workers: job producers (per distro, per release)
	produce, prodCtx := errgroup.WithContext(ctx)
	for _, d := range distros {
		for _, r := range releases {
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
					}
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
