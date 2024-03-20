package repo

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type UbuntuRepo struct {
	repo        map[string]string // map[altArch]url
	debugRepo   string            // url
	kernelTypes map[string]string // map[signed,unsigned]regex
	archs       map[string]string // map[arch]altArch
}

func NewUbuntuRepo() Repository {
	return &UbuntuRepo{
		repo: map[string]string{
			"amd64": "http://archive.ubuntu.com/ubuntu",
			"arm64": "http://ports.ubuntu.com",
		},
		debugRepo: "http://ddebs.ubuntu.com",
		kernelTypes: map[string]string{
			"signed":   "linux-image-[0-9.]+-.*-(generic|azure|gke|gkeop|gcp|aws)",
			"unsigned": "linux-image-unsigned-[0-9.]+-.*-(generic|azure|gke|gkeop|gcp|aws)",
		},
		archs: map[string]string{
			"x86_64": "amd64",
			"arm64":  "arm64",
		},
	}
}

// GetKernelPackages downloads Packages.xz from the main, updates and universe,
// from the debug repo and parses the list of kernel packages to download. It
// then filters out kernel packages that we already have or failed to download.
// It then process the list of kernel packages: they will be downloaded and then
// the btf files will be extracted from them.
func (uRepo *UbuntuRepo) GetKernelPackages(
	ctx context.Context,
	workDir string,
	release string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
) error {
	altArch := uRepo.archs[arch]

	var kernelPkgs []*pkg.UbuntuPackage
	filteredKernelDbgPkgMap := make(map[string]*pkg.UbuntuPackage) // map[filename]package

	if opts.PackageFile != "" {
		lines, err := readPackageFile(opts.PackageFile)
		if err != nil {
			return err
		}
		for _, l := range lines {
			kernelPkgs = append(kernelPkgs, &pkg.UbuntuPackage{
				Name:          fmt.Sprintf("linux-image-%s", l),
				NameOfFile:    l,
				Release:       release,
				Architecture:  altArch,
				KernelVersion: kernel.NewKernelVersion(l),
			})
		}
	} else {
		// Get Packages.xz from debug repo
		dbgRawPkgs, err := pkg.GetPackageList(ctx, uRepo.debugRepo, release, altArch)
		if err != nil {
			return fmt.Errorf("ddebs: %s", err)
		}
		// Get the list of kernel packages to download from debug repo
		kernelDbgPkgs, err := pkg.ParseAPTPackages(dbgRawPkgs, uRepo.debugRepo, release)
		if err != nil {
			return fmt.Errorf("parsing debug package list: %s", err)
		}

		lpDbgPkgs, err := getLaunchpadPackages(ctx, release, altArch)
		if err != nil {
			return fmt.Errorf("launchpad search: %s", err)
		}

		for _, ktype := range []string{"unsigned", "signed"} {
			re := regexp.MustCompile(fmt.Sprintf("%s-dbgsym", uRepo.kernelTypes[ktype]))
			for _, pkgs := range [][]*pkg.UbuntuPackage{kernelDbgPkgs, lpDbgPkgs} {
				for _, p := range pkgs {
					match := re.FindStringSubmatch(p.Name)
					if match == nil {
						continue
					}
					if p.Size < 10_000_000 { // ignore smaller than 10MB (signed vs unsigned emptiness)
						continue
					}
					// match = [filename = linux-image-{unsigned}-XXX-dbgsym, flavor = generic, gke, aws, ...]
					p.Flavor = match[1]
					if dp, ok := filteredKernelDbgPkgMap[p.Filename()]; !ok {
						filteredKernelDbgPkgMap[p.Filename()] = p
					} else {
						log.Printf("DEBUG: duplicate %s filename from %s (other %s)", p.Filename(), p, dp)
					}
				}
			}
		}
	}

	log.Printf("DEBUG: %d %s packages\n", len(filteredKernelDbgPkgMap), arch)

	// type: signed/unsigned
	// flavor: generic, gcp, aws, ...

	pkgsByKernelFlavor := make(map[string][]pkg.Package)

	for _, p := range filteredKernelDbgPkgMap { // map[filename]package
		pkgSlice, ok := pkgsByKernelFlavor[p.Flavor]
		if !ok {
			pkgSlice = make([]pkg.Package, 0, 1)
		}
		pkgSlice = append(pkgSlice, p)
		pkgsByKernelFlavor[p.Flavor] = pkgSlice
	}

	log.Printf("DEBUG: %d %s flavors\n", len(pkgsByKernelFlavor), arch)

	for flavor, pkgSlice := range pkgsByKernelFlavor {
		sort.Sort(pkg.ByVersion(pkgSlice)) // so kernels can be skipped if previous has BTF already
		log.Printf("DEBUG: %s %s flavor %d kernels\n", arch, flavor, len(pkgSlice))
	}

	g, ctx := errgroup.WithContext(ctx)

	for flavor, pkgSlice := range pkgsByKernelFlavor {
		theFlavor := flavor
		thePkgSlice := pkgSlice

		// Start a goroutine for each flavor to process all of its packages

		g.Go(func() error {
			log.Printf("DEBUG: start kernel flavor %s %s (%d pkgs)\n", theFlavor, arch, len(thePkgSlice))
			err := processPackages(ctx, workDir, thePkgSlice, opts, chans)
			log.Printf("DEBUG: end kernel flavor %s %s\n", theFlavor, arch)
			return err
		})
	}

	return g.Wait()
}

// processPackages processes a list of packages, sending jobs to the job channel.
func processPackages(
	ctx context.Context,
	workDir string,
	pkgs []pkg.Package,
	opts RepoOptions,
	chans *JobChannels,
) error {
	if !opts.Ordered {
		g, ctx := errgroup.WithContext(ctx)
		for i, p := range pkgs {
			pos := i + 1
			gp := p
			g.Go(func() error {
				log.Printf("DEBUG: start pkg %s (%d/%d)\n", p, pos, len(pkgs))
				err := processPackage(ctx, gp, workDir, opts, chans)
				if err != nil {
					if errors.Is(err, utils.ErrKernelHasBTF) {
						log.Printf("INFO: kernel %s has BTF already\n", p)
						return nil
					}
					if errors.Is(err, context.Canceled) {
						return nil
					}
					log.Printf("ERROR: %s: %s\n", gp, err)
				}
				log.Printf("DEBUG: end pkg %s (%d/%d)\n", p, pos, len(pkgs))
				return nil
			})
		}
		return g.Wait()
	}

	for i, p := range pkgs {
		log.Printf("DEBUG: start pkg %s (%d/%d)\n", p, i+1, len(pkgs))
		err := processPackage(ctx, p, workDir, opts, chans)
		if err != nil {
			if errors.Is(err, utils.ErrKernelHasBTF) {
				log.Printf("INFO: kernel %s has BTF already, skipping later kernels\n", p)
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			log.Printf("ERROR: %s: %s\n", p, err)
			continue
		}
		log.Printf("DEBUG: end pkg %s (%d/%d)\n", p, i+1, len(pkgs))
	}
	return nil
}

func readPackageFile(pkgFile string) ([]string, error) {
	f, err := os.Open(pkgFile)
	if err != nil {
		return nil, fmt.Errorf("open pkg file: %s", err)
	}
	defer f.Close()

	var lines []string
	scan := bufio.NewScanner(f)
	for scan.Scan() {
		lines = append(lines, scan.Text())
	}
	if scan.Err() != nil {
		return nil, fmt.Errorf("read pkg file: %s", scan.Err())
	}
	return lines, nil
}
