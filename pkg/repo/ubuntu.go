package repo

import (
	"context"
	"fmt"
	"iter"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/pkg"
)

type UbuntuRepo struct {
	repo         map[string]string // map[altArch]url
	debugRepo    string            // url
	kernelTypes  map[string]string // map[signed,unsigned]regex
	archs        map[string]string // map[arch]altArch
	releaseNames map[string]string // map[number]name
}

func NewUbuntuRepo() Repository {
	return &UbuntuRepo{
		repo: map[string]string{
			"amd64": "http://archive.ubuntu.com/ubuntu",
			"arm64": "http://ports.ubuntu.com",
		},
		debugRepo: "http://ddebs.ubuntu.com",
		kernelTypes: map[string]string{
			"signed":   "linux-image-[0-9.]+-.*-(generic|azure|gke|gkeop|gcp|aws|aws-fips)",
			"unsigned": "linux-image-unsigned-[0-9.]+-.*-(generic|azure|gke|gkeop|gcp|aws|aws-fips)",
		},
		archs: map[string]string{
			"x86_64": "amd64",
			"arm64":  "arm64",
		},
		releaseNames: map[string]string{
			"16.04": "xenial",
			"18.04": "bionic",
			"20.04": "focal",
		},
	}
}

func (uRepo *UbuntuRepo) ProcessDebugPackage(
	ctx context.Context,
	workDir string,
	release string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
	kernelFile string,
) error {
	altArch := uRepo.archs[arch]
	releaseName := uRepo.releaseNames[release]

	stat, err := os.Stat(kernelFile)
	if err != nil {
		return fmt.Errorf("stat %s: %w", kernelFile, err)
	}
	rootFile := strings.TrimSuffix(filepath.Base(kernelFile), filepath.Ext(kernelFile))
	rootFile, _, _ = strings.Cut(rootFile, "_")
	fn := strings.TrimPrefix(rootFile, "linux-image-")
	fn, _, _ = strings.Cut(fn, "-dbgsym")
	fn, _, _ = strings.Cut(fn, "-dbg")
	fn = strings.TrimPrefix(fn, "unsigned-")

	apath, err := filepath.Abs(kernelFile)
	if err != nil {
		return fmt.Errorf("file abs: %s", err)
	}
	up := &pkg.UbuntuPackage{
		Name:          rootFile,
		Architecture:  altArch,
		KernelVersion: kernel.NewKernelVersion(fn),
		NameOfFile:    fn,
		URL:           "file://" + apath,
		Size:          uint64(stat.Size()),
		Release:       release,
		ReleaseName:   releaseName,
	}
	log.Printf("%#v", up)

	all := slices.Values([]*pkg.UbuntuPackage{up})
	return uRepo.processPackages(ctx, workDir, arch, opts, chans, all)
}

// GetKernelPackages downloads Packages.xz from the main, updates and universe,
// from the debug repo and parses the list of kernel packages to download. It
// then filters out kernel packages that we already have or failed to download.
// It then processes the list of kernel packages: they will be downloaded and then
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
	releaseName := uRepo.releaseNames[release]

	// Get Packages.xz from debug repo
	dbgRawPkgs, err := pkg.GetPackageList(ctx, uRepo.debugRepo, releaseName, altArch)
	if err != nil {
		return fmt.Errorf("ddebs: %s", err)
	}
	// Get the list of kernel packages to download from debug repo
	kernelDbgPkgs, err := pkg.ParseAPTPackages(dbgRawPkgs, uRepo.debugRepo, release, releaseName)
	if err != nil {
		return fmt.Errorf("parsing debug package list: %s", err)
	}

	var lpDbgPkgs []*pkg.UbuntuPackage
	if opts.Launchpad {
		lpDbgPkgs, err = getLaunchpadPackages(ctx, release, releaseName, altArch)
		if err != nil {
			return fmt.Errorf("launchpad search: %s", err)
		}
	}

	return uRepo.processPackages(ctx, workDir, arch, opts, chans, concatIter(kernelDbgPkgs, lpDbgPkgs))
}

func (uRepo *UbuntuRepo) processPackages(
	ctx context.Context,
	workDir string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
	pkgs iter.Seq[*pkg.UbuntuPackage],
) error {
	filteredKernelDbgPkgMap := uRepo.filterPackages(pkgs)

	if opts.Query != nil {
		for k, p := range filteredKernelDbgPkgMap {
			if !opts.Query.MatchString(p.Filename()) {
				delete(filteredKernelDbgPkgMap, k)
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

func (uRepo *UbuntuRepo) filterPackages(pkgs iter.Seq[*pkg.UbuntuPackage]) map[string]*pkg.UbuntuPackage {
	filteredKernelDbgPkgMap := make(map[string]*pkg.UbuntuPackage)
	for _, ktype := range []string{"unsigned", "signed"} {
		re := regexp.MustCompile(fmt.Sprintf("%s-dbgsym", uRepo.kernelTypes[ktype]))
		for p := range pkgs {
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
	return filteredKernelDbgPkgMap
}

func concatIter[S ~[]E, E any](slices ...S) iter.Seq[E] {
	return func(yield func(E) bool) {
		for _, slice := range slices {
			for _, s := range slice {
				if !yield(s) {
					return
				}
			}
		}
	}
}
