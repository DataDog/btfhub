package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type openSUSERepo struct {
	archs       map[string]string
	repoAliases map[string]string
	repos       map[string]map[string][]string
}

var oldOpenSUSERepos = map[string][]string{
	"x86_64": {
		"https://download.opensuse.org/debug/distribution/leap/%s/repo/oss/",
		"https://download.opensuse.org/debug/update/leap/%s/oss/",
	},
	"aarch64": {
		"https://download.opensuse.org/ports/aarch64/debug/distribution/leap/%s/repo/oss/",
	},
}

var newOpenSUSERepos = map[string][]string{
	"x86_64": {
		"https://download.opensuse.org/debug/distribution/leap/%s/repo/oss/",
		"https://download.opensuse.org/debug/update/leap/%s/oss/",
		"https://download.opensuse.org/debug/update/leap/%s/sle/",
	},
	"aarch64": {
		"https://download.opensuse.org/debug/distribution/leap/%s/repo/oss/",
		"https://download.opensuse.org/debug/update/leap/%s/oss/",
		"https://download.opensuse.org/debug/update/leap/%s/sle/",
		"https://download.opensuse.org/ports/aarch64/debug/distribution/leap/%s/repo/oss/",
	},
}

var ignoredOpenSUSEFlavors = []string{"debug", "vanilla", "preempt", "rt", "rt_debug"}

func NewOpenSUSERepo() Repository {
	return &openSUSERepo{
		archs: map[string]string{
			"x86_64": "x86_64",
			"arm64":  "aarch64",
		},
		repoAliases: map[string]string{},
		repos: map[string]map[string][]string{
			"15.0": oldOpenSUSERepos,
			"15.1": oldOpenSUSERepos,
			"15.2": {
				"x86_64": {
					"https://download.opensuse.org/debug/distribution/leap/%s/repo/oss/",
					"https://download.opensuse.org/debug/update/leap/%s/oss/",
				},
				"aarch64": {
					"https://download.opensuse.org/ports/aarch64/debug/distribution/leap/%s/repo/oss/",
					"https://download.opensuse.org/debug/update/leap/%s/oss/",
				},
			},
			"15.3": newOpenSUSERepos,
		},
	}
}

func (d *openSUSERepo) GetKernelPackages(ctx context.Context, workDir string, release string, arch string, opts RepoOptions, jobChan chan<- job.Job) error {
	altArch := d.archs[arch]
	repoURLs := d.repos[release][altArch]

	var links []string
	for _, repoURLFormat := range repoURLs {
		repoURL := fmt.Sprintf(repoURLFormat, release)
		// get repo directory and find primary index URL
		repoDirectoryURL, _ := url.JoinPath(repoURL, "repodata/repomd.xml")
		repolinks, err := utils.GetRelativeLinks(ctx, repoDirectoryURL, repoURL)
		if err != nil {
			return fmt.Errorf("ERROR: list repodata files: %s", err)
		}
		var primaryURL string
		for _, l := range repolinks {
			if strings.HasSuffix(l, "-primary.xml.gz") {
				primaryURL = l
				break
			}
		}
		if primaryURL == "" {
			return fmt.Errorf("unable to find primary repodata in %s", repoDirectoryURL)
		}

		// get package links from primary index URL
		rlinks, err := utils.GetRelativeLinks(ctx, primaryURL, repoURL)
		if err != nil {
			return fmt.Errorf("ERROR: list packages: %s", err)
		}
		links = append(links, rlinks...)
	}

	kre := regexp.MustCompile(fmt.Sprintf(`/kernel-([^-]+)-debuginfo-([-1-9].*)\.%s\.rpm`, altArch))

	pkgsByKernelType := make(map[string][]pkg.Package)
	for _, l := range links {
		match := kre.FindStringSubmatch(l)
		if match == nil {
			continue
		}
		name := strings.TrimPrefix(strings.TrimSuffix(match[0], ".rpm"), "/")
		flavor, ver := match[1], match[2]
		if slices.Contains(ignoredOpenSUSEFlavors, flavor) {
			continue
		}

		// remove final .x because it is just a build counter and not included in `uname -r`
		parts := strings.Split(ver, ".")
		btfver := strings.Join(parts[:len(parts)-1], ".")

		p := &pkg.OpenSUSEPackage{
			Name:          name,
			NameOfFile:    fmt.Sprintf("%s-%s", ver, flavor),
			NameOfBTFFile: fmt.Sprintf("%s-%s", btfver, flavor),
			Architecture:  altArch,
			Flavor:        flavor,
			URL:           l,
			KernelVersion: kernel.NewKernelVersion(ver),
		}

		ks, ok := pkgsByKernelType[p.Flavor]
		if !ok {
			ks = make([]pkg.Package, 0, 1)
		}
		ks = append(ks, p)
		pkgsByKernelType[p.Flavor] = ks
	}

	for kt, ks := range pkgsByKernelType {
		sort.Sort(pkg.ByVersion(ks))
		log.Printf("DEBUG: %s %s flavor %d kernels\n", arch, kt, len(ks))
	}

	g, ctx := errgroup.WithContext(ctx)
	for kt, ks := range pkgsByKernelType {
		ckt := kt
		cks := ks
		g.Go(func() error {
			log.Printf("DEBUG: start kernel type %s %s (%d pkgs)\n", ckt, arch, len(cks))
			err := d.processPackages(ctx, workDir, cks, opts, jobChan)
			log.Printf("DEBUG: end kernel type %s %s\n", ckt, arch)
			return err
		})
	}
	return g.Wait()
}

func (d *openSUSERepo) processPackages(ctx context.Context, dir string, pkgs []pkg.Package, opts RepoOptions, jobchan chan<- job.Job) error {
	for i, p := range pkgs {
		log.Printf("DEBUG: start pkg %s (%d/%d)\n", p, i+1, len(pkgs))
		if err := processPackage(ctx, p, dir, opts, jobchan); err != nil {
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
