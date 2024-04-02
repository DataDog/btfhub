package repo

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type DebianRepo struct {
	archs            map[string]string
	repos            map[string][]string
	releaseNumbers   map[string]string
	snapshotVersions map[string][]string
}

var archiveRepos = []string{
	// prefer snapshot over apt
	//"http://archive.debian.org/debian/dists/%s/main/binary-%s/Packages.gz",
	//"http://archive.debian.org/debian-security/dists/%s/updates/main/binary-%s/Packages.gz",
}

var oldRepos = []string{
	// prefer snapshot over apt
	//"http://ftp.debian.org/debian/dists/%s/main/binary-%s/Packages.gz",
	//"http://ftp.debian.org/debian/dists/%s-updates/main/binary-%s/Packages.gz",
	//"http://security.debian.org/debian-security/dists/%s/updates/main/binary-%s/Packages.gz",
}

func NewDebianRepo() Repository {
	return &DebianRepo{
		archs: map[string]string{
			"x86_64": "amd64",
			"arm64":  "arm64",
		},
		repos: map[string][]string{
			"stretch": archiveRepos,
			"buster":  oldRepos,
		},
		releaseNumbers: map[string]string{
			"stretch": "9",
			"buster":  "10",
		},
		snapshotVersions: map[string][]string{
			"stretch": {`4\.9\.0`, `4\.19\.0-0\.bpo.\d+`},
			"buster":  {`4\.19\.0-\d+`},
		},
	}
}

// GetKernelPackages downloads Packages.xz from the main, updates and security,
// from the official repos and parses the list of kernel packages to download.
// It then filters out kernel packages that we already have or failed to
// download. It then process the list of kernel packages: they will be
// downloaded and then the btf files will be extracted from them.
func (d *DebianRepo) GetKernelPackages(
	ctx context.Context,
	workDir string,
	release string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
) error {
	altArch := d.archs[arch]

	var pkgs []pkg.Package

	for _, r := range d.repos[release] {
		rawPkgs := &bytes.Buffer{}

		// Get Packages.xz from main, updates and security

		repo := fmt.Sprintf(r, release, altArch) // ..debian/dists/%s/%s/main.../Packages.gz

		if err := utils.Download(ctx, repo, rawPkgs); err != nil {
			return fmt.Errorf("download package list %s: %s", repo, err)
		}

		// Get the list of kernel packages to download from those repos
		repoURL, err := url.Parse(repo)
		if err != nil {
			return fmt.Errorf("repo url parse: %s", err)
		}

		// Get the list of kernel packages to download from debug repo
		repoURL.Path = strings.Split(repoURL.Path, "/dists")[0]
		kernelDbgPkgs, err := pkg.ParseAPTPackages(rawPkgs, repoURL.String(), release)
		if err != nil {
			return fmt.Errorf("parsing package list: %s", err)
		}

		// Filter out packages that aren't debug kernel packages

		re := regexp.MustCompile(`linux-image-[0-9]+\.[0-9]+\.[0-9].*-dbg`)

		for _, p := range kernelDbgPkgs {
			match := re.FindStringSubmatch(p.Name)
			if match == nil {
				continue
			}
			pkgs = append(pkgs, p)
		}
	}

	if len(d.snapshotVersions[release]) > 0 {
		allLinks, err := utils.GetLinks(ctx, "https://snapshot-lw07.debian.org/binary/?cat=l")
		if err != nil {
			return fmt.Errorf("parsing snapshot links: %s", err)
		}
		allowedFlavors := []string{"", "cloud", "rt"}
		for _, sn := range d.snapshotVersions[release] {
			re := regexp.MustCompile(fmt.Sprintf(`linux-image-(%s)(-[^-]+)?-%s-dbg`, sn, altArch))
			for _, l := range allLinks {
				parts := strings.Split(l, "/")
				name := parts[len(parts)-2]
				match := re.FindStringSubmatch(name)
				if match == nil {
					continue
				}
				flavor := ""
				if len(match) == 3 {
					flavor = strings.TrimPrefix(match[2], "-")
				}
				if !slices.Contains(allowedFlavors, flavor) {
					continue
				}

				p := &pkg.UbuntuPackage{
					Name:          name,
					NameOfFile:    strings.TrimPrefix(strings.TrimSuffix(name, "-dbg"), "linux-image-"),
					Architecture:  altArch,
					KernelVersion: kernel.NewKernelVersion(match[1]),
					Flavor:        flavor,
				}

				var binpkg snapshotBinaryPackage
				if err := queryJsonAPI(ctx, fmt.Sprintf("https://snapshot-lw07.debian.org/mr/binary/%s/", name), &binpkg, nil); err != nil {
					return fmt.Errorf("snapshot package API error for %s: %s", name, err)
				}
				if len(binpkg.Result) == 0 {
					continue
				}

				var verInfo snapshotBinaryVersionInfo
				if err := queryJsonAPI(ctx, fmt.Sprintf("https://snapshot-lw07.debian.org/mr/binary/%s/%s/binfiles?fileinfo=1", name, binpkg.Result[0].BinaryVersion), &verInfo, nil); err != nil {
					return fmt.Errorf("snapshot version API error for %s: %s", name, err)
				}
				for _, info := range verInfo.FileInfo {
					if len(info) == 0 {
						continue
					}
					pi := info[0]
					p.URL = fmt.Sprintf("https://snapshot-lw07.debian.org/archive/%s/%s%s/%s", pi.ArchiveName, pi.FirstSeen, pi.Path, pi.Name)
					p.Size = uint64(pi.Size)
					break
				}

				if p.Size > 0 {
					pkgs = append(pkgs, p)
				} else {
					fmt.Printf("WARN: unable to find detailed snapshot info for %s\n", p.Name)
				}

				// TODO deal with duplicates from APT repos?
			}
		}
	}

	sort.Sort(pkg.ByVersion(pkgs)) // so kernels can be skipped if previous has BTF already

	for i, p := range pkgs {
		log.Printf("DEBUG: start pkg %s (%d/%d)\n", p, i+1, len(pkgs))

		// Jobs about to be created:
		//
		// 1. Download package and extract vmlinux file
		// 2. Extract BTF info from vmlinux file

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

type snapshotBinaryPackageVersion struct {
	BinaryVersion string `json:"binary_version"`
	Name          string `json:"name"`
	Version       string `json:"version"`
}

type snapshotBinaryPackage struct {
	Binary string                         `json:"binary"`
	Result []snapshotBinaryPackageVersion `json:"result"`
}

type snapshotBinaryPackageFileInfo struct {
	ArchiveName string  `json:"archive_name"`
	FirstSeen   string  `json:"first_seen"`
	Name        string  `json:"name"`
	Path        string  `json:"path"`
	Size        float64 `json:"size"`
}

type snapshotBinaryVersionInfo struct {
	FileInfo map[string][]snapshotBinaryPackageFileInfo `json:"fileinfo"`
}

var retryError = errors.New("retry")

func retryQueryJsonAPI[T any](ctx context.Context, url string, out *T, headers map[string]string, attempts int) error {
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		err = queryJsonAPI(ctx, url, out, headers)
		if err == nil {
			return nil
		}
		if !errors.Is(err, retryError) {
			return err
		}
	}
	return err
}

func queryJsonAPI[T any](ctx context.Context, url string, out *T, headers map[string]string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		if resp.StatusCode/100 == 5 {
			return fmt.Errorf("%w: %s returned status code: %d", retryError, url, resp.StatusCode)
		}
		return fmt.Errorf("%s returned status code: %d", url, resp.StatusCode)
	}

	var rdr io.Reader

	transferEncoding := resp.Header.Get("Transfer-Encoding")
	switch {
	case transferEncoding == "gzip":
		rdr, err = gzip.NewReader(resp.Body)
		if err != nil {
			return fmt.Errorf("gzip body read: %s", err)
		}
	default:
		rdr = resp.Body
	}

	err = json.NewDecoder(rdr).Decode(out)
	if err != nil {
		return fmt.Errorf("JSON decode error: %s", err)
	}
	return nil
}
