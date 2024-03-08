package repo

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/aquasecurity/btfhub/pkg/kernel"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type lpPublishedBinaries struct {
	Entries            []lpPublishedBinary `json:"entries"`
	TotalSizeLink      string              `json:"total_size_link"`
	NextCollectionLink string              `json:"next_collection_link"`
}

//	{
//		"self_link": "https://api.launchpad.net/devel/ubuntu/+archive/primary/+binarypub/100061265",
//		"resource_type_link": "https://api.launchpad.net/devel/#binary_package_publishing_history",
//		"display_name": "linux-image-4.4.0-98-generic-dbgsym 4.4.0-98.121 in xenial amd64",
//		"component_name": "main",
//		"section_name": "kernel",
//		"source_package_name": "linux",
//		"source_package_version": "4.4.0-98.121",
//		"distro_arch_series_link": "https://api.launchpad.net/devel/ubuntu/xenial/amd64",
//		"phased_update_percentage": null,
//		"date_published": "2017-10-30T19:53:48.149191+00:00",
//		"scheduled_deletion_date": "2023-12-19T20:15:22.365771+00:00",
//		"status": "Deleted",
//		"pocket": "Security",
//		"creator_link": null,
//		"date_created": "2017-10-30T19:43:10.104442+00:00",
//		"date_superseded": "2023-12-19T21:59:37.225614+00:00",
//		"date_made_pending": "2023-12-19T20:15:22.365771+00:00",
//		"date_removed": "2024-01-10T12:10:17.179074+00:00",
//		"archive_link": "https://api.launchpad.net/devel/ubuntu/+archive/primary",
//		"copied_from_archive_link": null,
//		"removed_by_link": "https://api.launchpad.net/devel/~vorlon",
//		"removal_comment": "NBS",
//		"binary_package_name": "linux-image-4.4.0-98-generic-dbgsym",
//		"binary_package_version": "4.4.0-98.121",
//		"build_link": "https://api.launchpad.net/devel/~canonical-kernel-team/+archive/ubuntu/ppa/+build/13563657",
//		"architecture_specific": true,
//		"priority_name": "OPTIONAL",
//		"is_debug": true,
//		"http_etag": "\"d7d2acd64ff60f66894a6aa0d176b3b6fdd9a85e-cbacc9c0c353f19af70226f360bd294c2201f79b\""
//	}
type lpPublishedBinary struct {
	Status               string    `json:"status"`
	Pocket               string    `json:"pocket"`
	DateCreated          time.Time `json:"date_created"`
	DateSuperseded       time.Time `json:"date_superseded"`
	DateRemoved          time.Time `json:"date_removed"`
	DatePublished        time.Time `json:"date_published"`
	BinaryPackageName    string    `json:"binary_package_name"`
	BinaryPackageVersion string    `json:"binary_package_version"`
	BuildLink            string    `json:"build_link"`
}

func getLaunchpadPackages(ctx context.Context, release string, arch string) ([]*pkg.UbuntuPackage, error) {
	name := "linux-image-"
	distroArchSeries := fmt.Sprintf("https://api.launchpad.net/devel/ubuntu/%s/%s", release, arch)
	url := fmt.Sprintf("https://api.launchpad.net/devel/ubuntu/+archive/primary?ws.op=getPublishedBinaries&binary_name=%s&distro_arch_series=%s&ws.size=300&status=Published", name, distroArchSeries)

	pkgMap := make(map[string]lpPublishedBinary)
	for i := 0; ; i++ {
		fmt.Printf("TRACE: get %s\n", url)
		var binaries lpPublishedBinaries
		if err := queryJsonAPI(ctx, url, &binaries, map[string]string{"TE": "gzip"}); err != nil {
			return nil, err
		}
		if i == 0 && binaries.TotalSizeLink != "" {
			rawTotal := &bytes.Buffer{}
			if err := utils.Download(ctx, binaries.TotalSizeLink, rawTotal); err == nil {
				fmt.Printf("DEBUG: launchpad total package count %s\n", rawTotal.String())
			}
		}

		for _, p := range binaries.Entries {
			if !strings.HasSuffix(p.BinaryPackageName, "-dbgsym") {
				continue
			}
			if p.Pocket == "Proposed" {
				continue
			}
			if p.Status == "Deleted" && p.DateSuperseded.IsZero() {
				continue
			}
			if p.Status != "Published" {
				continue
			}
			fmt.Printf("DEBUG: %+v\n", p)
			url := fmt.Sprintf("%s/+files/%s_%s_%s.ddeb", strings.ReplaceAll(p.BuildLink, "api.launchpad.net/devel", "launchpad.net"), p.BinaryPackageName, p.BinaryPackageVersion, arch)
			if _, ok := pkgMap[url]; !ok {
				pkgMap[url] = p
			}
		}
		if binaries.NextCollectionLink != "" {
			url = binaries.NextCollectionLink
			continue
		}
		break
	}

	var pkgs []*pkg.UbuntuPackage
	for url, p := range pkgMap {
		up := &pkg.UbuntuPackage{
			Name:          p.BinaryPackageName,
			Architecture:  arch,
			KernelVersion: kernel.NewKernelVersion(p.BinaryPackageVersion),
			NameOfFile:    strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(p.BinaryPackageName, "linux-image-"), "unsigned-"), "-dbgsym"),
			URL:           url,
			Size:          math.MaxUint64, // no idea on real size
			Release:       release,
			Flavor:        "",
		}
		pkgs = append(pkgs, up)
	}

	slices.SortFunc(pkgs, func(a, b *pkg.UbuntuPackage) int {
		if a.KernelVersion.Less(b.KernelVersion) {
			return -1
		} else if b.KernelVersion.Less(a.KernelVersion) {
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})
	return pkgs, nil
}
