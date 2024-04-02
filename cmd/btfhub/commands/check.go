package commands

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	fastxz "github.com/therootcompany/xz"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/btfhub/pkg/utils"
)

type checkResult struct {
	time, mode, owner, group       bool
	distro, release, arch, version string
}

func (r checkResult) Failed() bool {
	return r.time || r.mode || r.owner || r.group
}

func failedToEmoji(v bool) string {
	if v {
		return "❌"
	}
	return "✅"
}

func Check(ctx context.Context) error {
	distros, releases, archs, err := processArgs(maps.Keys(distroReleases), distroReleases)
	if err != nil {
		return err
	}

	archiveDir, err := archivePath()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}

	maxDistro := len("distro")
	for _, distro := range distros {
		maxDistro = max(maxDistro, len(distro))
	}
	maxRelease := len("release")
	for _, release := range releases {
		maxRelease = max(maxRelease, len(release))
	}
	maxArch := len("arch")
	for _, arch := range archs {
		maxArch = max(maxArch, len(arch))
	}
	fmt.Printf(fmt.Sprintf(" time | mode | owner | group | %%-%ds | %%-%ds | %%-%ds | version\n", maxDistro, maxRelease, maxArch), "distro", "release", "arch")

	var printResult = func(r checkResult) {
		// widths are minus one because emoji is two chars wide
		fmt.Printf(fmt.Sprintf(" %-3s | %-3s | %-4s | %-4s | %%-%ds | %%-%ds | %%-%ds | %%s\n", failedToEmoji(r.time), failedToEmoji(r.mode), failedToEmoji(r.owner), failedToEmoji(r.group), maxDistro, maxRelease, maxArch), r.distro, r.release, r.arch, r.version)
	}

	for _, distro := range distros {
		for _, release := range releases[distro] {
			for _, arch := range archs {
				btfdir := filepath.Join(archiveDir, distro, release, arch)
				if !utils.Exists(btfdir) {
					continue
				}

				err = filepath.Walk(btfdir, func(path string, info fs.FileInfo, err error) error {
					if cerr := ctx.Err(); cerr != nil {
						return cerr
					}
					if err != nil {
						_, _ = fmt.Fprintf(os.Stderr, "walk error: %s\n", err)
						return nil
					}

					if info.IsDir() {
						return nil
					}
					if !strings.HasSuffix(path, ".btf.tar.xz") {
						return nil
					}

					unameName := strings.TrimSuffix(filepath.Base(path), ".tar.xz")

					f, err := os.Open(path)
					if err != nil {
						return err
					}
					defer f.Close()

					xr, err := fastxz.NewReader(f, 0)
					if err != nil {
						return err
					}

					version := strings.TrimSuffix(unameName, ".btf")
					res := checkResult{distro: distro, release: release, arch: arch, version: version}

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
							res.time = true
							//fmt.Printf("%s: BTF file timestamp is not unix epoch. name=%s time=%s unix=%d\n", path, hdr.Name, hdr.ModTime, hdr.ModTime.Unix())
						}
						if hdr.Mode != 0444 {
							res.mode = true
							//fmt.Printf("%s: BTF file mode is not 0444. name=%s mode=%o\n", path, hdr.Name, hdr.Mode)
						}
						if hdr.Uid != 0 {
							res.owner = true
							//fmt.Printf("%s: BTF file owner is not UID 0. name=%s uid=%d\n", path, hdr.Name, hdr.Uid)
						}
						if hdr.Gid != 0 {
							res.group = true
							//fmt.Printf("%s: BTF file group is not GID 0. name=%s gid=%d\n", path, hdr.Name, hdr.Gid)
						}
					}

					if res.Failed() {
						printResult(res)
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
