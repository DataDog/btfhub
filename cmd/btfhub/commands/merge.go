package commands

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/mholt/archiver/v3"
	"golang.org/x/exp/maps"

	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

func Merge(ctx context.Context) error {
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
					hasKmod, err := utils.TarballHasKernelModules(path)
					if err != nil {
						return err
					}
					if !hasKmod {
						return nil
					}

					extractDir, err := os.MkdirTemp("", "btfhub-extract-*")
					if err != nil {
						return err
					}
					defer os.RemoveAll(extractDir)

					mergeDir, err := os.MkdirTemp("", "btfhub-merge-*")
					if err != nil {
						return err
					}
					defer os.RemoveAll(mergeDir)

					err = archiver.NewTarXz().Unarchive(path, extractDir)
					if err != nil {
						return fmt.Errorf("unarchive %s: %s", path, err)
					}

					unameName := strings.TrimSuffix(filepath.Base(path), ".tar.xz")
					mergedFile := filepath.Join(mergeDir, unameName)
					if err := utils.RunCMD(ctx, extractDir, "/bin/bash", "-O", "extglob", "-c", fmt.Sprintf(`bpftool -B vmlinux btf merge %s !(vmlinux)`, mergedFile)); err != nil {
						return fmt.Errorf("merge %s: %s", path, err)
					}
					if err := pkg.TarballBTF(ctx, mergeDir, path); err != nil {
						return fmt.Errorf("tarball %s: %s", path, err)
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
