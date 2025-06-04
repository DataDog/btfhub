package commands

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/DataDog/btfhub/pkg/utils"
)

func Upload(ctx context.Context) error {
	distros, releases, archs, err := processArgs(slices.Sorted(maps.Keys(distroReleases)), distroReleases)
	if err != nil {
		return err
	}

	if s3bucket == "" {
		return fmt.Errorf("s3bucket is required")
	}

	archiveDir, err := archivePath()
	if err != nil {
		return fmt.Errorf("pwd: %s", err)
	}

	for _, distro := range distros {
		for _, release := range releases[distro] {
			for _, arch := range archs {
				btfdir := filepath.Join(archiveDir, distro, release, arch)
				if !utils.Exists(btfdir) {
					continue
				}

				err = filepath.Walk(btfdir, func(walkPath string, info fs.FileInfo, walkErr error) error {
					if cerr := ctx.Err(); cerr != nil {
						return cerr
					}
					if walkErr != nil {
						_, _ = fmt.Fprintf(os.Stderr, "walk error: %s\n", walkErr)
						return nil
					}

					if info.IsDir() {
						return nil
					}
					if !strings.HasSuffix(walkPath, ".btf.tar.xz") {
						return nil
					}

					f, err := os.Open(walkPath)
					if err != nil {
						return err
					}
					defer f.Close()

					relPath, err := filepath.Rel(archiveDir, walkPath)
					if err != nil {
						return err
					}
					key := path.Join(s3prefix, relPath)
					if !force {
						exists, err := utils.S3Exists(ctx, s3bucket, key)
						if err != nil || exists {
							return err
						}
					}
					log.Printf("uploading %s to %s/%s", walkPath, s3bucket, key)
					if dryRun {
						return nil
					}
					return utils.S3Upload(ctx, s3bucket, key, f)
				})
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}
