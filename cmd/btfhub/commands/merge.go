package commands

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
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

	if numWorkers == 0 {
		numWorkers = runtime.NumCPU() - 1
	}

	jobChan := make(chan job.Job)
	consume, consCtx := errgroup.WithContext(ctx)

	log.Printf("Using %d workers\n", numWorkers)
	for i := 0; i < numWorkers; i++ {
		consume.Go(func() error {
			return job.StartWorker(consCtx, jobChan, jobChan)
		})
	}

	produce, prodCtx := errgroup.WithContext(ctx)
	for _, d := range distros {
		distro := d
		for _, r := range releases[d] {
			release := r
			for _, a := range archs {
				arch := a

				btfdir := filepath.Join(archiveDir, distro, release, arch)
				if !utils.Exists(btfdir) {
					continue
				}

				produce.Go(func() error {
					return filepath.Walk(btfdir, func(path string, info fs.FileInfo, err error) error {
						if cerr := prodCtx.Err(); cerr != nil {
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

						produce.Go(func() error {
							mergeJob := &job.InPlaceBTFMergeJob{
								SourceTarball: path,
								ReplyChan:     make(chan any),
							}
							select {
							case <-ctx.Done():
								return ctx.Err()
							case jobChan <- mergeJob: // send BTF merge job to worker
							}
							reply := <-mergeJob.ReplyChan // wait for reply
							switch v := reply.(type) {
							case error:
								return v
							default:
								return nil
							}
						})
						return nil
					})
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
