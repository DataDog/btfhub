package job

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/mholt/archiver/v3"

	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

type BTFMergeJob struct {
	SourceTarball string
	ReplyChan     chan any
}

// Do implements the Job interface, and is called by the worker. It generates a
// BTF file from an object file with a .BTF section.
func (job *BTFMergeJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: merging BTF from %s\n", job.SourceTarball)
	start := time.Now()

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

	err = archiver.NewTarXz().Unarchive(job.SourceTarball, extractDir)
	if err != nil {
		return fmt.Errorf("unarchive %s: %s", job.SourceTarball, err)
	}

	unameName := strings.TrimSuffix(filepath.Base(job.SourceTarball), ".tar.xz")
	mergedFile := filepath.Join(mergeDir, unameName)
	if err := utils.RunCMD(ctx, extractDir, "/bin/bash", "-O", "extglob", "-c", fmt.Sprintf(`bpftool -B vmlinux btf merge %s !(vmlinux)`, mergedFile)); err != nil {
		return fmt.Errorf("merge %s: %s", job.SourceTarball, err)
	}

	tmpTarball := filepath.Join(extractDir, "tmp.tar.xz")
	if err := pkg.TarballBTF(ctx, mergeDir, tmpTarball); err != nil {
		return fmt.Errorf("tarball %s: %s", tmpTarball, err)
	}
	if err := os.Rename(tmpTarball, job.SourceTarball); err != nil {
		return fmt.Errorf("rename %s: %s", tmpTarball, err)
	}

	log.Printf("DEBUG: finished merging BTF from %s in %s\n", job.SourceTarball, time.Since(start))
	job.ReplyChan <- nil
	return nil
}

func (job *BTFMergeJob) Reply() chan<- any {
	return job.ReplyChan
}
