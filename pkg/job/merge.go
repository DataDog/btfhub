package job

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/DataDog/btfhub/pkg/utils"
)

type BTFMergeJob struct {
	SourceDir string
	BTFPath   string
	ReplyChan chan any
}

// Do implements the Job interface, and is called by the worker. It generates a
// BTF file from an object file with a .BTF section.
func (job *BTFMergeJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: merging BTF from %s\n", job.SourceDir)
	start := time.Now()

	if err := utils.RunCMD(ctx, job.SourceDir, "/bin/bash", "-O", "extglob", "-c", fmt.Sprintf(`bpftool -B vmlinux btf merge %s !(vmlinux)`, job.BTFPath)); err != nil {
		return fmt.Errorf("merge %s: %s", job.SourceDir, err)
	}

	log.Printf("DEBUG: finished merging BTF from %s in %s\n", job.SourceDir, time.Since(start))
	job.ReplyChan <- nil
	return nil
}

func (job *BTFMergeJob) Reply() chan any {
	return job.ReplyChan
}
