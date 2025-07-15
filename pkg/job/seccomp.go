package job

import (
	"context"
	"log"
	"time"

	"github.com/DataDog/btfhub/pkg/utils"
)

type SeccompJob struct {
	DebugFilePath string
	ReplyChan     chan any
}

func IsBuggy(ctx context.Context, vmlinuxFile string) error {
	args := []string{vmlinuxFile}
	return utils.RunCMD(ctx, "", "./scripts/is_buggy.sh", args...)
}

func (job *SeccompJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: checking if seccomp bug is present %s\n", job.DebugFilePath)
	seccompStart := time.Now()

	if err := IsBuggy(ctx, job.DebugFilePath); err != nil {
		log.Printf("WARN: %s looks buggy!: %v\n", job.DebugFilePath, err)
	}

	log.Printf("DEBUG: finished checking for seccomp bug in %s. Took %s\n", job.DebugFilePath, time.Since(seccompStart))
	job.ReplyChan <- nil
	return nil
}

func (job *SeccompJob) Reply() chan any {
	return job.ReplyChan
}
