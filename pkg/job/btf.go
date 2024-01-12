package job

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"
)

type BTFGenerationJob struct {
	DebugFilePath string
	BTFPath       string
	ReplyChan     chan any
}

// Do implements the Job interface, and is called by the worker. It generates a
// BTF file from an object file with a .BTF section.
func (job *BTFGenerationJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: generating BTF from %s\n", job.DebugFilePath)
	btfGenStart := time.Now()

	if err := GenerateBTF(ctx, job.DebugFilePath, job.BTFPath); err != nil {
		os.Remove(job.BTFPath)
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return fmt.Errorf("btf gen: %s", err)
	}

	log.Printf("DEBUG: finished generating BTF from %s in %s\n", job.DebugFilePath, time.Since(btfGenStart))
	job.ReplyChan <- nil
	return nil
}

func (job *BTFGenerationJob) Reply() chan<- any {
	return job.ReplyChan
}
