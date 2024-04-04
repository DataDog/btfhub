package job

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aquasecurity/btfhub/pkg/pkg"
)

type BTFCompressionJob struct {
	SourceDir  string
	BTFTarPath string
	ReplyChan  chan any
}

// Do implements the Job interface, and is called by the worker. It generates a
// BTF file from an object file with a .BTF section.
func (job *BTFCompressionJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: compressing BTF into %s\n", job.BTFTarPath)
	tarCompressStart := time.Now()
	os.Remove(job.BTFTarPath)
	if err := pkg.TarballBTF(ctx, job.SourceDir, job.BTFTarPath); err != nil {
		os.Remove(job.BTFTarPath)
		return fmt.Errorf("ERROR: btf.tar.xz gen: %s", err)
	}

	log.Printf("DEBUG: finished compressing BTF into %s in %s\n", job.BTFTarPath, time.Since(tarCompressStart))
	job.ReplyChan <- nil
	return nil
}

func (job *BTFCompressionJob) Reply() chan<- any {
	return job.ReplyChan
}
