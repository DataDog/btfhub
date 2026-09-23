package job

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DataDog/btfhub/pkg/pkg"
)

type KernelExtractionJob struct {
	Pkg           pkg.Package
	WorkDir       string
	Path          string
	ReplyChan     chan any
	Force         bool
	KernelModules bool
}

type KernelExtractReply struct {
	ExtractDir  string
	VMLinuxPath string
	Paths       []string
}

// Do implements the Job interface, and is called by the worker. It downloads
// the kernel package, extracts the vmlinux file, and replies with a KernelExtractReply
// structure containing the paths in the reply channel.
func (job *KernelExtractionJob) Do(ctx context.Context) error {
	// Extract downloaded kernel package
	extractStart := time.Now()
	log.Printf("DEBUG: extracting vmlinux from %s\n", job.Path)

	vmlinuxPath, paths, err := job.Pkg.ExtractKernel(ctx, job.Path, job.WorkDir, job.KernelModules)
	if err != nil {
		os.RemoveAll(job.WorkDir)
		return fmt.Errorf("extracting vmlinux from %s: %w", job.Path, err)
	}

	log.Printf("DEBUG: finished extracting %d files from %s in %s\n", len(paths), job.Path, time.Since(extractStart))
	os.Remove(job.Path) // remove downloaded kernel package

	// Reply with the path to the extracted directory
	job.ReplyChan <- &KernelExtractReply{
		ExtractDir:  job.WorkDir,
		VMLinuxPath: vmlinuxPath,
		Paths:       paths,
	}
	return nil
}

func (job *KernelExtractionJob) Reply() chan any {
	return job.ReplyChan
}
