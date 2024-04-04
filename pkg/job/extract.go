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
	// Download the kernel package
	downloadStart := time.Now()
	log.Printf("DEBUG: downloading %s\n", job.Pkg)

	kernPkgPath, err := job.Pkg.Download(ctx, job.WorkDir, job.Force)
	if err != nil {
		os.Remove(kernPkgPath)
		return err
	}

	log.Printf("DEBUG: finished downloading %s in %s\n", job.Pkg, time.Since(downloadStart))

	// Extract downloaded kernel package
	extractStart := time.Now()
	log.Printf("DEBUG: extracting vmlinux from %s\n", kernPkgPath)

	vmlinuxPath, paths, err := job.Pkg.ExtractKernel(ctx, kernPkgPath, job.WorkDir, job.KernelModules)
	if err != nil {
		os.RemoveAll(job.WorkDir)
		return fmt.Errorf("extracting vmlinux from %s: %w", kernPkgPath, err)
	}

	log.Printf("DEBUG: finished extracting %d files from %s in %s\n", len(paths), kernPkgPath, time.Since(extractStart))
	os.Remove(kernPkgPath) // remove downloaded kernel package

	// Reply with the path to the extracted directory
	job.ReplyChan <- &KernelExtractReply{
		ExtractDir:  job.WorkDir,
		VMLinuxPath: vmlinuxPath,
		Paths:       paths,
	}
	return nil
}

func (job *KernelExtractionJob) Reply() chan<- any {
	return job.ReplyChan
}
