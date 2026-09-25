package job

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/DataDog/btfhub/pkg/pkg"
)

type DownloadJob struct {
	Pkg       pkg.Package
	WorkDir   string
	ReplyChan chan any
	Force     bool
}

type DownloadReply struct {
	Path string
}

func (job *DownloadJob) Do(ctx context.Context) error {
	// Download the kernel package
	downloadStart := time.Now()
	log.Printf("DEBUG: downloading %s\n", job.Pkg)

	kernPkgPath, err := job.Pkg.Download(ctx, job.WorkDir, job.Force)
	if err != nil {
		os.Remove(kernPkgPath)
		return err
	}

	log.Printf("DEBUG: finished downloading %s in %s\n", job.Pkg, time.Since(downloadStart))
	job.ReplyChan <- &DownloadReply{
		Path: kernPkgPath,
	}
	return nil
}

func (job *DownloadJob) Reply() chan any {
	return job.ReplyChan
}
