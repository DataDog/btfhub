package job

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/DataDog/btfhub/pkg/utils"
)

type S3UploadJob struct {
	SourcePath string
	Bucket     string
	Key        string
	ReplyChan  chan any
}

// Do implements the Job interface, and is called by the worker.
// It uploads the specified file to the provided S3 bucket and key.
func (job *S3UploadJob) Do(ctx context.Context) error {
	log.Printf("DEBUG: S3 uploading %s to %s/%s\n", job.SourcePath, job.Bucket, job.Key)
	start := time.Now()

	file, err := os.Open(job.SourcePath)
	if err != nil {
		return fmt.Errorf("open %s: %s", job.SourcePath, err)
	}
	defer file.Close()

	err = utils.S3Upload(ctx, job.Bucket, job.Key, file)
	if err != nil {
		return fmt.Errorf("s3 upload %s/%s: %s", job.Bucket, job.Key, err)
	}

	log.Printf("DEBUG: finished S3 uploading from %s to %s/%s in %s\n", job.SourcePath, job.Bucket, job.Key, time.Since(start))
	job.ReplyChan <- nil
	return nil
}

func (job *S3UploadJob) Reply() chan<- any {
	return job.ReplyChan
}
