package job

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

type HashJob struct {
	SourcePath string
	DestPath   string
	ReplyChan  chan any
}

// Do implements the Job interface, and is called by the worker.
// It hashs the SourcePath and writes the SHA256 hash to DestPath
func (job *HashJob) Do(_ context.Context) error {
	log.Printf("DEBUG: hashing %s to %s\n", job.SourcePath, job.DestPath)
	start := time.Now()

	hash, err := sha256File(job.SourcePath)
	if err != nil {
		return fmt.Errorf("sha256 hash: %w", err)
	}
	destDir := filepath.Dir(job.DestPath)
	if err := os.Mkdir(destDir, 0755); err != nil {
		return fmt.Errorf("mkdir %s: %w", destDir, err)
	}
	if err := os.WriteFile(job.DestPath, []byte(hash), 0644); err != nil {
		return fmt.Errorf("write hash file: %w", err)
	}

	log.Printf("DEBUG: finished hashing %s to %s in %s\n", job.SourcePath, job.DestPath, time.Since(start))
	job.ReplyChan <- nil
	return nil
}

func (job *HashJob) Reply() chan any {
	return job.ReplyChan
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", h.Sum(nil)), nil
}
