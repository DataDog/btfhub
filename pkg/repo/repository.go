package repo

import (
	"context"
	"regexp"

	"github.com/DataDog/btfhub/pkg/job"
)

type RepoOptions struct {
	Force         bool
	KernelModules bool
	Ordered       bool
	DryRun        bool
	Query         *regexp.Regexp
	Launchpad     bool
	HashDir       string

	// S3Bucket is the AWS S3 bucket where uploaded BTFs should be stored
	S3Bucket string
	// S3Prefix is the key prefix used when uploading BTFs
	S3Prefix string
}

type JobChannels struct {
	BTF     chan<- job.Job
	Default chan<- job.Job
}

type Repository interface {
	GetKernelPackages(
		ctx context.Context,
		workDir string,
		release string,
		arch string,
		opts RepoOptions,
		chans *JobChannels,
	) error
}
