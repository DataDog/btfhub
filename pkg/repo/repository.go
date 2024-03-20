package repo

import (
	"context"
	"regexp"

	"github.com/aquasecurity/btfhub/pkg/job"
)

type RepoOptions struct {
	Force         bool
	KernelModules bool
	Ordered       bool
	PackageFile   string
	DryRun        bool
	Query         *regexp.Regexp
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
