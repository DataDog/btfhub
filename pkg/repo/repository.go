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
