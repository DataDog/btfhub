package repo

import (
	"context"

	"github.com/aquasecurity/btfhub/pkg/job"
)

type RepoOptions struct {
	Force         bool
	KernelModules bool
	Ordered       bool
	PackageFile   string
	DryRun        bool
}

type Repository interface {
	GetKernelPackages(
		ctx context.Context,
		workDir string,
		release string,
		arch string,
		opts RepoOptions,
		jobChan chan<- job.Job,
	) error
}
