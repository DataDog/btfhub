package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"

	"github.com/DataDog/btfhub/pkg/job"
	"github.com/DataDog/btfhub/pkg/pkg"
	"github.com/DataDog/btfhub/pkg/utils"
)

// processPackages processes a list of packages, sending jobs to the job channel.
func processPackages(
	ctx context.Context,
	workDir string,
	pkgs []pkg.Package,
	opts RepoOptions,
	chans *JobChannels,
) error {
	if !opts.Ordered {
		return processUnorderedPackages(ctx, workDir, pkgs, opts, chans)
	}
	return processOrderedPackages(ctx, workDir, pkgs, opts, chans)
}

func processUnorderedPackages(ctx context.Context, workDir string, pkgs []pkg.Package, opts RepoOptions, chans *JobChannels) error {
	g, ctx := errgroup.WithContext(ctx)
	for i, p := range pkgs {
		pos := i + 1
		gp := p
		g.Go(func() error {
			log.Printf("DEBUG: start pkg %s (%d/%d)\n", gp, pos, len(pkgs))
			err := processPackage(ctx, gp, workDir, opts, chans)
			if err != nil {
				if errors.Is(err, utils.ErrKernelHasBTF) {
					log.Printf("INFO: kernel %s has BTF already\n", gp)
					return nil
				}
				if errors.Is(err, context.Canceled) {
					return nil
				}
				log.Printf("ERROR: %s: %s\n", gp, err)
			}
			log.Printf("DEBUG: end pkg %s (%d/%d)\n", gp, pos, len(pkgs))
			return nil
		})
	}
	return g.Wait()
}

func processOrderedPackages(ctx context.Context, workDir string, pkgs []pkg.Package, opts RepoOptions, chans *JobChannels) error {
	for i, p := range pkgs {
		log.Printf("DEBUG: start pkg %s (%d/%d)\n", p, i+1, len(pkgs))
		err := processPackage(ctx, p, workDir, opts, chans)
		if err != nil {
			if errors.Is(err, utils.ErrKernelHasBTF) {
				log.Printf("INFO: kernel %s has BTF already, skipping later kernels\n", p)
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return nil
			}
			log.Printf("ERROR: %s: %s\n", p, err)
			continue
		}
		log.Printf("DEBUG: end pkg %s (%d/%d)\n", p, i+1, len(pkgs))
	}
	return nil
}

// processPackage creates a kernel extraction job and waits for the reply. It
// then creates a BTF generation job and sends it to the worker. It returns
func processPackage(
	ctx context.Context,
	p pkg.Package,
	workDir string,
	opts RepoOptions,
	chans *JobChannels,
) error {
	if opts.DryRun {
		return nil
	}

	return findIfPatchPresent(ctx, p, workDir, opts, chans)
}

func findIfPatchPresent(ctx context.Context, p pkg.Package, workDir string, opts RepoOptions, chans *JobChannels) error {
	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("btfhub-%s-*", p.BTFFilename()))
	if err != nil {
		return fmt.Errorf("create temp dir for package: %w", err)
	}
	//	defer os.RemoveAll(tmpDir)

	// 1st job: Extract kernel vmlinux and module .ko.debug files
	exDir := filepath.Join(tmpDir, "extract")
	if err := os.Mkdir(exDir, 0777); err != nil {
		return err
	}
	kernelExtJob := &job.KernelExtractionJob{
		Pkg:           p,
		WorkDir:       exDir,
		ReplyChan:     make(chan any),
		Force:         opts.Force,
		KernelModules: opts.KernelModules,
	}
	extractReply, err := job.SubmitAndWaitT[job.KernelExtractReply](ctx, kernelExtJob, chans.Default)
	if err != nil {
		if errors.Is(err, utils.ErrKernelHasBTF) {
			_ = pkg.MarkPackageHasBTF(p, workDir)
		}
		return err
	}

	seccompJob := &job.SeccompJob{
		DebugFilePath: extractReply.VMLinuxPath,
		ReplyChan:     make(chan any),
	}
	if err := job.SubmitAndWait(ctx, seccompJob, chans.BTF); err != nil {
		return err
	}

	return nil
}
