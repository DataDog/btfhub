package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path"
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
	btfTarName := fmt.Sprintf("%s.btf.tar.xz", p.BTFFilename())
	btfTarPath := filepath.Join(workDir, btfTarName)
	if pkg.PackageKernelHasBTF(p, workDir) {
		return utils.ErrKernelHasBTF
	}
	s3key := path.Join(opts.S3Prefix, btfTarName)

	if !opts.Force {
		if pkg.PackageFailed(p, workDir) {
			log.Printf("SKIP: %s previously failed\n", btfTarName)
			return nil
		}

		if pkg.PackageBTFExists(p, workDir) {
			log.Printf("SKIP: %s exists\n", btfTarName)
			return nil
		}

		if opts.S3Bucket != "" {
			exists, err := utils.S3Exists(ctx, opts.S3Bucket, s3key)
			if err != nil {
				return err
			}
			if exists {
				log.Printf("SKIP: %s/%s exists in S3\n", opts.S3Bucket, s3key)
				return nil
			}
		}
	}

	if opts.DryRun {
		return nil
	}

	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("btfhub-%s-*", p.BTFFilename()))
	if err != nil {
		return fmt.Errorf("create temp dir for package: %w", err)
	}
	defer os.RemoveAll(tmpDir)

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

	// from this point on, we just want to kick the jobs off and proceed with other packages
	btfGenDir := filepath.Join(tmpDir, "btfgen")
	if err := os.Mkdir(btfGenDir, 0777); err != nil {
		return err
	}

	// submit vmlinux BTF gen first, and then kernel modules afterwards
	vmlinuxBTF := filepath.Join(btfGenDir, "vmlinux")
	btfGenJob := &job.BTFGenerationJob{
		DebugFilePath: extractReply.VMLinuxPath,
		BTFPath:       vmlinuxBTF,
		ReplyChan:     make(chan any),
	}
	if err := job.SubmitAndWait(ctx, btfGenJob, chans.BTF); err != nil {
		return err
	}

	g := new(errgroup.Group)
	for _, debugFilePath := range extractReply.Paths {
		filename := filepath.Base(debugFilePath)
		// 2nd job: Generate BTF file from vmlinux file
		btfGenJob := &job.BTFGenerationJob{
			DebugFilePath: debugFilePath,
			BaseFilePath:  vmlinuxBTF,
			BTFPath:       filepath.Join(btfGenDir, filename),
			ReplyChan:     make(chan any),
		}
		if err := job.Submit(ctx, btfGenJob, chans.BTF); err != nil {
			return err
		}
		g.Go(func() error {
			return job.Wait(btfGenJob)
		})
	}

	if err := g.Wait(); err != nil {
		if !errors.Is(err, context.Canceled) {
			log.Printf("ERROR: %s", err)
		}
		return err
	}

	btfMergeDir := filepath.Join(tmpDir, "btfmerge")
	if err := os.Mkdir(btfMergeDir, 0777); err != nil {
		return err
	}
	btfPath := filepath.Join(btfMergeDir, fmt.Sprintf("%s.btf", p.BTFFilename()))
	if len(extractReply.Paths) > 0 {
		mergeJob := &job.BTFMergeJob{
			SourceDir: btfGenDir,
			BTFPath:   btfPath,
			ReplyChan: make(chan any),
		}
		if err := job.SubmitAndWait(ctx, mergeJob, chans.BTF); err != nil {
			return err
		}
	} else {
		if err := os.Rename(vmlinuxBTF, btfPath); err != nil {
			return fmt.Errorf("rename: %s", err)
		}
	}

	compressJob := &job.BTFCompressionJob{
		SourceDir:  btfMergeDir,
		BTFTarPath: btfTarPath,
		ReplyChan:  make(chan any),
	}
	if err := job.SubmitAndWait(ctx, compressJob, chans.BTF); err != nil {
		return err
	}

	if opts.S3Bucket != "" {
		uploadJob := &job.S3UploadJob{
			SourcePath: btfTarPath,
			Bucket:     opts.S3Bucket,
			Key:        s3key,
			ReplyChan:  make(chan any),
		}
		if err := job.SubmitAndWait(ctx, uploadJob, chans.BTF); err != nil {
			return err
		}
	}

	return nil
}
