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

	if !opts.Force {
		if pkg.PackageFailed(p, workDir) {
			log.Printf("SKIP: %s previously failed\n", btfTarName)
			return nil
		}

		if pkg.PackageBTFExists(p, workDir) {
			log.Printf("SKIP: %s exists\n", btfTarName)
			return nil
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

	select {
	case <-ctx.Done():
		return ctx.Err()
	case chans.Default <- kernelExtJob: // send vmlinux file extraction job to worker
	}

	reply := <-kernelExtJob.ReplyChan // wait for reply
	var extractReply *job.KernelExtractReply
	switch v := reply.(type) {
	case error:
		if errors.Is(v, utils.ErrKernelHasBTF) {
			_ = pkg.MarkPackageHasBTF(p, workDir)
		}
		return v
	case *job.KernelExtractReply:
		extractReply = v
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case chans.BTF <- btfGenJob: // send BTF generation job to worker
	}
	reply = <-btfGenJob.ReplyChan // wait for reply
	switch v := reply.(type) {
	case error:
		return v
	default:
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

		select {
		case <-ctx.Done():
			return ctx.Err()
		case chans.BTF <- btfGenJob: // send BTF generation job to worker
		}

		g.Go(func() error {
			reply := <-btfGenJob.ReplyChan // wait for reply
			switch v := reply.(type) {
			case error:
				return v
			default:
				return nil
			}
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
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chans.BTF <- mergeJob: // send BTF merge job to worker
		}
		reply := <-mergeJob.ReplyChan // wait for reply
		switch v := reply.(type) {
		case error:
			return v
		default:
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
	select {
	case <-ctx.Done():
		return ctx.Err()
	case chans.BTF <- compressJob: // send BTF compression job to worker
	}

	// removing the temp directory requires we want for this job to complete
	reply = <-compressJob.ReplyChan // wait for reply
	switch v := reply.(type) {
	case error:
		return v
	default:
		return nil
	}
}
