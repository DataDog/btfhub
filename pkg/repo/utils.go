package repo

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/aquasecurity/btfhub/pkg/job"
	"github.com/aquasecurity/btfhub/pkg/pkg"
	"github.com/aquasecurity/btfhub/pkg/utils"
)

// processPackage creates a kernel extraction job and waits for the reply. It
// then creates a BTF generation job and sends it to the worker. It returns
func processPackage(
	ctx context.Context,
	p pkg.Package,
	workDir string,
	force bool,
	kernelModules bool,
	jobChan chan<- job.Job,
) error {
	btfTarName := fmt.Sprintf("%s.btf.tar.xz", p.BTFFilename())
	btfTarPath := filepath.Join(workDir, btfTarName)
	if pkg.PackageKernelHasBTF(p, workDir) {
		return utils.ErrKernelHasBTF
	}

	if !force && utils.Exists(btfTarPath) {
		if kernelModules {
			hasmods, err := utils.TarballHasKernelModules(btfTarPath)
			if err != nil || hasmods {
				return err
			}
		} else {
			log.Printf("SKIP: %s exists\n", btfTarName)
			return nil
		}
	}

	tmpDir, err := os.MkdirTemp("", fmt.Sprintf("btfhub-%s-*", p.BTFFilename()))
	if err != nil {
		return fmt.Errorf("create temp dir for package: %w", err)
	}

	// 1st job: Extract kernel vmlinux and module .ko.debug files
	exDir := filepath.Join(tmpDir, "extract")
	if err := os.Mkdir(exDir, 0777); err != nil {
		return err
	}
	kernelExtJob := &job.KernelExtractionJob{
		Pkg:           p,
		WorkDir:       exDir,
		ReplyChan:     make(chan any),
		Force:         force,
		KernelModules: kernelModules,
	}

	select {
	case <-ctx.Done():
		os.RemoveAll(tmpDir)
		return ctx.Err()
	case jobChan <- kernelExtJob: // send vmlinux file extraction job to worker
	}

	reply := <-kernelExtJob.ReplyChan // wait for reply
	var extractReply *job.KernelExtractReply
	switch v := reply.(type) {
	case error:
		os.RemoveAll(tmpDir)
		return v
	case *job.KernelExtractReply:
		extractReply = v
	}

	// Check if BTF is already present in vmlinux (will skip further packages)
	vmlinuxPath := filepath.Join(extractReply.ExtractDir, "vmlinux")
	hasBTF, err := utils.HasBTFSection(vmlinuxPath)
	if err != nil {
		return fmt.Errorf("BTF check: %s", err)
	}
	if hasBTF {
		_ = pkg.MarkPackageHasBTF(p, workDir)
		os.RemoveAll(tmpDir)
		return utils.ErrKernelHasBTF
	}

	// from this point on, we just want to kick the jobs off and proceed with other packages

	btfGenDir := filepath.Join(tmpDir, "btfgen")
	if err := os.Mkdir(btfGenDir, 0777); err != nil {
		os.RemoveAll(tmpDir)
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
	case jobChan <- btfGenJob: // send BTF generation job to worker
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
		case jobChan <- btfGenJob: // send BTF generation job to worker
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
	go func() {
		defer os.RemoveAll(tmpDir)
		if err := g.Wait(); err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Printf("ERROR: %s", err)
			}
			return
		}

		log.Printf("DEBUG: compressing BTF into %s\n", btfTarPath)
		tarCompressStart := time.Now()
		if err := pkg.TarballBTF(ctx, btfGenDir, btfTarPath); err != nil {
			os.Remove(btfTarPath)
			log.Printf("ERROR: btf.tar.xz gen: %s", err)
			return
		}

		log.Printf("DEBUG: finished compressing BTF into %s in %s\n", btfTarPath, time.Since(tarCompressStart))
	}()

	return nil
}
