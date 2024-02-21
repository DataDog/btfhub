package repo

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

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
	jobChan chan<- job.Job,
) error {

	btfName := fmt.Sprintf("%s.btf", p.BTFFilename())
	btfPath := filepath.Join(workDir, btfName)
	btfTarName := fmt.Sprintf("%s.btf.tar.xz", p.BTFFilename())
	btfTarPath := filepath.Join(workDir, btfTarName)

	if pkg.PackageHasBTF(p, workDir) {
		return utils.ErrHasBTF
	}
	if !force && utils.Exists(btfTarPath) {
		log.Printf("SKIP: %s exists\n", btfTarName)
		return nil
	}

	// 1st job: Extract kernel vmlinux file

	kernelExtJob := &job.KernelExtractionJob{
		Pkg:       p,
		WorkDir:   workDir,
		ReplyChan: make(chan interface{}),
		Force:     force,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case jobChan <- kernelExtJob: // send vmlinux file extraction job to worker
	}

	reply := <-kernelExtJob.ReplyChan // wait for reply

	var vmlinuxPath string

	switch v := reply.(type) {
	case error:
		return v
	case string:
		vmlinuxPath = v // receive vmlinux path from worker
	}

	// Check if BTF is already present in vmlinux (will skip further packages)

	hasBTF, err := utils.HasBTFSection(vmlinuxPath)
	if err != nil {
		return fmt.Errorf("BTF check: %s", err)
	}
	if hasBTF {
		pkg.MarkPackageHasBTF(p, workDir)
		// Removing here is bad for re-runs (it has to re-download)
		os.Remove(vmlinuxPath)
		return utils.ErrHasBTF
	}

	// 2nd job: Generate BTF file from vmlinux file

	job := &job.BTFGenerationJob{
		VmlinuxPath: vmlinuxPath,
		BTFPath:     btfPath,
		BTFTarPath:  btfTarPath,
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case jobChan <- job: // send BTF generation job to worker
	}

	return nil
}
