package utils

import (
	"compress/bzip2"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/DataDog/zstd"
	"github.com/cavaliergopher/cpio"
	"github.com/cavaliergopher/rpm"
	fastxz "github.com/therootcompany/xz"
)

func ExtractVmlinuxFromRPM(ctx context.Context, rpmPath string, extractDir string, kernelModules bool) (string, []string, error) {
	file, err := os.Open(rpmPath)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()

	rpmPkg, err := rpm.Read(file)
	if err != nil {
		return "", nil, fmt.Errorf("rpm read: %s", err)
	}

	var crdr io.Reader

	// Find out about RPM package compression
	switch rpmPkg.PayloadCompression() {
	case "xz":
		crdr, err = fastxz.NewReader(file, 0)
		if err != nil {
			return "", nil, fmt.Errorf("xz reader: %s", err)
		}
	case "zstd":
		zrdr := zstd.NewReader(file)
		defer zrdr.Close()
		crdr = zrdr
	case "gzip":
		grdr, err := gzip.NewReader(file)
		if err != nil {
			return "", nil, fmt.Errorf("gzip reader: %s", err)
		}
		defer grdr.Close()
		crdr = grdr
	case "bzip2":
		crdr = bzip2.NewReader(file)
	default:
		return "", nil, fmt.Errorf("unsupported compression: %s", rpmPkg.PayloadCompression())
	}

	if format := rpmPkg.PayloadFormat(); format != "cpio" {
		return "", nil, fmt.Errorf("unsupported payload format: %s", format)
	}

	// Read from cpio archive
	var paths []string
	vmlinuxPath := ""
	cpioReader := cpio.NewReader(crdr)
	for {
		if err := ctx.Err(); err != nil {
			return "", nil, err
		}

		cpioHeader, err := cpioReader.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return "", nil, fmt.Errorf("cpio next: %s", err)
		}

		if !cpioHeader.Mode.IsRegular() {
			continue
		}

		// Extract vmlinux and .ko.debug files
		if strings.Contains(cpioHeader.Name, "vmlinux") {
			vmlinuxPath = filepath.Join(extractDir, "vmlinux")
			err = extractFile(ctx, vmlinuxPath, cpioHeader, cpioReader)
			if err != nil {
				return "", nil, err
			}
			hasBTF, err := HasBTFSection(vmlinuxPath)
			if err != nil {
				return "", nil, err
			}
			if hasBTF {
				return "", nil, ErrKernelHasBTF
			}
			if !kernelModules {
				return vmlinuxPath, nil, nil
			}
		} else if kernelModules && strings.HasSuffix(cpioHeader.Name, ".ko.debug") {
			filename := strings.TrimSuffix(filepath.Base(cpioHeader.Name), ".ko.debug")
			outfile := filepath.Join(extractDir, filename)
			err = extractFile(ctx, outfile, cpioHeader, cpioReader)
			if err != nil {
				return "", nil, err
			}
			paths = append(paths, outfile)
		}
	}
	if vmlinuxPath == "" {
		return "", nil, fmt.Errorf("vmlinux file not found in rpm")
	}
	return vmlinuxPath, paths, nil
}

func extractFile(ctx context.Context, filename string, cpioHeader *cpio.Header, cpioReader *cpio.Reader) error {
	outFile, err := os.Create(filename)
	if err != nil {
		return err
	}

	counter := &ProgressCounter{
		Ctx:  ctx,
		Op:   "Extracting " + filepath.Base(filename),
		Name: cpioHeader.Name,
		Size: uint64(cpioHeader.Size),
	}

	_, err = io.Copy(outFile, io.TeeReader(cpioReader, counter))

	if err != nil {
		outFile.Close()
		os.Remove(filename)
		return fmt.Errorf("cpio file copy: %s", err)
	}

	outFile.Close()
	return nil
}
