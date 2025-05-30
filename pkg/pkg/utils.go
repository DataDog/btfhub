package pkg

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/utils"
)

func TarballBTF(ctx context.Context, btfDir string, out string) error {
	// Use external tool for performance reasons
	f, err := os.Open(btfDir)
	if err != nil {
		return fmt.Errorf("open %s: %w", btfDir, err)
	}
	defer f.Close()
	files, err := f.Readdirnames(-1)
	if err != nil {
		return fmt.Errorf("readdirnames: %w", err)
	}
	slices.Sort(files)

	args := []string{"-cvJ",
		"--sort=name",
		"--owner=root:0",
		"--group=root:0",
		"--mode=a=r",
		"--mtime=@0",
		"-f",
		out,
	}
	args = append(args, files...)
	return utils.RunCMD(ctx, btfDir, "tar", args...)
}

//
// RHEL packages
//

func yumDownload(ctx context.Context, pkg string, arch string, destdir string) error {
	stderr := &bytes.Buffer{}
	binary, args := utils.SudoCMD("yumdownloader", "--archlist="+arch, "--destdir="+destdir, pkg)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("yum download %s: %s\n%s", pkg, err, stderr.String())
	}

	return nil
}

//
// Ubuntu packages
//

// GetPackageList downloads the Packages.xz file from the given repo and release
func GetPackageList(ctx context.Context, repo string, releaseName string, arch string) (
	*bytes.Buffer, error,
) {
	var err error
	rawPkgs := &bytes.Buffer{}

	main := fmt.Sprintf("%s/dists/%s/main/binary-%s/Packages.xz", repo, releaseName, arch)
	updates := fmt.Sprintf("%s/dists/%s-updates/main/binary-%s/Packages.xz", repo, releaseName, arch)
	universe := fmt.Sprintf("%s/dists/%s-updates/universe/binary-%s/Packages.xz", repo, releaseName, arch)

	if err = utils.Download(ctx, main, rawPkgs); err != nil {
		return nil, fmt.Errorf("download base package list: %s", err)
	}
	if err = utils.Download(ctx, updates, rawPkgs); err != nil {
		return nil, fmt.Errorf("download updates main package list: %s", err)
	}
	if err = utils.Download(ctx, universe, rawPkgs); err != nil {
		return nil, fmt.Errorf("download updates universe package list: %s", err)
	}

	return rawPkgs, nil
}

func ParseAPTPackages(rawPkgs io.Reader, repoURL string, release string, releaseName string) (
	[]*UbuntuPackage, error,
) {
	var kernelPkgs []*UbuntuPackage

	pkg := &UbuntuPackage{Release: release, ReleaseName: releaseName}

	bio := bufio.NewScanner(rawPkgs)
	bio.Buffer(make([]byte, 4096), 128*1024)

	for bio.Scan() {
		line := bio.Text()

		// Start parsing the next package

		if len(line) == 0 {
			if strings.HasPrefix(pkg.Name, "linux-image-") && pkg.isValid() {
				kernelPkgs = append(kernelPkgs, pkg) // save the previous kernel package
			}
			pkg = &UbuntuPackage{Release: release, ReleaseName: releaseName}
			continue
		}
		if line[0] == ' ' {
			continue
		}
		name, val, found := strings.Cut(line, ": ")
		if !found {
			continue
		}

		// Populate current package fields

		switch name {
		case "Package":
			pkg.Name = val
			fn := strings.TrimPrefix(val, "linux-image-")
			fn = strings.TrimSuffix(fn, "-dbgsym")
			fn = strings.TrimSuffix(fn, "-dbg")
			pkg.NameOfFile = strings.TrimPrefix(fn, "unsigned-")
		case "Architecture":
			pkg.Architecture = val
		case "Version":
			pkg.KernelVersion = kernel.NewKernelVersion(val)
		case "Filename":
			pkg.URL = fmt.Sprintf("%s/%s", repoURL, val)
		case "Size":
			sz, err := strconv.ParseUint(val, 10, 64)
			if err == nil {
				pkg.Size = sz
			}
		default:
			continue
		}
	}
	if err := bio.Err(); err != nil {
		return nil, err
	}

	// Save the last package

	if pkg.isValid() && strings.HasPrefix(pkg.Name, "linux-image-") {
		kernelPkgs = append(kernelPkgs, pkg)
	}

	return kernelPkgs, nil
}
