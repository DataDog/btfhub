package repo

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/DataDog/btfhub/pkg/kernel"
	"github.com/DataDog/btfhub/pkg/pkg"
	"github.com/DataDog/btfhub/pkg/utils"
)

type AmazonRepo struct {
	archs map[string]string
}

func NewAmazonRepo() Repository {
	return &AmazonRepo{
		archs: map[string]string{
			"x86_64": "x86_64",
			"arm64":  "aarch64",
		},
	}
}

func (d *AmazonRepo) GetKernelPackages(
	ctx context.Context,
	workDir string,
	_ string,
	arch string,
	opts RepoOptions,
	chans *JobChannels,
) error {
	altArch := d.archs[arch]
	searchOut, err := repoquery(ctx, "kernel-debuginfo", altArch)
	if err != nil {
		return err
	}
	pkgs, err := parseRepoqueryPackages(searchOut, kernel.NewKernelVersion(""))
	if err != nil {
		return fmt.Errorf("parse package listing: %s", err)
	}
	sort.Sort(pkg.ByVersion(pkgs))

	return processPackages(ctx, workDir, pkgs, opts, chans)
}

func repoquery(ctx context.Context, pkg string, arch string) (*bytes.Buffer, error) {
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	binary, args := utils.SudoCMD("repoquery", "--archlist="+arch, "--show-duplicates", pkg)
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("repoquery search %s: %s\n%s", pkg, err, stderr.String())
	}
	return stdout, nil
}

func parseRepoqueryPackages(rdr io.Reader, minVersion kernel.Version) ([]pkg.Package, error) {
	pkgs := map[string]pkg.Package{}
	bio := bufio.NewScanner(rdr)
	for bio.Scan() {
		line := bio.Text()
		if !strings.HasPrefix(line, "kernel-debuginfo-") {
			continue
		}
		if strings.HasPrefix(line, "kernel-debuginfo-common-") {
			continue
		}
		_, version, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		filename := version
		lastdot := strings.LastIndex(filename, ".")
		if lastdot == -1 {
			continue
		}
		p := &pkg.RHELPackage{
			Name:          fmt.Sprintf("kernel-debuginfo-%s", version),
			NameOfFile:    filename,
			KernelVersion: kernel.NewKernelVersion(filename[:lastdot]),
			Architecture:  filename[lastdot+1:],
		}
		if !minVersion.IsZero() && p.Version().Less(minVersion) {
			continue
		}
		if _, ok := pkgs[p.Name]; !ok {
			pkgs[p.Name] = p
		}
	}
	if err := bio.Err(); err != nil {
		return nil, err
	}
	return slices.Collect(maps.Values(pkgs)), nil
}
