package commands

import "flag"

var distroArg, releaseArg, archArg, fileArg, queryArg string
var numWorkers int
var force, kernelModules, ordered, dryRun bool

func init() {
	flag.StringVar(&distroArg, "distro", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&distroArg, "d", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&releaseArg, "release", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&releaseArg, "r", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&archArg, "arch", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&archArg, "a", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&fileArg, "pkg-file", "", "file to use as list of packages rather than reading from repositories (requires distro, release, and arch)")
	flag.StringVar(&queryArg, "query", "", "regexp query to filter kernel versions")
	flag.StringVar(&queryArg, "q", "", "regexp query to filter kernel versions")
	flag.IntVar(&numWorkers, "workers", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.IntVar(&numWorkers, "j", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.BoolVar(&force, "f", false, "force update regardless of existing files (defaults to false)")
	flag.BoolVar(&kernelModules, "kmod", true, "generate BTF for kernel modules, in addition to the base kernel (defaults to true)")
	flag.BoolVar(&ordered, "ordered", true, "process kernels in order so future kernels can be skipped once BTF is detected")
	flag.BoolVar(&dryRun, "dry-run", false, "do not make changes")
}
