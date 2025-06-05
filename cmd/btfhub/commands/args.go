package commands

import "flag"

var distroArg, releaseArg, archArg, queryArg, s3bucket, s3prefix string
var numWorkers int
var force, kernelModules, ordered, dryRun, launchpad bool

func init() {
	flag.StringVar(&distroArg, "distro", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&distroArg, "d", "", "distribution to update (ubuntu,debian,centos,fedora,ol,rhel,amazon,sles)")
	flag.StringVar(&releaseArg, "release", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&releaseArg, "r", "", "distribution release to update, requires specifying distribution")
	flag.StringVar(&archArg, "arch", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&archArg, "a", "", "architecture to update (x86_64,arm64)")
	flag.StringVar(&queryArg, "query", "", "regexp query to filter kernel versions")
	flag.StringVar(&queryArg, "q", "", "regexp query to filter kernel versions")
	flag.IntVar(&numWorkers, "workers", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.IntVar(&numWorkers, "j", 0, "number of concurrent workers (defaults to runtime.NumCPU() - 1)")
	flag.BoolVar(&force, "f", false, "force update regardless of existing files (defaults to false)")
	flag.BoolVar(&kernelModules, "kmod", true, "generate BTF for kernel modules, in addition to the base kernel (defaults to true)")
	flag.BoolVar(&ordered, "ordered", true, "process kernels in order so future kernels can be skipped once BTF is detected")
	flag.BoolVar(&dryRun, "dry-run", false, "do not make changes")
	flag.BoolVar(&launchpad, "launchpad", false, "query Ubuntu Launchpad for additional kernels")
	flag.StringVar(&s3bucket, "s3-bucket", "", "AWS S3 bucket where new BTFs will be uploaded")
	flag.StringVar(&s3prefix, "s3-prefix", "", "Key prefix to use when uploading BTFs")
}
