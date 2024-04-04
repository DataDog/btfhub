package job

import (
	"context"

	"github.com/DataDog/btfhub/pkg/utils"
)

// GenerateBTF generates a BTF file from a vmlinux file
func GenerateBTF(ctx context.Context, debugFile string, baseFile string, out string) error {
	var args []string
	if baseFile != "" {
		args = append(args, "--btf_base", baseFile)
	}
	args = append(args, "--btf_gen_floats", "--skip_encoding_btf_inconsistent_proto", "--btf_gen_optimized", "--btf_encode_detached", out, debugFile)
	return utils.RunCMD(ctx, "", "pahole", args...)
}
