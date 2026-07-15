package commands

import (
	"context"
	"fmt"

	"github.com/DataDog/btfhub/pkg/utils"
)

func ACL(ctx context.Context) error {
	if s3bucket == "" {
		return fmt.Errorf("s3bucket is required")
	}
	if s3prefix == "" {
		return fmt.Errorf("s3prefix is required")
	}

	keys, err := utils.S3List(ctx, s3bucket, s3prefix)
	if err != nil {
		return err
	}

	for _, key := range keys {
		err = utils.S3PutACL(ctx, s3bucket, key)
		if err != nil {
			return err
		}
	}
	return nil
}
