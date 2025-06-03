package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
)

var S3Client = sync.OnceValues(func() (*s3.Client, error) {
	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}
	return s3.NewFromConfig(cfg), nil
})

func S3Exists(ctx context.Context, bucket string, key string) (bool, error) {
	client, err := S3Client()
	if err != nil {
		return false, err
	}

	_, err = client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err == nil {
		return true, nil
	}

	var notFoundError *types.NotFound
	if errors.As(err, &notFoundError) {
		return false, nil
	}
	return false, err
}

func S3Upload(ctx context.Context, bucket string, key string, data io.Reader) error {
	client, err := S3Client()
	if err != nil {
		return err
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   data,
	})
	if err != nil {
		return fmt.Errorf("s3 put: %w", err)
	}

	err = s3.NewObjectExistsWaiter(client).Wait(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}, time.Minute)
	if err != nil {
		return errors.New("timed out waiting for object to exist")
	}
	return nil
}
