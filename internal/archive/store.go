// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 ElcanoTek, Inc.

package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"

	"github.com/ElcanoTek/explorer/internal/config"
)

// MaxObjectBytes caps a full message download. SES accepts at most 40 MB
// per message; anything larger is not mail Explorer can show.
const MaxObjectBytes = 128 << 20

var (
	// ErrInvalidRange is S3's InvalidRange: a ranged read of a zero-byte
	// object (such as SES's AMAZON_SES_SETUP_NOTIFICATION marker).
	ErrInvalidRange = errors.New("invalid range")
	// ErrNotFound means the requested attachment is not in the message.
	ErrNotFound = errors.New("not found")
	// ErrBucketUnset is returned by every call when EMAIL_S3_BUCKET is empty.
	ErrBucketUnset = errors.New("EMAIL_S3_BUCKET is not set — configure it with: explorer env edit && explorer restart")
	// ErrTooLarge is returned for an object over MaxObjectBytes.
	ErrTooLarge = errors.New("message is larger than Explorer will download")
	// ErrNoSuchKey is S3's NoSuchKey: the object does not exist.
	ErrNoSuchKey = errors.New("no such key")
)

// ObjectStream is an open S3 object body.
type ObjectStream struct {
	Body        io.ReadCloser
	Size        int64
	ContentType string
}

// Streamer is implemented by stores that can stream an object without
// buffering it (the cached link payloads run to hundreds of megabytes).
type Streamer interface {
	Open(ctx context.Context, key string) (*ObjectStream, error)
}

// Object is one listed archive object.
type Object struct {
	Key          string
	LastModified time.Time
	Size         int64
}

// ListPage is one ListObjectsV2 page.
type ListPage struct {
	Objects   []Object
	NextToken string // "" on the last page
}

// Store is the read-only slice of S3 Explorer uses: ListObjectsV2 and
// GetObject, exactly the two calls the documented IAM policy grants.
type Store interface {
	// List returns one page of keys under prefix.
	List(ctx context.Context, prefix, continuationToken string, maxKeys int32) (ListPage, error)
	// Get reads an object: the first maxBytes bytes with a ranged GET when
	// maxBytes > 0, the whole object otherwise (bounded by MaxObjectBytes).
	Get(ctx context.Context, key string, maxBytes int64) ([]byte, error)
}

type s3Store struct {
	client *s3.Client
	bucket string
}

type unsetStore struct{}

func (unsetStore) List(context.Context, string, string, int32) (ListPage, error) {
	return ListPage{}, ErrBucketUnset
}

func (unsetStore) Get(context.Context, string, int64) ([]byte, error) {
	return nil, ErrBucketUnset
}

// NewS3Store builds the S3-backed Store. Static credentials are used only
// when both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set; otherwise
// the SDK's default chain applies (instance role, ~/.aws, AWS_PROFILE,
// AWS_ENDPOINT_URL*, …), read from the process environment. With
// EMAIL_S3_BUCKET unset the store is still returned, and every call fails
// with ErrBucketUnset, so the service starts and says what is missing.
func NewS3Store(ctx context.Context, s config.Settings) (Store, error) {
	if s.Bucket == "" {
		return unsetStore{}, nil
	}
	opts := []func(*awsconfig.LoadOptions) error{awsconfig.WithRegion(s.AWSRegion)}
	if s.AWSAccessKeyID != "" && s.AWSSecretAccessKey != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(s.AWSAccessKeyID, s.AWSSecretAccessKey, s.AWSSessionToken)))
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("load AWS configuration: %w", err)
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = s.S3ForcePathStyle
		// Ranged header reads carry no whole-object checksum; validating
		// only when required keeps the SDK from logging that on every row.
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		o.DisableLogOutputChecksumValidationSkipped = true
	})
	return &s3Store{client: client, bucket: s.Bucket}, nil
}

func (st *s3Store) List(ctx context.Context, prefix, token string, maxKeys int32) (ListPage, error) {
	in := &s3.ListObjectsV2Input{
		Bucket:  aws.String(st.bucket),
		Prefix:  aws.String(prefix),
		MaxKeys: aws.Int32(maxKeys),
	}
	if token != "" {
		in.ContinuationToken = aws.String(token)
	}
	out, err := st.client.ListObjectsV2(ctx, in)
	if err != nil {
		return ListPage{}, err
	}
	page := ListPage{Objects: make([]Object, 0, len(out.Contents))}
	for _, o := range out.Contents {
		obj := Object{Key: aws.ToString(o.Key), Size: aws.ToInt64(o.Size)}
		if o.LastModified != nil {
			obj.LastModified = o.LastModified.UTC()
		}
		page.Objects = append(page.Objects, obj)
	}
	if aws.ToBool(out.IsTruncated) {
		page.NextToken = aws.ToString(out.NextContinuationToken)
	}
	return page, nil
}

func (st *s3Store) Get(ctx context.Context, key string, maxBytes int64) ([]byte, error) {
	in := &s3.GetObjectInput{Bucket: aws.String(st.bucket), Key: aws.String(key)}
	limit := int64(MaxObjectBytes)
	if maxBytes > 0 {
		in.Range = aws.String(fmt.Sprintf("bytes=0-%d", maxBytes-1))
		limit = maxBytes
	}
	out, err := st.client.GetObject(ctx, in)
	if err != nil {
		return nil, mapGetError(err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(io.LimitReader(out.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		if maxBytes > 0 {
			return data[:limit], nil
		}
		return nil, ErrTooLarge
	}
	return data, nil
}

func mapGetError(err error) error {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "InvalidRange":
			return ErrInvalidRange
		case "NoSuchKey":
			return ErrNoSuchKey
		}
	}
	return err
}

// Open streams a whole object.
func (st *s3Store) Open(ctx context.Context, key string) (*ObjectStream, error) {
	out, err := st.client.GetObject(ctx, &s3.GetObjectInput{Bucket: aws.String(st.bucket), Key: aws.String(key)})
	if err != nil {
		return nil, mapGetError(err)
	}
	return &ObjectStream{Body: out.Body, Size: aws.ToInt64(out.ContentLength), ContentType: aws.ToString(out.ContentType)}, nil
}
