package oss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"testing"
)

const (
	ossKey = "1-2-3"
	ossUse = OSS
)

var ctx = context.Background()
var bs = []byte("this is another minus test only")

var o = New(ossUse, &Config{
	Prefix:    "",
	Signature: V4, // 注意: obs不支持v4签名算法!
	StorageConfig: StorageConfig{
		Access: "***",
		Secret: "***",
		Region: "cn-shenzhen",
		Bucket: "hezhaowu",
		Domain: "hezhaowu.oss-cn-shenzhen.aliyuncs.com",
	},
	ClientConfig: ClientConfig{
		InsecureSkipVerify: true, // 自定义证书必须跳过CA验证!
	},
})

func TestPutObjectData(t *testing.T) {
	err := o.PutObjectData(ctx, ossKey, bs)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PutObjectData success: %v\n", ossKey)
}

func TestPutObject(t *testing.T) {
	err := o.PutObject(ctx, ossKey, -1, bytes.NewReader(bs))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PutObject success: %v\n", ossKey)
}

func TestGetObject(t *testing.T) {
	ln, rc, err := o.GetObject(ctx, ossKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	fmt.Println(ln)
	io.Copy(os.Stdout, rc)
	fmt.Println()
}

func TestGetObjectLink(t *testing.T) {
	fmt.Println(o.GetObjectLink(ctx, ossKey, 180))
}

func TestHasObject(t *testing.T) {
	fmt.Println(o.HasObject(ctx, ossKey))
}

func TestDeleteObject(t *testing.T) {
	fmt.Println(o.DeleteObject(ctx, ossKey))
}

func TestPutObjectMultipart(t *testing.T) {
	uploadId, err := o.InitiateMultipartUpload(ctx, ossKey)
	if err != nil {
		t.Fatal(err)
	}
	etag, err := o.UploadPart(ctx, ossKey, uploadId, 1, bs)
	if err != nil {
		t.Fatal(err)
	}
	err = o.CompleteMultipartUpload(ctx, ossKey, uploadId, []*Part{
		{PartNumber: 1, ETag: etag},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PutObjectMultipart success: %v\n", ossKey)
}
