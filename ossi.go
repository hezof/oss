package oss

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

/*================================*\
	OSS统一接口
\*================================*/

type OSSI interface {
	DeleteObject(ctx context.Context, ossKey string) error
	HasObject(ctx context.Context, ossKey string) (bool, error)
	GetObject(ctx context.Context, ossKey string, _range *Range) (int64, io.ReadCloser, error)
	GetObjectLink(ctx context.Context, ossKey string, expires int64) string
	PutObjectData(ctx context.Context, ossKey string, data []byte) error
	PutObject(ctx context.Context, ossKey string, contentLength int64, content io.Reader) error
	InitiateMultipartUpload(c context.Context, ossKey string) (string, error)
	UploadPart(c context.Context, ossKey string, uploadId string, partNumber int, data []byte) (string, error)
	AbortMultipartUpload(c context.Context, ossKey string, uploadId string) error
	CompleteMultipartUpload(c context.Context, ossKey string, uploadId string, parts []*Part) error
}

type ossiImpl struct {
	use     string
	storage Storage
	client  *http.Client
}

func New(use string, config *Config) OSSI {
	if config.ContentType == "" {
		// 设置默认内容类型为二进制流
		config.ContentType = contentTypeApplicationOctetStream
	}
	return &ossiImpl{
		use:     use,
		storage: signatures[config.Signature](config.Prefix, &config.StorageConfig, profiles[use]),
		client:  NewClient(&config.ClientConfig),
	}
}

/*
DeleteObject 从oss删除对象
*/
func (o *ossiImpl) DeleteObject(ctx context.Context, ossKey string) error {
	set := o.storage.DeleteObject(ossKey)
	req, err := http.NewRequestWithContext(ctx, set.Method, set.Url, nil)
	if err != nil {
		return err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = 0

	rsp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer discardResponseBody(rsp)
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return invalidStatusError(rsp)
	}
	return nil
}

func (o *ossiImpl) HasObject(ctx context.Context, ossKey string) (bool, error) {
	set := o.storage.HeadObject(ossKey)
	req, err := http.NewRequestWithContext(ctx, set.Method, set.Url, nil)
	if err != nil {
		return false, err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = 0

	rsp, err := o.client.Do(req)
	if err != nil {
		return false, err
	}
	defer discardResponseBody(rsp)
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != http.StatusNotFound && rsp.StatusCode != set.Status {
		return false, invalidStatusError(rsp)
	}
	return rsp.StatusCode == http.StatusOK, nil
}

/*
GetObject 下载对象(或部分)
*/
func (o *ossiImpl) GetObject(ctx context.Context, ossKey string, _range *Range) (int64, io.ReadCloser, error) {
	set := o.storage.GetObject(ossKey, _range)
	req, err := http.NewRequestWithContext(ctx, set.Method, set.Url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = 0

	rsp, err := o.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		defer discardResponseBody(rsp)
		return 0, nil, invalidStatusError(rsp)
	}

	return rsp.ContentLength, rsp.Body, nil
}

func (o *ossiImpl) GetObjectLink(ctx context.Context, ossKey string, expires int64) string {
	return o.storage.GetObjectLink(ossKey, expires)
}

/*
PutObjectData 上传对象数据
*/
func (o *ossiImpl) PutObjectData(ctx context.Context, ossKey string, data []byte) error {
	set := o.storage.PutObject(ossKey, "") // 不要求服务端hash校验
	req, err := http.NewRequestWithContext(ctx, set.Method, set.Url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	for k, v := range set.Header {
		// 注意:使用Header.Set()会将header name标准化
		req.Header[k] = []string{v}
	}
	req.ContentLength = int64(len(data))

	rsp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer discardResponseBody(rsp)

	// 断言状态
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return invalidStatusError(rsp)
	}
	return nil
}

/*
PutObject 上传对象
*/
func (o *ossiImpl) PutObject(ctx context.Context, ossKey string, contentLength int64, content io.Reader) error {
	set := o.storage.PutObject(ossKey, "") // 不要求服务端hash校验
	req, err := http.NewRequestWithContext(ctx, set.Method, set.Url, content)
	if err != nil {
		return err
	}
	for k, v := range set.Header {
		// 注意:使用Header.Set()会将header name标准化
		req.Header[k] = []string{v}
	}
	if contentLength < 0 {
		// 采用chunked方式上传
		req.Header[TransferEncoding] = TransferEncodingChunked
	} else {
		req.ContentLength = contentLength
	}

	rsp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer discardResponseBody(rsp)

	// 断言状态
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return invalidStatusError(rsp)
	}
	return nil
}

func (o *ossiImpl) InitiateMultipartUpload(c context.Context, ossKey string) (string, error) {
	set := o.storage.InitiateMultipartUpload(ossKey)
	req, err := http.NewRequestWithContext(c, set.Method, set.Url, nil)
	if err != nil {
		return "", err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = 0

	rsp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer discardResponseBody(rsp)

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return "", invalidStatusError(rsp)
	}
	uploadId, err := ExtractMultipartUploadId(rsp)
	if err != nil {
		return "", err
	}
	return uploadId, nil
}

func (o *ossiImpl) UploadPart(c context.Context, ossKey string, uploadId string, partNumber int, data []byte) (string, error) {

	set := o.storage.UploadPart(ossKey, uploadId, partNumber, "")
	req, err := http.NewRequestWithContext(c, set.Method, set.Url, bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = int64(len(data))

	rsp, err := o.client.Do(req)
	if err != nil {
		return "", err
	}
	defer discardResponseBody(rsp)
	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return "", invalidStatusError(rsp)
	}

	return ExtractMultipartUploadETag(rsp)
}

func (o *ossiImpl) AbortMultipartUpload(c context.Context, ossKey string, uploadId string) error {

	set := o.storage.AbortMultipartUpload(ossKey, uploadId)
	req, err := http.NewRequestWithContext(c, set.Method, set.Url, nil)
	if err != nil {
		return err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = 0

	rsp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer discardResponseBody(rsp)

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return invalidStatusError(rsp)
	}
	return nil
}

func (o *ossiImpl) CompleteMultipartUpload(c context.Context, ossKey string, uploadId string, parts []*Part) error {

	set := o.storage.CompleteMultipartUpload(ossKey, uploadId)

	buf := borrowBuffer()
	defer returnBuffer(buf)

	err := CompleteMultipartUploadParts(buf, parts)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(c, set.Method, set.Url, buf)
	if err != nil {
		return err
	}
	for k, v := range set.Header {
		req.Header[k] = []string{v}
	}
	req.ContentLength = int64(buf.Len())

	rsp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer discardResponseBody(rsp)

	if rsp.StatusCode != http.StatusOK && rsp.StatusCode != set.Status {
		return invalidStatusError(rsp)
	}
	return nil
}

/*=================================*\
	非法状态错误
\*=================================*/

func invalidStatusError(rsp *http.Response) error {
	buf := borrowBuffer()
	defer returnBuffer(buf)
	buf.ReadFrom(rsp.Body)
	return fmt.Errorf("invalid status(%v): %s", rsp.StatusCode, buf.Bytes())
}

var discardBuffer = make([]byte, 2048)

func discardResponseBody(rsp *http.Response) {
	for {
		n, err := rsp.Body.Read(discardBuffer)
		if n == 0 && err != nil {
			break
		}
	}
	rsp.Body.Close()
}
