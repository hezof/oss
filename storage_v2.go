package oss

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type storageV2 struct {
	prefix  string
	config  *StorageConfig
	profile *Profile
	secret  []byte
}

func NewStorageV2(prefix string, c *StorageConfig, p *Profile) Storage {
	s := new(storageV2)
	s.prefix = prefix
	s.config = c
	s.profile = p
	s.secret = []byte(c.Secret)
	return s
}

func (c storageV2) Url(ctx *ProviderContext) string {
	// 重用buffer
	bf := borrowBuffer()
	defer returnBuffer(bf)

	// 拼接结果
	bf.WriteString(c.profile.Schema)
	bf.WriteString("://")
	bf.WriteString(c.config.Domain)
	bf.WriteByte('/')
	if c.profile.AccessBucketURI {
		bf.WriteString(c.config.Bucket)
		bf.WriteByte('/')
	}
	bf.WriteString(ctx.ObjectKey)
	if ctx.SignedQueries.Len() > 0 {
		bf.WriteByte('?')
		for i, v := range ctx.SignedQueries.values {
			if i > 0 {
				bf.WriteByte('&')
			}
			bf.WriteString(v.Name)
			if v.Text != "" {
				bf.WriteByte('=')
				bf.WriteString(v.Text) // 在此项目所有参数不用escape!!!
			}
		}
	}
	return bf.String()
}

func (c storageV2) Link(ctx *ProviderContext, expires, signature string) string {
	// 重用buffer
	bf := borrowBuffer()
	defer returnBuffer(bf)

	// 拼接结果
	bf.WriteString(c.profile.Schema)
	bf.WriteString("://")
	bf.WriteString(c.config.Domain)
	bf.WriteByte('/')
	if c.profile.AccessBucketURI {
		bf.WriteString(c.config.Bucket)
		bf.WriteByte('/')
	}
	bf.WriteString(ctx.ObjectKey)
	bf.WriteByte('?')
	bf.WriteString(c.profile.V2QueryParams.AccessKeyId)
	bf.WriteByte('=')
	bf.WriteString(url.QueryEscape(c.config.Access))
	bf.WriteByte('&')
	bf.WriteString(c.profile.V2QueryParams.Expires)
	bf.WriteByte('=')
	bf.WriteString(expires)
	bf.WriteByte('&')
	bf.WriteString(c.profile.V2QueryParams.Signature)
	bf.WriteByte('=')
	bf.WriteString(url.QueryEscape(signature))
	for _, v := range ctx.SignedQueries.values {
		bf.WriteByte('&')
		bf.WriteString(v.Name)
		if v.Text != "" {
			bf.WriteByte('=')
			bf.WriteString(url.QueryEscape(v.Text))
		}
	}
	return bf.String()
}

func (c storageV2) Header(ctx *ProviderContext, signature string) map[string]string {
	var ret = make(map[string]string)
	for _, v := range ctx.SignedHeaders.values {
		// 需要将host转为Host, 否则直设Header会出现Host与host二个头
		if v.Name == headerHost {
			ret["Host"] = v.Text
		} else {
			ret[v.Name] = v.Text
		}
	}
	if ctx.Range.Start != 0 || ctx.Range.End != 0 {
		ret[headerRange] = ctx.Range.Value()
	}
	if ctx.ContentType != "" {
		ret[headerContentType] = ctx.ContentType
	}
	if ctx.ContentMD5 != "" {
		ret[headerContentMD5] = ctx.ContentMD5
	}
	ret[headerAuthorization] = c.profile.V2Code + " " + c.config.Access + ":" + signature
	return ret
}

func (c storageV2) Signature(ctx *ProviderContext, date string) string {
	// 重用buffer
	bf := borrowBuffer()
	defer returnBuffer(bf)

	/*
		StringToSign = HTTP-Verb + "\n" +
			Content-MD5 + "\n" +
			Content-GlobalType + "\n" +
			DateHeader + "\n" +
			CanonicalizedKssHeaders+
			CanonicalizedResource;
	*/
	bf.WriteString(ctx.Method)
	bf.WriteByte('\n')
	bf.WriteString(ctx.ContentMD5)
	bf.WriteByte('\n')
	bf.WriteString(ctx.ContentType)
	bf.WriteByte('\n')
	bf.WriteString(date)
	bf.WriteByte('\n')
	for _, v := range ctx.SignedHeaders.SortedValues() {
		bf.WriteString(v.Name)
		bf.WriteByte(':')
		bf.WriteString(v.Text)
		bf.WriteByte('\n')
	}
	bf.WriteByte('/')
	bf.WriteString(c.config.Bucket)
	bf.WriteByte('/')
	bf.WriteString(ctx.ObjectKey)
	if ctx.SignedQueries.Len() > 0 {
		for i, v := range ctx.SignedQueries.SortedValues() {
			if i > 0 {
				bf.WriteByte('&')
			} else {
				bf.WriteByte('?')
			}
			bf.WriteString(url.PathEscape(v.Name))
			if v.Text != "" {
				bf.WriteByte('=')
				bf.WriteString(url.PathEscape(v.Text))
			}
		}
	}

	/*
		Signature = Base64(HMAC-SHA1(YourSecretKey, UTF-8-Encoding-Of( StringToSign ) ) );
	*/
	signature := base64.StdEncoding.EncodeToString(HmacSha1(c.secret, bf.Bytes()))

	return signature
}

func (c storageV2) PutObject(key string, contentMD5 string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}
	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodPut
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK
	ctx.ContentMD5 = contentMD5
	ctx.ContentType = c.config.ContentType

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)
	for k, v := range c.profile.StorageHeaders {
		ctx.SignedHeaders.Add(k, v)
	}

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.返回request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) HeadObject(key string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodHead
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) GetObject(key string, _range *Range) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodGet
	ctx.ObjectKey = key
	if _range != nil && (_range.Start != 0 || _range.End != 0) {
		ctx.Status = http.StatusPartialContent
		ctx.Range.Start = _range.Start
		ctx.Range.End = _range.End
	} else {
		ctx.Status = http.StatusOK
	}

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) GetObjectLink(key string, timeout int64) string {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodGet
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK

	exptime := ctx.UTC.Add(time.Duration(timeout) * time.Second)
	expires := strconv.FormatInt(exptime.Unix(), 10)

	// 3.计算signature
	signature := c.Signature(ctx, expires)

	// 4.组装request
	return c.Link(ctx, expires, signature)
}

func (c storageV2) DeleteObject(key string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodDelete
	ctx.ObjectKey = key
	ctx.Status = http.StatusNoContent

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) InitiateMultipartUpload(key string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodPost
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)
	for k, v := range c.profile.StorageHeaders {
		ctx.SignedHeaders.Add(k, v)
	}
	// 阿里云签名对于无值参数不需"=", 金山云签名对于无值参数需要"=". 这里带上"1"兼容二边的签名!
	ctx.SignedQueries.Add("uploads", "1")

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) UploadPart(key string, uploadId string, partNumber int, contentMD5 string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodPut
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK
	ctx.ContentMD5 = contentMD5
	ctx.ContentType = c.config.ContentType

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)
	ctx.SignedQueries.Add("partNumber", strconv.Itoa(partNumber))
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) CompleteMultipartUpload(key string, uploadId string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodPost
	ctx.ObjectKey = key
	ctx.Status = http.StatusOK

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

func (c storageV2) AbortMultipartUpload(key string, uploadId string) *RequestSetting {
	if c.prefix != "" {
		key = c.prefix + key
	}

	ctx := borrowContext()
	defer returnContext(ctx)

	// 1.初始(重置)context
	ctx.UTC = time.Now().UTC()
	ctx.Method = http.MethodDelete
	ctx.ObjectKey = key
	ctx.Status = http.StatusNoContent

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	gmt := ctx.UTC.Format(gmtDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, gmt)
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signature(是否签名Date由profile决定)
	signature := c.Signature(ctx, If(c.profile.SignedDateHeader, gmt, ""))

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature),
	}
}

var _ SignatureV2 = (*storageV2)(nil)
var _ Storage = (*storageV2)(nil)
