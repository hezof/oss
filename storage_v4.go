package oss

import (
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

type storageV4 struct {
	prefix   string
	config   *StorageConfig
	profile  *Profile
	secret   []byte
	region   []byte
	service  []byte
	boundary []byte
}

func NewStorageV4(prefix string, c *StorageConfig, p *Profile) Storage {
	s := new(storageV4)
	s.prefix = prefix
	s.config = c
	s.profile = p
	s.secret = []byte(p.V4Code + c.Secret)
	s.region = []byte(c.Region)
	s.service = []byte(p.V4Service)
	s.boundary = []byte(p.V4Boundary)
	return s
}

func (c storageV4) Url(ctx *ProviderContext) string {
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

func (c storageV4) Link(ctx *ProviderContext, expires string, signature string) string {
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
	bf.WriteString(c.profile.V4QueryParams.Signature)
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

func (c storageV4) Header(ctx *ProviderContext, signature string, signedScope string, signedHeaders string) map[string]string {
	var ret = make(map[string]string)
	for _, v := range ctx.SignedHeaders.values {
		if v.Name == headerHost {
			ret["Host"] = v.Text
		} else {
			ret[v.Name] = v.Text
		}
	}
	if ctx.Range.Start != 0 || ctx.Range.End != 0 {
		ret[headerRange] = ctx.Range.Value()
	}

	// 排序后将名称串起来
	/*
		Authorization: <algorithm> Credential=<ak>/<credential_scope>, SignedHeaders=<SignedHeaders>, Signature=<signature>
	*/
	bf := borrowBuffer()
	defer returnBuffer(bf)

	bf.WriteString(c.profile.V4Algorithm)
	bf.WriteString(" Credential=")
	bf.WriteString(c.config.Access)
	bf.WriteString("/")
	bf.WriteString(signedScope)
	if c.profile.SignedHostHeader {
		// 阿里云是SignedHeaders里面的AdditionalHeaders
		bf.WriteString(", SignedHeaders=")
		bf.WriteString(signedHeaders)
	}
	bf.WriteString(", Signature=")
	bf.WriteString(signature)
	ret[headerAuthorization] = bf.String()

	return ret
}

/*
Signature
V4签名必须注意
# 签名必需的header头
- Content-GlobalType
- x-kss-content-sha256
# 签名前必须将header小写升序, 同时生成signedHeaders
# 签名前必须将query小写升序
# 签名前必须计算scope: date(YYYYMMDD)/region/service/boundary
*/
func (c storageV4) Signature(ctx *ProviderContext, datetime string, signedScope string, signedHeaders string) (signature string) {

	// 重用buffer
	bf := borrowBuffer()
	defer returnBuffer(bf)

	/*
		CanonicalRequest = HTTPRequestMethod + '\n'
				+ CanonicalURI + '\n'
				+ CanonicalQueryString + '\n'
				+ CanonicalHeaders + '\n'
				+ SignedHeaders + '\n'
				+ ContentSHA256
	*/
	// 重置清零
	bf.WriteString(ctx.Method)
	bf.WriteByte('\n')
	if c.profile.SignedBucketURI {
		bf.WriteByte('/')
		bf.WriteString(c.config.Bucket)
	}
	bf.WriteByte('/')
	bf.WriteString(ctx.ObjectKey)
	bf.WriteByte('\n')
	if ctx.SignedQueries.Len() > 0 {
		for i, v := range ctx.SignedQueries.SortedValues() {
			if i > 0 {
				bf.WriteByte('&')
			}
			bf.WriteString(url.PathEscape(v.Name))
			bf.WriteByte('=')
			bf.WriteString(url.PathEscape(v.Text))
		}
	}
	bf.WriteByte('\n')
	for _, v := range ctx.SignedHeaders.SortedValues() {
		bf.WriteString(v.Name)
		bf.WriteByte(':')
		bf.WriteString(v.Text)
		bf.WriteByte('\n')
	}
	bf.WriteByte('\n')
	bf.WriteString(signedHeaders)
	bf.WriteByte('\n')
	bf.WriteString(contentSha256UnsignedPayload)

	// 计算CanonicalRequest的Sha256
	reqSha256Hex := hex.EncodeToString(Sha256(bf.Bytes()))

	/*
		StringToSign =
		    Algorithm + \n +
		    RequestDateTime + \n +
		    CredentialScope + \n +
		    Hex（SHA256HASH(CanonicalRequest)
	*/
	// 重置清零
	bf.Reset()
	bf.WriteString(c.profile.V4Algorithm)
	bf.WriteByte('\n')
	bf.WriteString(datetime) // YYYYMMDD’T’HHMMSS’Z’
	bf.WriteByte('\n')
	bf.WriteString(signedScope)
	bf.WriteByte('\n')
	bf.WriteString(reqSha256Hex)
	/*
		kSecret = your Access Key
		kDate = HMAC("KSS4" + kSecret, Date)
		kRegion = HMAC(kDate, Region)
		kService = HMAC(kRegion, Storage)
		kSigning = HMAC(kService, "kss4_request")
	*/
	kSecret := c.secret
	kDate := HmacSha256(kSecret, UnsafeBytes(datetime[0:8])) // 注意: 该处是date非datetime
	kRegion := HmacSha256(kDate, c.region)
	kService := HmacSha256(kRegion, c.service)
	kSigning := HmacSha256(kService, c.boundary)

	/*
		HMAC-SHA256(SigningKey, StringToSign)
	*/
	kResult := HmacSha256(kSigning, bf.Bytes())
	signature = hex.EncodeToString(kResult)
	return
}

func (c storageV4) signedScope(datetime string) string {
	bf := borrowBuffer()
	defer returnBuffer(bf)
	bf.Grow(64)
	bf.WriteString(datetime[0:8]) // 必须是YYYYMMDD’T’HHMMSS’Z’
	bf.WriteByte('/')
	bf.Write(c.region)
	bf.WriteByte('/')
	bf.Write(c.service)
	bf.WriteByte('/')
	bf.Write(c.boundary)
	return bf.String()
}

func (c storageV4) signedHeaders(ctx *ProviderContext, contentSha256Need bool) string {

	// 添加必需的header
	if ctx.ContentType != "" {
		ctx.SignedHeaders.Add(headerContentType, ctx.ContentType)
	}
	if ctx.ContentMD5 != "" {
		ctx.SignedHeaders.Add(headerContentMD5, ctx.ContentMD5)
	}
	// 约定所有都是UNSIGNED-PAYLOAD
	if contentSha256Need {
		ctx.SignedHeaders.Add(c.profile.ContentSHA256Header, contentSha256UnsignedPayload)
	}

	// 根据profile决定是否签名Host(阿里云比较特殊)
	if c.profile.SignedHostHeader {

		ctx.SignedHeaders.Add(headerHost, c.config.Domain)

		// 排序后将名称串起来
		bf := borrowBuffer()
		defer returnBuffer(bf)

		for i, v := range ctx.SignedHeaders.SortedValues() {
			if i > 0 {
				bf.WriteByte(';')
			}
			bf.WriteString(v.Name)
		}
		return bf.String()
	}

	return ""
}

func (c storageV4) PutObject(key string, contentMD5 string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)
	for k, v := range c.profile.StorageHeaders {
		ctx.SignedHeaders.Add(k, v)
	}

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) HeadObject(key string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) GetObject(key string, _range *Range) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) GetObjectLink(key string, timeout int64) string {

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

	// 2.添加Date及profile的设置.其中Date使用profile定义的名称
	iso := ctx.UTC.Format(isoDateTime)
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, false)

	ctx.SignedQueries.Add(c.profile.V4QueryParams.Algorithm, c.profile.V4Algorithm)
	ctx.SignedQueries.Add(c.profile.V4QueryParams.Credential, c.config.Access+"/"+signedScope)
	ctx.SignedQueries.Add(c.profile.V4QueryParams.Date, iso)
	ctx.SignedQueries.Add(c.profile.V4QueryParams.Expires, strconv.FormatInt(timeout, 10))
	if c.profile.SignedHostHeader {
		ctx.SignedQueries.Add(c.profile.V4QueryParams.SignedHeaders, signedHeaders)
	}

	// 3.计算signedScope, signedHeaders, signature
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return c.Link(ctx, "", signature)
}

func (c storageV4) DeleteObject(key string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) InitiateMultipartUpload(key string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)
	for k, v := range c.profile.StorageHeaders {
		ctx.SignedHeaders.Add(k, v)
	}
	// 阿里云签名对于无值参数不需"=", 金山云签名对于无值参数需要"=". 这里带上"1"兼容二边的签名!
	ctx.SignedQueries.Add("uploads", "1")

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) UploadPart(key string, uploadId string, partNumber int, contentMD5 string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)
	ctx.SignedQueries.Add("partNumber", strconv.Itoa(partNumber))
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) CompleteMultipartUpload(key string, uploadId string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

func (c storageV4) AbortMultipartUpload(key string, uploadId string) *RequestSetting {

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
	iso := ctx.UTC.Format(isoDateTime)
	ctx.SignedHeaders.Add(c.profile.DateHeader, iso)
	ctx.SignedQueries.Add("uploadId", uploadId)

	// 3.计算signedScope, signedHeaders, signature
	signedScope := c.signedScope(iso)
	signedHeaders := c.signedHeaders(ctx, true)
	signature := c.Signature(ctx, iso, signedScope, signedHeaders)

	// 4.组装request
	return &RequestSetting{
		Method: ctx.Method,
		Status: ctx.Status,
		Url:    c.Url(ctx),
		Header: c.Header(ctx, signature, signedScope, signedHeaders),
	}
}

var _ SignatureV4 = (*storageV4)(nil)
var _ Storage = (*storageV4)(nil)
