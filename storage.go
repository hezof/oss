package oss

// SignatureV2 签名接口
type SignatureV2 interface {
	Url(ctx *ProviderContext) string                                 // url,封装通过query发送签名信息
	Header(ctx *ProviderContext, signature string) map[string]string // header,封闭通过header发送签名信息
	Signature(ctx *ProviderContext, date string) string              // 签名算法实现(不用policy)
}

// SignatureV4 签名接口
type SignatureV4 interface {
	Url(ctx *ProviderContext) string                                                                           // url,封装通过query发送签名信息
	Header(ctx *ProviderContext, signature string, signedScope string, signedHeaders string) map[string]string // header,封闭通过header发送签名信息
	Signature(ctx *ProviderContext, datetime string, signedScope string, signedHeaders string) string          // 签名算法实现(不用policy) 	// 签名算法实现(使用policy)
	Link(ctx *ProviderContext, expires, signature string) string                                               // 生成下载外链
}

// Storage 用于邮箱服务的OSS提供者接口(是标准OSS接口子集)
type Storage interface {
	// PutObject V2的hash是Content-MD5, V4的hash是Content-SHA256
	HeadObject(key string) *RequestSetting
	PutObject(key string, contentMD5 string) *RequestSetting
	GetObject(key string, _range *Range) *RequestSetting
	GetObjectLink(key string, timeout int64) string
	DeleteObject(key string) *RequestSetting
	InitiateMultipartUpload(key string) *RequestSetting
	// UploadPart V2的hash是Content-MD5, V4的hash是Content-SHA256
	UploadPart(key string, uploadId string, partNumber int, contentMD5 string) *RequestSetting
	CompleteMultipartUpload(key string, uploadId string) *RequestSetting
	AbortMultipartUpload(key string, uploadId string) *RequestSetting
}

// RequestSetting Http请求设置
type RequestSetting struct {
	Status int               `json:"expect,omitempty"` // 预期返回的http-Status
	Method string            `json:"Method,omitempty"` // http Method
	Url    string            `json:"url,omitempty"`    // http url
	Header map[string]string `json:"header,omitempty"` // http header
}
