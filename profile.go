package oss

const (
	schemaHttp  = "http"
	schemaHttps = "https"
)

// Profile 各家云商自己实现部分
type Profile struct {
	V2Code              string            // 在V2用作Authentication的前缀
	V4Code              string            // 在V4用作secret的前缀
	V4Service           string            // 在V4用作服务名称
	V4Algorithm         string            // 在V4用作算法名称
	V4Boundary          string            // 在V4用作边界标志
	Schema              string            // endpoint 地址 schema, http 或者 https
	AccessBucketURI     bool              // 访问URI携带bucket
	SignedBucketURI     bool              // 签名URI携带bucket
	SignedHostHeader    bool              // 在V4是否将Host加入StringToSign
	SignedDateHeader    bool              // 在V2是否将Date加入StringToSign
	DateHeader          string            // 在V2和V4用于代替Date的header名称(小写)
	ContentSHA256Header string            // 在V2和V4用于Content-Sha256的header名称(小写)
	StorageHeaders      map[string]string // 在V2和V4上传对象存储设置,用于PutObject或MultipartUpload等上传header设置
	V2QueryParams       V2QueryParams     // 在V2用作Query参数名称
	V4QueryParams       V4QueryParams     // 在V4用作Query参数名称
}

type V2QueryParams struct {
	AccessKeyId string // AccessKeyId的参数名称
	Expires     string // Expires的参数名称
	Signature   string // Signature的参数名称
}

type V4QueryParams struct {
	Algorithm     string
	Credential    string
	Date          string
	Expires       string
	SignedHeaders string
	Signature     string
}

// ProfileKS3 KS3配置
var ProfileKS3 = &Profile{
	V2Code:              "KSS",
	V4Code:              "KSS4",
	V4Service:           "ks3",
	V4Algorithm:         "KSS4-HMAC-SHA256",
	V4Boundary:          "kss4_request",
	Schema:              schemaHttps,
	AccessBucketURI:     false,
	SignedBucketURI:     false,
	SignedHostHeader:    true,
	SignedDateHeader:    true, // KS3需要将Date加到StringToSign
	DateHeader:          "x-kss-date",
	ContentSHA256Header: "x-kss-content-sha256",
	StorageHeaders: map[string]string{
		"x-kss-server-side-encryption": "AES256",
		"x-kss-acl":                    "private",
		"x-kss-auto-compress":          "true",
	},
	V2QueryParams: V2QueryParams{
		AccessKeyId: "KSSAccessKeyId",
		Expires:     "Expires",
		Signature:   "Signature",
	},
	V4QueryParams: V4QueryParams{
		Algorithm:     "X-Kss-Algorithm",
		Credential:    "X-Kss-Credential",
		Date:          "X-Kss-Date",
		Expires:       "X-Kss-Expires",
		SignedHeaders: "X-Kss-SignedHeaders",
		Signature:     "X-Kss-Signature",
	},
}

// ProfileOBS OBS官档没有V4的详细介绍
var ProfileOBS = &Profile{
	V2Code:              "OBS",
	V4Code:              "OBS4",
	V4Service:           "obs",
	V4Algorithm:         "OBS4-HMAC-SHA256",
	V4Boundary:          "obs4_request",
	Schema:              schemaHttps,
	AccessBucketURI:     false,
	SignedBucketURI:     false,
	SignedHostHeader:    true,
	SignedDateHeader:    false, // 当存在x-obs-date时,Date参数按照空字符串处理!
	DateHeader:          "x-obs-date",
	ContentSHA256Header: "x-obs-content-sha256",
	StorageHeaders: map[string]string{
		"x-obs-server-side-encryption": "AES256",
		"x-obs-acl":                    "private",
	},
	V2QueryParams: V2QueryParams{
		AccessKeyId: "AccessKeyId",
		Expires:     "Expires",
		Signature:   "Signature",
	},
	V4QueryParams: V4QueryParams{
		Algorithm:     "X-Obs-Algorithm",
		Credential:    "X-Obs-Credential",
		Date:          "X-Obs-Date",
		Expires:       "X-Obs-Expires",
		SignedHeaders: "X-Obs-SignedHeaders",
		Signature:     "X-Obs-Signature",
	},
}

// ProfileAWS AWS配置
var ProfileAWS = &Profile{
	V2Code:              "AWS",
	V4Code:              "AWS4",
	V4Service:           "s3",
	V4Algorithm:         "AWS4-HMAC-SHA256",
	V4Boundary:          "aws4_request",
	Schema:              schemaHttps,
	AccessBucketURI:     false,
	SignedBucketURI:     false,
	SignedHostHeader:    true,
	SignedDateHeader:    true, // 需要将Date加到StringToSign
	DateHeader:          "x-amz-date",
	ContentSHA256Header: "x-amz-content-sha256",
	StorageHeaders: map[string]string{
		"x-amz-server-side-encryption": "AES256",
		"x-amz-acl":                    "private",
	},
	V2QueryParams: V2QueryParams{
		AccessKeyId: "AWSAccessKeyId",
		Expires:     "Expires",
		Signature:   "Signature",
	},
	V4QueryParams: V4QueryParams{
		Algorithm:     "X-Amz-Algorithm",
		Credential:    "X-Amz-Credential",
		Date:          "X-Amz-Date",
		Expires:       "X-Amz-Expires",
		SignedHeaders: "X-Amz-SignedHeaders",
		Signature:     "X-Amz-Signature",
	},
}

// ProfileAWS Minio配置
var ProfileMINIO = &Profile{
	V2Code:              "AWS",
	V4Code:              "AWS4",
	V4Service:           "s3",
	V4Algorithm:         "AWS4-HMAC-SHA256",
	V4Boundary:          "aws4_request",
	Schema:              schemaHttps,
	AccessBucketURI:     false,
	SignedBucketURI:     false,
	SignedHostHeader:    true,
	SignedDateHeader:    true, // 需要将Date加到StringToSign
	DateHeader:          "x-amz-date",
	ContentSHA256Header: "x-amz-content-sha256",
	StorageHeaders: map[string]string{
		//"x-amz-server-side-encryption": "AES256", // 无法支持加密
		"x-amz-acl": "private",
	},
	V2QueryParams: V2QueryParams{
		AccessKeyId: "AWSAccessKeyId",
		Expires:     "Expires",
		Signature:   "Signature",
	},
	V4QueryParams: V4QueryParams{
		Algorithm:     "X-Amz-Algorithm",
		Credential:    "X-Amz-Credential",
		Date:          "X-Amz-Date",
		Expires:       "X-Amz-Expires",
		SignedHeaders: "X-Amz-SignedHeaders",
		Signature:     "X-Amz-Signature",
	},
}

// ProfileOSS 阿里云OSS(不支持V2)
var ProfileOSS = &Profile{
	V2Code:              "OSS",
	V4Code:              "aliyun_v4",
	V4Service:           "oss",
	V4Algorithm:         "OSS4-HMAC-SHA256",
	V4Boundary:          "aliyun_v4_request",
	Schema:              schemaHttps,
	AccessBucketURI:     false,
	SignedBucketURI:     true,
	SignedHostHeader:    false,
	DateHeader:          "x-oss-date",
	SignedDateHeader:    false, // 当存在x-obs-date时,Date参数按照空字符串处理!
	ContentSHA256Header: "x-oss-content-sha256",
	StorageHeaders: map[string]string{
		"x-oss-server-side-encryption": "AES256",
		"x-oss-acl":                    "private",
	},
	V2QueryParams: V2QueryParams{
		AccessKeyId: "AccessKeyId",
		Expires:     "Expires",
		Signature:   "Signature",
	},
	V4QueryParams: V4QueryParams{
		Algorithm:     "X-Oss-Signature-Version",
		Credential:    "X-Oss-Credential",
		Date:          "X-Oss-Date",
		Expires:       "X-Oss-Expires",
		SignedHeaders: "X-Oss-Signed-headers",
		Signature:     "X-Oss-Signature",
	},
}
