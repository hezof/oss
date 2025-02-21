# oss

统一对象存储接口, 支持在各主要云厂间切换或互备!

## 简单开始

### API内容:

1. OSSI统一对象存储接口
2. Storage存储读写接口
3. Profile云厂配置接口, 目前支持:
    - 金山云对象存储(KS3)
    - 华为云对象存储(OBS)
    - 亚马逊对象存储(AWS)
    - minio对象存储(MINIO)
    - 阿里云对象存储(OSS)
    - 腾讯云对象存储(COS)[TODO]

### API使用

1. 创建OSS实例
    - 指定前缀. 前缀相当目录路径, 自动拼接在Object Key前面.
    - 指定所用云厂(KS3, OBS, AWS, MINIO, OSS, COS)
    - 指定签名版本(V2,V4). 注意: OBS可能不支持V4, MINIO可能不支持V2....
    - 指定存储配置(AccessKey, SecretKey, Region, Bucket, Domain)
    - 指定客户端配置. http.Client的细分配置!
2. 执行对象操作(PUT/GET/DELETE/POST/HEAD)
    - 详见Storage接口.

### API示例

简单示例:

```
const (
	ossKey = "1111-2222-3333"
	ossUse = "ks3"
)

var ctx = context.Background()
var bs = []byte("this is another minus test only")

var o = New(ossUse, &Config{
	Prefix:    "test/",
	Signature: "v2", // 注意: obs不支持v4签名算法!
	StorageConfig: StorageConfig{
		Access: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Region: "GUANGZHOU",
		Bucket: "hezhaowu",
		Domain: "hezhaowu.ks3-cn-guangzhou.ksyuncs.com",
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
....

```

## 关键API

## New() Method

```
var o = New(ossUse, &Config{
	Prefix:    "test/",
	Signature: "v2", // 注意: obs不支持v4签名算法!
	StorageConfig: StorageConfig{
		Access: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Secret: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Region: "GUANGZHOU",
		Bucket: "xxxxx",
		Domain: "xxxxx.ks3-cn-guangzhou.ksyuncs.com",
	},
	ClientConfig: ClientConfig{
		InsecureSkipVerify: true, // 自定义证书必须跳过CA验证!
	},
})
```

- Prefix:

  路径前缀! 相当于根目录, 多业务共享bucket时很实用.

- Signature:

  签名版本. V2性能快, V4安全高. 不同云厂支持度不同.

- StorageConfig:

  存储配置, 公钥/私钥/区/桶/域. 可以桶详情查看!

- ClientConfig:

  http配置.

## OSSI interface

```
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
```

## Storage interface

```
// Storage 用于邮箱服务的OSS提供者接口(是标准OSS接口子集)
type Storage interface {
	// PutObject V2的hash是Content-MD5, V4的hash是Content-SHA256
	HeadObject(key string) *RequestSetting
	PutObject(key string, hash string) *RequestSetting
	GetObject(key string, _range *Range) *RequestSetting
	GetObjectLink(key string, timeout int64) string
	DeleteObject(key string) *RequestSetting
	InitiateMultipartUpload(key string) *RequestSetting
	// UploadPart V2的hash是Content-MD5, V4的hash是Content-SHA256
	UploadPart(key string, uploadId string, partNumber int, hash string) *RequestSetting
	CompleteMultipartUpload(key string, uploadId string) *RequestSetting
	AbortMultipartUpload(key string, uploadId string) *RequestSetting
}
```

## Profile struct

```
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
	StorageHeaders     map[string]string // 在V2和V4上传对象存储设置,用于PutObject或MultipartUpload等上传header设置
	V2QueryParams       V2QueryParams     // 在V2用作Query参数名称
	V4QueryParams       V4QueryParams     // 在V4用作Query参数名称
}
```