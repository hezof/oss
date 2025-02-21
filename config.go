package oss

import "time"

// 要求S3兼容的对象存储服务
const (
	KS3      = "ks3"      // 金山云对象存储
	OBS      = "obs"      // 华为云对象存储
	AWS      = "aws"      // 亚马逊对象存储
	MINIO    = "minio"    // minio对象存储
	OSS      = "oss"      // 阿里云对象存储
	V2       = "v2"       // S3 V2签名算法
	V4       = "v4"       // S3 V4签名算法
	SHAKE256 = "SHAKE256" // 校验惟一性hash算法
)

var profiles = map[string]*Profile{
	KS3:   ProfileKS3,
	OBS:   ProfileOBS,
	AWS:   ProfileAWS,
	MINIO: ProfileMINIO,
	OSS:   ProfileOSS,
}

type Signature func(prefix string, c *StorageConfig, p *Profile) Storage

var signatures = map[string]Signature{
	V2: NewStorageV2,
	V4: NewStorageV4,
}

type ClientConfig struct {

	// DialerTimeout 连接超时(默认3分钟)
	DialerTimeout time.Duration `json:"dialer_timeout"`

	// DialerKeepAlive 保持活跃(默认30秒)
	DialerKeepAlive time.Duration `json:"dialer_keep_alive"`

	// TLSHandshakeTimeout TLS握手超时(默认10秒)
	TLSHandshakeTimeout time.Duration

	// MaxIdleConnsPerHost 每个Host最大空闲连接数(默认64)
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host"`

	// MaxConnsPerHost 每个Host最大连接数(默认2048)
	MaxConnsPerHost int `json:"max_conns_per_host"`

	// IdleConnTimeout 空闲连接超时(默认30分)
	IdleConnTimeout time.Duration `json:"idle_conn_timeout"`

	// WriteBufferSize 写缓存区大小(默认64K)
	WriteBufferSize int `json:"write_buffer_size"`

	// ReadBufferSize 读缓存区大小(默认64K)
	ReadBufferSize int `json:"read_buffer_size"`

	// InsecureSkipVerify TLS是否跳过校验(默认false)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

type StorageConfig struct {
	Access      string `json:"access"`       // 访问ak
	Secret      string `json:"secret"`       // 访问sk
	Region      string `json:"region"`       // 区域
	Bucket      string `json:"bucket"`       // 桶名
	Domain      string `json:"domain"`       // 访问域名
	ContentType string `json:"content_type"` // Content-Type, 默认二进制流application/octet-stream
}

// Config 对象存储服务统一配置
type Config struct {
	ClientConfig
	StorageConfig
	Signature string `json:"signature"` // 签名版本: V2,V4...默认V2
	Prefix    string `json:"prefix"`    // key前缀
}

// 默认编码值
var (
	TransferEncoding        = "Transfer-Encoding"
	TransferEncodingChunked = []string{"chunked"}
)
