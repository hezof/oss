package oss

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/xml"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"
	"unsafe"
)

const (
	commonProviderHeadersInitSize = 8 // providerContext的Header初始大小
	commonProviderQueriesInitSize = 2 // providerContext的Query初始大小
	/* StringBuffer初始1024,自动增长2次(大于4096)会被销毁!*/
	commonStringBufferInitSize = 1024 // commonStringBuffer的初始大小(至少1K)
	commonStringBufferHoldSize = 4096 // commonStringBuffer的保留大小(超出销毁)
)

const (
	contentSha256UnsignedPayload      = "UNSIGNED-PAYLOAD"         // 用于V4签名头
	contentTypeApplicationOctetStream = "application/octet-stream" // 二进制流的mime类型

	gmtDateTime = `Mon, 02 Jan 2006 15:04:05 GMT` // GMT时间格式
	isoDateTime = "20060102T150405Z"              // ISO标准时间,短形式

	// 约定所有header统一小写(签名排序不用转换)
	headerAuthorization = "authorization"
	headerContentType   = "content-type"
	headerContentMD5    = "content-md5"
	headerRange         = "range"
	headerHost          = "host"
)

/****************************************
 * CommonStringBuffer辅助数据结构
 ****************************************/

var buffers = sync.Pool{
	New: func() interface{} {
		return bytes.NewBuffer(make([]byte, 0, commonStringBufferInitSize))
	},
}

func borrowBuffer() *bytes.Buffer {
	bf := buffers.Get().(*bytes.Buffer)
	bf.Reset()
	return bf
}

func returnBuffer(bf *bytes.Buffer) {
	if bf.Cap() < commonStringBufferHoldSize {
		buffers.Put(bf)
	}
}

/****************************************
 * CommonProviderContext 辅助数据结构
 ****************************************/

var contexts = sync.Pool{
	New: func() interface{} {
		return &ProviderContext{
			SignedHeaders: Values{
				values: make([]*Value, 0, commonProviderHeadersInitSize),
			},
			SignedQueries: Values{
				values: make([]*Value, 0, commonProviderQueriesInitSize),
			},
		}
	},
}

func borrowContext() *ProviderContext {
	pc := contexts.Get().(*ProviderContext)
	pc.Reset()
	return pc
}

func returnContext(pc *ProviderContext) {
	contexts.Put(pc)
}

// ProviderContext 请求选项,内部细节不对外暴露,通过Option进行设置!
type ProviderContext struct {
	UTC           time.Time // UTC时间
	Status        int       // 预期返回的http-Status
	Method        string    // 请求的http Method
	ObjectKey     string    // 对象的key, 目前固定为上传文件的SHA1, 必须正确, 云存储开启sha1重命名后会导致文件"真空"!
	ContentType   string    // 内容类型, 默认为空, 即服务器不检查内容类型
	ContentMD5    string    // 内容MD5
	SignedHeaders Values    // 需要加入签名的自定义头部
	SignedQueries Values    // 需要加入签名的自与定义参数
	Range         Range     // 需要Range查询
}

func (a *ProviderContext) Reset() {
	a.Status = 0
	a.Method = ""
	a.ObjectKey = ""
	a.ContentType = ""
	a.ContentMD5 = ""
	a.SignedHeaders.Reset()
	a.SignedQueries.Reset()
	a.Range.Start = 0
	a.Range.End = 0
}

type Value struct {
	Name string `json:"name"`
	Text string `json:"text"`
}

type Values struct {
	sorted bool
	values []*Value
}

func (p *Values) Add(name, text string) {
	p.values = append(p.values, &Value{
		Name: name,
		Text: text,
	})
}

func (p *Values) SortedValues() []*Value {
	if p.sorted {
		return p.values
	}
	sort.Sort(p)
	p.sorted = true
	return p.values
}

func (p *Values) Reset() *Values {
	p.sorted = false
	p.values = p.values[0:0]
	return p
}

func (p *Values) Len() int {
	return len(p.values)
}

func (p *Values) Less(i, j int) bool {
	pi := p.values[i]
	pj := p.values[j]
	if pi.Name == pj.Name {
		return pi.Text < pj.Text
	} else {
		return pi.Name < pj.Name
	}
}

func (p *Values) Swap(i, j int) {
	p.values[i], p.values[j] = p.values[j], p.values[i]
}

var _ sort.Interface = (*Values)(nil)

type Range struct {
	Start uint64
	End   uint64
}

func (r Range) Value() string {
	bf := borrowBuffer()
	defer returnBuffer(bf)

	bf.WriteString("bytes=")
	bf.WriteString(strconv.FormatUint(r.Start, 10))
	if r.End > 0 {
		bf.WriteByte('-')
		bf.WriteString(strconv.FormatUint(r.End, 10))
	}
	return bf.String()
}

/****************************************
 * multipart upload 辅助数据结构
 ****************************************/

// initiateMultipartUploadResult 忽略没必要解析的字段
type initiateMultipartUploadResult struct {
	XMLName xml.Name `xml:"InitiateMultipartUploadResult"`
	//Bucket   string   `xml:"Bucket"`
	//Key      string   `xml:"Key"`
	UploadId string `xml:"UploadId"`
}

type Part struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

type Parts []*Part

func (p Parts) Less(i, j int) bool { return p[i].PartNumber < p[j].PartNumber }
func (p Parts) Swap(i, j int)      { p[i], p[j] = p[j], p[i] }
func (p Parts) Len() int           { return len(p) }

// completeMultipartUpload 完成分片上传
type completeMultipartUpload struct {
	XMLName xml.Name `xml:"CompleteMultipartUpload"`
	Parts   []*Part  `xml:"Part"`
}

func ExtractMultipartUploadId(rsp *http.Response) (string, error) {

	result := new(initiateMultipartUploadResult)

	err := xml.NewDecoder(rsp.Body).Decode(result)
	if err != nil {
		return "", err
	}
	return result.UploadId, nil
}

var ErrEtagNotFound = errors.New("Etag not found")

func ExtractMultipartUploadETag(rsp *http.Response) (string, error) {
	if vs, ok := rsp.Header["Etag"]; ok {
		return vs[0], nil
	}
	return "", ErrEtagNotFound
}

func CompleteMultipartUploadParts(buffer *bytes.Buffer, parts []*Part) error {
	content := &completeMultipartUpload{
		Parts: parts,
	}
	return xml.NewEncoder(buffer).Encode(content)
}

/****************************************
 * 辅助工具方法
 ****************************************/

func If(c bool, t, f string) string {
	if c {
		return t
	} else {
		return f
	}
}

func Sha256(p []byte) []byte {
	h := sha256.New()
	h.Write(p)
	return h.Sum(nil)
}

func HmacSha256(key []byte, val []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(val)
	return h.Sum(nil)
}

func HmacSha1(key []byte, val []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(val)
	return h.Sum(nil)
}

// UnsafeBytes converts string to byte slice without a memory allocation.
// For more details, see https://github.com/golang/go/issues/53003#issuecomment-1140276077.
func UnsafeBytes(s string) []byte {
	return unsafe.Slice(unsafe.StringData(s), len(s))
}

// UnsafeString converts byte slice to string without a memory allocation.
// For more details, see https://github.com/golang/go/issues/53003#issuecomment-1140276077.
func UnsafeString(b []byte) string {
	return unsafe.String(unsafe.SliceData(b), len(b))
}
