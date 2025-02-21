package oss

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// 默认值与go/pkg/http相同
const (
	defaultDialerTimeout       = 20 * time.Second
	defaultDialerKeepAlive     = 20 * time.Second
	defaultIdleConnTimeout     = 20 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultMaxIdleConnsPerHost = 64
	defaultMaxConnsPerHost     = 2048
	defaultWriteBufferSize     = 512 * 1024
	defaultReadBufferSize      = 512 * 1024
)

func NewClient(c *ClientConfig) *http.Client {

	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				Timeout:   NvlD(c.DialerTimeout, defaultDialerTimeout),
				KeepAlive: NvlD(c.DialerKeepAlive, defaultDialerKeepAlive),
			}).DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: c.InsecureSkipVerify},
			TLSHandshakeTimeout: NvlD(c.TLSHandshakeTimeout, defaultTLSHandshakeTimeout),
			MaxIdleConnsPerHost: NvlI(c.MaxIdleConnsPerHost, defaultMaxIdleConnsPerHost),
			MaxConnsPerHost:     NvlI(c.MaxConnsPerHost, defaultMaxConnsPerHost),
			IdleConnTimeout:     NvlD(c.IdleConnTimeout, defaultIdleConnTimeout),
			WriteBufferSize:     NvlI(c.WriteBufferSize, defaultWriteBufferSize),
			ReadBufferSize:      NvlI(c.ReadBufferSize, defaultReadBufferSize),
			DisableKeepAlives:   true, // 尝试解决UnexpectedEOF
		},
	}
}

func NvlI(val, def int) int {
	if val == 0 {
		return def
	}
	return val
}

func NvlD(val, def time.Duration) time.Duration {
	if val == 0 {
		return def
	}
	return val
}
