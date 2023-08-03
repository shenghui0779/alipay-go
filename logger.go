package alipay

import (
	"context"
	"net/http"
	"strconv"
)

// ReqLog 请求日志
type ReqLog struct {
	data map[string]string
}

// Set 设置日志K-V
func (l *ReqLog) Set(k, v string) {
	l.data[k] = v
}

// SetBody 设置请求Body
func (l *ReqLog) SetReqBody(v string) {
	l.data["request_body"] = v
}

// SetResp 设置返回报文
func (l *ReqLog) SetRespBody(v string) {
	l.data["response_body"] = v
}

// SetRespHeader 设置返回头
func (l *ReqLog) SetRespHeader(h http.Header) {
	v := V{}

	for key, vals := range h {
		if len(vals) != 0 {
			v.Set(key, vals[0])
		}
	}

	l.data["response_header"] = v.Encode("=", "&")
}

// SetStatusCode 设置HTTP状态码
func (l *ReqLog) SetStatusCode(code int) {
	l.data["status_code"] = strconv.Itoa(code)
}

// Do 日志记录
func (l *ReqLog) Do(ctx context.Context, log func(ctx context.Context, data map[string]string)) {
	if log == nil {
		return
	}

	log(ctx, l.data)
}

// NewReqLog 生成请求日志
func NewReqLog(method, reqURL string) *ReqLog {
	return &ReqLog{
		data: map[string]string{
			"method": method,
			"url":    reqURL,
		},
	}
}
