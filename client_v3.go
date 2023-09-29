package alipay

import (
	"bytes"
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/tidwall/gjson"
)

// ClientV3 支付宝V3客户端(仅支持v3版本的接口可用)
type ClientV3 struct {
	host    string
	appid   string
	aesKey  string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// AppID 返回appid
func (c *ClientV3) AppID() string {
	return c.appid
}

func (c *ClientV3) url(path string, query url.Values) string {
	var builder strings.Builder

	builder.WriteString(c.host)
	if len(path) != 0 && path[0] != '/' {
		builder.WriteString("/")
	}
	builder.WriteString(path)

	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}

	return builder.String()
}

func (c *ClientV3) do(ctx context.Context, method, path string, query url.Values, params X, header http.Header) (*APIResult, error) {
	reqURL := c.url(path, query)

	log := NewReqLog(method, reqURL)
	defer log.Do(ctx, c.logger)

	var (
		body []byte
		err  error
	)

	if params != nil {
		body, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}

		log.SetReqBody(string(body))

		if len(header.Get(HeaderEncryptType)) != 0 {
			encryptData, err := c.Encrypt(string(body))
			if err != nil {
				return nil, err
			}

			body = []byte(encryptData)
			log.Set("encrypt", encryptData)
		}
	}

	authStr, err := c.Authorization(method, path, query, body, header)
	if err != nil {
		return nil, err
	}
	header.Set(HeaderAuthorization, authStr)

	log.SetReqHeader(header)

	resp, err := c.httpCli.Do(ctx, method, reqURL, body, HeaderToHttpOption(header)...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	// 签名校验
	if err = c.Verify(resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	// 如果是加密请求，需要解密
	if resp.StatusCode < 400 && len(b) != 0 && !bytes.HasPrefix(b, []byte("{")) {
		data, err := c.Decrypt(string(b))
		if err != nil {
			return nil, err
		}

		log.Set("decrypt", string(data))
		ret.Body = gjson.ParseBytes(data)
	}

	return ret, nil
}

// GetJSON GET请求JSON数据
func (c *ClientV3) GetJSON(ctx context.Context, path string, query url.Values, options ...V3HeaderOption) (*APIResult, error) {
	header := http.Header{}

	header.Set(HeaderAccept, "application/json")
	header.Set(HeaderRequestID, uuid.NewString())

	for _, f := range options {
		f(header)
	}

	return c.do(ctx, http.MethodGet, path, query, nil, header)
}

// PostJSON POST请求JSON数据
func (c *ClientV3) PostJSON(ctx context.Context, path string, params X, options ...V3HeaderOption) (*APIResult, error) {
	header := http.Header{}

	header.Set(HeaderAccept, "application/json")
	header.Set(HeaderRequestID, uuid.NewString())
	header.Set(HeaderContentType, ContentJSON)

	for _, f := range options {
		f(header)
	}

	return c.do(ctx, http.MethodPost, path, nil, params, header)
}

// PostJSON POST加密请求
func (c *ClientV3) PostEncrypt(ctx context.Context, path string, params X, options ...V3HeaderOption) (*APIResult, error) {
	header := http.Header{}

	header.Set(HeaderRequestID, uuid.NewString())
	header.Set(HeaderEncryptType, "AES")
	header.Set(HeaderContentType, ContentText)

	for _, f := range options {
		f(header)
	}

	return c.do(ctx, http.MethodPost, path, nil, params, header)
}

// Upload 文件上传，参考：https://opendocs.alipay.com/open-v3/054oog?pathHash=7834d743
func (c *ClientV3) Upload(ctx context.Context, path string, form UploadForm, options ...V3HeaderOption) (*APIResult, error) {
	reqID := uuid.NewString()
	reqURL := c.url(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	reqHeader := http.Header{}

	reqHeader.Set(HeaderRequestID, reqID)
	for _, f := range options {
		f(reqHeader)
	}

	authStr, err := c.Authorization(http.MethodPost, path, nil, []byte(form.Field("data")), reqHeader)
	if err != nil {
		return nil, err
	}
	reqHeader.Set(HeaderAuthorization, authStr)

	log.SetReqHeader(reqHeader)

	resp, err := c.httpCli.Upload(ctx, reqURL, form, HeaderToHttpOption(reqHeader)...)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	// 签名校验
	if err = c.Verify(resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Authorization 生成签名并返回 HTTP Authorization
func (c *ClientV3) Authorization(method, path string, query url.Values, body []byte, header http.Header) (string, error) {
	if c.prvKey == nil {
		return "", errors.New("private key not found (forgotten configure?)")
	}

	authStr := fmt.Sprintf("app_id=%s,nonce=%s,timestamp=%d", c.appid, Nonce(32), time.Now().UnixMilli())

	var builder strings.Builder

	builder.WriteString(authStr)
	builder.WriteString("\n")
	builder.WriteString(method)
	builder.WriteString("\n")
	builder.WriteString(path)

	if len(query) != 0 {
		builder.WriteString("?")
		builder.WriteString(query.Encode())
	}
	builder.WriteString("\n")

	if len(body) != 0 {
		builder.Write(body)
		builder.WriteString("\n")
	}

	if token := header.Get(HeaderAppAuthToken); len(token) != 0 {
		builder.WriteString(token)
		builder.WriteString("\n")
	}

	sign, err := c.prvKey.Sign(crypto.SHA256, []byte(builder.String()))
	if err != nil {
		return "", err
	}

	auth := fmt.Sprintf("ALIPAY-SHA256withRSA %s,sign=%s", authStr, base64.StdEncoding.EncodeToString(sign))

	return auth, nil
}

// Verify 验证签名
func (c *ClientV3) Verify(header http.Header, body []byte) error {
	if c.pubKey == nil {
		return errors.New("public key not found (forgotten configure?)")
	}

	signByte, err := base64.StdEncoding.DecodeString(header.Get(HeaderSignature))
	if err != nil {
		return err
	}

	nonce := header.Get(HeaderNonce)
	timestamp := header.Get(HeaderTimestamp)

	var builder strings.Builder

	builder.WriteString(timestamp)
	builder.WriteString("\n")
	builder.WriteString(nonce)
	builder.WriteString("\n")

	if len(body) != 0 {
		builder.Write(body)
		builder.WriteString("\n")
	}

	return c.pubKey.Verify(crypto.SHA256, []byte(builder.String()), signByte)
}

// Encrypt 数据加密
func (c *ClientV3) Encrypt(plainText string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return "", err
	}

	cbc := NewAesCBC(key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, AES_PKCS5)

	b, err := cbc.Encrypt([]byte(plainText))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Decrypt 数据解密
func (c *ClientV3) Decrypt(encryptData string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return nil, err
	}

	cbc := NewAesCBC(key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, AES_PKCS5)

	cipherText, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, err
	}

	return cbc.Decrypt(cipherText)
}

// V3Option 自定义设置项
type V3Option func(c *ClientV3)

// WithV3Client 设置自定义 HTTP Client
func WithV3Client(cli *http.Client) V3Option {
	return func(c *ClientV3) {
		c.httpCli = NewHTTPClient(cli)
	}
}

// WithV3PrivateKey 设置商户RSA私钥
func WithV3PrivateKey(key *PrivateKey) V3Option {
	return func(c *ClientV3) {
		c.prvKey = key
	}
}

// WithV3PublicKey 设置平台RSA公钥
func WithV3PublicKey(key *PublicKey) V3Option {
	return func(c *ClientV3) {
		c.pubKey = key
	}
}

// WithV3Logger 设置日志记录
func WithV3Logger(f func(ctx context.Context, data map[string]string)) V3Option {
	return func(c *ClientV3) {
		c.logger = f
	}
}

// NewClientV3 生成支付宝客户端V3
func NewClientV3(appid, aesKey string, options ...V3Option) *ClientV3 {
	c := &ClientV3{
		host:    "https://openapi.alipay.com",
		appid:   appid,
		aesKey:  aesKey,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}

// NewSandboxV3 生成支付宝沙箱V3
func NewSandboxV3(appid, aesKey string, options ...V3Option) *ClientV3 {
	c := &ClientV3{
		host:    "http://openapi.sandbox.dl.alipaydev.com",
		appid:   appid,
		aesKey:  aesKey,
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}
