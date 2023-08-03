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

// ClientV3 支付宝客户端V3
type ClientV3 struct {
	host    string
	appid   string
	aesKey  string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// SetHTTPClient 设置自定义Client
func (c *ClientV3) SetHTTPClient(cli *http.Client) {
	c.httpCli = NewHTTPClient(cli)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置RSA私钥
func (c *ClientV3) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemBlock(mode, pemBlock)

	return
}

// SetPrivateKeyFromPemFile 通过PEM文件设置RSA私钥
func (c *ClientV3) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemFile(mode, pemFile)

	return
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (c *ClientV3) SetPrivateKeyFromPfxFile(pfxFile, password string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPfxFile(pfxFile, password)

	return
}

// NewPublicKeyFromPemBlock 通过PEM字节设置RSA公钥
func (c *ClientV3) SetPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromPemBlock(mode, pemBlock)

	return
}

// NewPublicKeyFromPemFile 通过PEM文件设置RSA公钥
func (c *ClientV3) SetPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromPemFile(mode, pemFile)

	return
}

// NewPublicKeyFromDerBlock 通过DER字节设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *ClientV3) SetPublicKeyFromDerBlock(pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromDerBlock(pemBlock)

	return
}

// NewPublicKeyFromDerFile 通过DER证书设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *ClientV3) SetPublicKeyFromDerFile(pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromDerFile(pemFile)

	return
}

// WithLogger 设置日志记录
func (c *ClientV3) WithLogger(f func(ctx context.Context, data map[string]string)) {
	c.logger = f
}

// URL 生成请求URL
func (c *ClientV3) URL(path string, query url.Values) string {
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

// GetJSON GET请求JSON数据
func (c *ClientV3) GetJSON(ctx context.Context, path string, query url.Values, options ...V3HeaderOption) (*APIResult, error) {
	reqID := uuid.NewString()
	reqURL := c.URL(path, query)

	log := NewReqLog(http.MethodGet, reqURL)
	defer log.Do(ctx, c.logger)

	reqHeader := http.Header{}

	reqHeader.Set(HeaderAccept, "application/json")
	reqHeader.Set(HeaderRequestID, reqID)

	for _, f := range options {
		f(reqHeader)
	}

	authStr, err := c.Authorization(http.MethodGet, path, query, "", reqHeader)

	if err != nil {
		return nil, err
	}

	reqHeader.Set(HeaderAuth, authStr)

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodGet, reqURL, nil, httpOptions...)

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
	if err = c.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// PostJSON POST请求JSON数据
func (c *ClientV3) PostJSON(ctx context.Context, path string, params X, options ...V3HeaderOption) (*APIResult, error) {
	reqID := uuid.NewString()
	reqURL := c.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	reqHeader := http.Header{}

	reqHeader.Set(HeaderAccept, "application/json")
	reqHeader.Set(HeaderRequestID, reqID)
	reqHeader.Set(HeaderContentType, "application/json;charset=utf-8")

	for _, f := range options {
		f(reqHeader)
	}

	authStr, err := c.Authorization(http.MethodPost, path, nil, string(body), reqHeader)

	if err != nil {
		return nil, err
	}

	reqHeader.Set(HeaderAuth, authStr)

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, body, httpOptions...)

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
	if err = c.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// PostJSON POST加密请求
func (c *ClientV3) PostEncrypt(ctx context.Context, path string, params X, options ...V3HeaderOption) (*APIResult, error) {
	reqID := uuid.NewString()
	reqURL := c.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	body, err := json.Marshal(params)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(string(body))

	encryptData, err := c.Encrypt(string(body))

	if err != nil {
		return nil, err
	}

	log.Set("encrypt", encryptData)

	reqHeader := http.Header{}

	reqHeader.Set(HeaderRequestID, reqID)
	reqHeader.Set(HeaderEncryptType, "AES")
	reqHeader.Set(HeaderContentType, "text/plain;charset=utf-8")

	for _, f := range options {
		f(reqHeader)
	}

	authStr, err := c.Authorization(http.MethodPost, path, nil, encryptData, reqHeader)

	if err != nil {
		return nil, err
	}

	reqHeader.Set(HeaderAuth, authStr)

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, []byte(encryptData), httpOptions...)

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
	if err = c.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	if resp.StatusCode < 400 && len(b) != 0 && !bytes.HasPrefix(b, []byte("{")) {
		data, err := c.Decrypt(string(b))

		if err != nil {
			return nil, err
		}

		log.Set("decrypt", data.String())

		ret.Body = data
	}

	return ret, nil
}

// Upload 上传资源
func (c *ClientV3) Upload(ctx context.Context, path string, form UploadForm, options ...V3HeaderOption) (*APIResult, error) {
	reqID := uuid.NewString()
	reqURL := c.URL(path, nil)

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	reqHeader := http.Header{}

	reqHeader.Set(HeaderRequestID, reqID)

	for _, f := range options {
		f(reqHeader)
	}

	authStr, err := c.Authorization(http.MethodPost, path, nil, form.Field("data"), reqHeader)

	if err != nil {
		return nil, err
	}

	reqHeader.Set(HeaderAuth, authStr)

	log.SetReqHeader(reqHeader)

	httpOptions := make([]HTTPOption, 0, len(reqHeader))

	for k, vals := range reqHeader {
		httpOptions = append(httpOptions, WithHTTPHeader(k, vals...))
	}

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, nil, httpOptions...)

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
	if err = c.Verify(ctx, resp.Header, b); err != nil {
		return nil, err
	}

	ret := &APIResult{
		Code: resp.StatusCode,
		Body: gjson.ParseBytes(b),
	}

	return ret, nil
}

// Authorization 生成签名并返回 HTTP Authorization
func (c *ClientV3) Authorization(method, path string, query url.Values, body string, header http.Header) (string, error) {
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
		builder.WriteString(body)
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

// Verify 验证微信签名
func (c *ClientV3) Verify(ctx context.Context, header http.Header, body []byte) error {
	if c.pubKey == nil {
		return errors.New("public key not found (forgotten configure?)")
	}

	sign := header.Get(HeaderSign)

	if len(sign) == 0 {
		return nil
	}

	signByte, err := base64.StdEncoding.DecodeString(sign)

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
func (c *ClientV3) Decrypt(encryptData string) (gjson.Result, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)

	if err != nil {
		return fail(err)
	}

	cbc := NewAesCBC(key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, AES_PKCS5)

	cipherText, err := base64.StdEncoding.DecodeString(encryptData)

	if err != nil {
		return fail(err)
	}

	b, err := cbc.Decrypt(cipherText)

	if err != nil {
		return fail(err)
	}

	return gjson.ParseBytes(b), nil
}

// NewClientV3 生成支付宝客户端V3
func NewClientV3(appid, aesKey string) *ClientV3 {
	return &ClientV3{
		host:    "https://openapi.alipay.com",
		appid:   appid,
		aesKey:  aesKey,
		httpCli: NewDefaultHTTPClient(),
	}
}

// NewSandboxV3 生成支付宝沙箱V3
func NewSandboxV3(appid, aesKey string) *ClientV3 {
	return &ClientV3{
		host:    "http://openapi.sandbox.dl.alipaydev.com",
		appid:   appid,
		aesKey:  aesKey,
		httpCli: NewDefaultHTTPClient(),
	}
}
