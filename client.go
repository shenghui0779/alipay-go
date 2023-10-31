package alipay

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/tidwall/gjson"
)

// Client 支付宝客户端
type Client struct {
	gateway string
	appid   string
	aesKey  string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	httpCli HTTPClient
	logger  func(ctx context.Context, data map[string]string)
}

// AppID 返回appid
func (c *Client) AppID() string {
	return c.appid
}

// Do 向支付宝网关发送请求
func (c *Client) Do(ctx context.Context, method string, options ...ActionOption) (gjson.Result, error) {
	reqURL := c.gateway + "?charset=utf-8"

	log := NewReqLog(http.MethodPost, reqURL)
	defer log.Do(ctx, c.logger)

	action := NewAction(method, options...)

	body, err := action.Encode(c)
	if err != nil {
		return fail(err)
	}

	log.SetReqBody(body)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, reqURL, []byte(body),
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderContentType, ContentForm),
	)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret, err := c.verifyResp(action.RespKey(), b)
	if err != nil {
		return fail(err)
	}

	// JSON串，无需解密
	if strings.HasPrefix(ret.String(), "{") {
		if code := ret.Get("code").String(); code != CodeOK {
			return fail(fmt.Errorf("%s | %s (sub_code = %s, sub_msg = %s)", code, ret.Get("msg").String(), ret.Get("sub_code").String(), ret.Get("sub_msg").String()))
		}

		return ret, nil
	}

	// 非JSON串，需解密
	data, err := c.Decrypt(ret.String())
	if err != nil {
		return fail(err)
	}

	log.Set("decrypt", string(data))

	return gjson.ParseBytes(data), nil
}

// Upload 文件上传，参考：https://opendocs.alipay.com/apis/api_4/alipay.merchant.item.file.upload
func (c *Client) Upload(ctx context.Context, method string, form UploadForm, options ...ActionOption) (gjson.Result, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	action := NewAction(method, options...)

	query, err := action.Encode(c)
	if err != nil {
		return fail(err)
	}

	log.Set("query", query)

	resp, err := c.httpCli.Upload(ctx, c.gateway+"?"+query, form, WithHTTPHeader(HeaderAccept, "application/json"))
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fail(err)
	}

	log.SetRespBody(string(b))

	ret, err := c.verifyResp(action.RespKey(), b)
	if err != nil {
		return fail(err)
	}

	// JSON串，无需解密
	if strings.HasPrefix(ret.String(), "{") {
		if code := ret.Get("code").String(); code != CodeOK {
			return fail(fmt.Errorf("%s | %s (sub_code = %s, sub_msg = %s)", code, ret.Get("msg").String(), ret.Get("sub_code").String(), ret.Get("sub_msg").String()))
		}

		return ret, nil
	}

	// 非JSON串，需解密
	data, err := c.Decrypt(ret.String())
	if err != nil {
		return fail(err)
	}

	log.Set("decrypt", string(data))

	return gjson.ParseBytes(data), nil
}

func (c *Client) verifyResp(key string, body []byte) (gjson.Result, error) {
	if c.pubKey == nil {
		return fail(errors.New("public key is nil (forgotten configure?)"))
	}

	ret := gjson.ParseBytes(body)

	signByte, err := base64.StdEncoding.DecodeString(ret.Get("sign").String())
	if err != nil {
		return fail(err)
	}

	hash := crypto.SHA256
	if ret.Get("sign_type").String() == "RSA" {
		hash = crypto.SHA1
	}

	if errResp := ret.Get("error_response"); errResp.Exists() {
		if err = c.pubKey.Verify(hash, []byte(errResp.Raw), signByte); err != nil {
			return fail(err)
		}

		return fail(fmt.Errorf("%s | %s (sub_code = %s, sub_msg = %s)",
			errResp.Get("code").String(),
			errResp.Get("msg").String(),
			errResp.Get("sub_code").String(),
			errResp.Get("sub_msg").String(),
		))
	}

	resp := ret.Get(key)
	if err = c.pubKey.Verify(hash, []byte(resp.Raw), signByte); err != nil {
		return fail(err)
	}

	return resp, nil
}

// PageExecute 致敬官方SDK
func (c *Client) PageExecute(method string, options ...ActionOption) (string, error) {
	action := NewAction(method, options...)

	query, err := action.Encode(c)
	if err != nil {
		return "", err
	}

	return c.gateway + "?" + query, nil
}

// Encrypt 数据加密
func (c *Client) Encrypt(data string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return "", fmt.Errorf("aes_key base64.decode error: %w", err)
	}

	b, err := AESEncryptCBC(key, []byte(data))
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(b), nil
}

// Decrypt 数据解密
func (c *Client) Decrypt(encryptData string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)
	if err != nil {
		return nil, fmt.Errorf("aes_key base64.decode error: %w", err)
	}

	data, err := base64.StdEncoding.DecodeString(encryptData)
	if err != nil {
		return nil, fmt.Errorf("encrypt_data base64.decode error: %w", err)
	}

	return AESDecryptCBC(key, data)
}

// DecodeEncryptData 解析加密数据，如：授权的用户信息和手机号
func (c *Client) DecodeEncryptData(hash crypto.Hash, data, sign string) ([]byte, error) {
	if c.pubKey == nil {
		return nil, errors.New("public key is nil (forgotten configure?)")
	}

	signByte, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return nil, fmt.Errorf("sign base64.decode error: %w", err)
	}

	if err = c.pubKey.Verify(hash, []byte(`"`+data+`"`), signByte); err != nil {
		return nil, fmt.Errorf("sign verified error: %w", err)
	}

	return c.Decrypt(data)
}

// VerifyNotify 验证回调通知表单数据
func (c *Client) VerifyNotify(form url.Values) (V, error) {
	if c.pubKey == nil {
		return nil, errors.New("public key is nil (forgotten configure?)")
	}

	sign, err := base64.StdEncoding.DecodeString(form.Get("sign"))
	if err != nil {
		return nil, err
	}

	v := V{}

	for key, vals := range form {
		if key == "sign_type" || key == "sign" || len(vals) == 0 {
			continue
		}

		v.Set(key, vals[0])
	}

	str := v.Encode("=", "&", WithEmptyEncMode(EmptyEncIgnore))

	hash := crypto.SHA256
	if form.Get("sign_type") == "RSA" {
		hash = crypto.SHA1
	}

	if err = c.pubKey.Verify(hash, []byte(str), sign); err != nil {
		return nil, err
	}

	return v, nil
}

// Option 自定义设置项
type Option func(c *Client)

// WithHttpCli 设置自定义 HTTP Client
func WithHttpCli(cli *http.Client) Option {
	return func(c *Client) {
		c.httpCli = NewHTTPClient(cli)
	}
}

// WithPrivateKey 设置商户RSA私钥
func WithPrivateKey(key *PrivateKey) Option {
	return func(c *Client) {
		c.prvKey = key
	}
}

// WithPublicKey 设置平台RSA公钥
func WithPublicKey(key *PublicKey) Option {
	return func(c *Client) {
		c.pubKey = key
	}
}

// WithLogger 设置日志记录
func WithLogger(f func(ctx context.Context, data map[string]string)) Option {
	return func(c *Client) {
		c.logger = f
	}
}

// NewClient 生成支付宝客户端
func NewClient(appid, aesKey string, options ...Option) *Client {
	c := &Client{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi.alipay.com/gateway.do",
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}

// NewSandbox 生成支付宝沙箱环境
func NewSandbox(appid, aesKey string, options ...Option) *Client {
	c := &Client{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi-sandbox.dl.alipaydev.com/gateway.do",
		httpCli: NewDefaultHTTPClient(),
	}

	for _, f := range options {
		f(c)
	}

	return c
}
