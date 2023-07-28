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

	"github.com/tidwall/gjson"
)

// AlipayClient 支付宝客户端
type AlipayClient struct {
	appid   string
	aesKey  string
	prvKey  *PrivateKey
	pubKey  *PublicKey
	gateway string
	client  HTTPClient
	logger  func(ctx context.Context, method, url, body, resp string)
}

// SetHTTPClient 设置自定义Client
func (c *AlipayClient) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置RSA私钥
func (c *AlipayClient) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemBlock(mode, pemBlock)

	return
}

// SetPrivateKeyFromPemFile 通过PEM文件设置RSA私钥
func (c *AlipayClient) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPemFile(mode, pemFile)

	return
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (c *AlipayClient) SetPrivateKeyFromPfxFile(pfxFile, password string) (err error) {
	c.prvKey, err = NewPrivateKeyFromPfxFile(pfxFile, password)

	return
}

// NewPublicKeyFromPemBlock 通过PEM字节设置RSA公钥
func (c *AlipayClient) SetPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromPemBlock(mode, pemBlock)

	return
}

// NewPublicKeyFromPemFile 通过PEM文件设置RSA公钥
func (c *AlipayClient) SetPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromPemFile(mode, pemFile)

	return
}

// NewPublicKeyFromDerBlock 通过DER字节设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *AlipayClient) SetPublicKeyFromDerBlock(pemBlock []byte) (err error) {
	c.pubKey, err = NewPublicKeyFromDerBlock(pemBlock)

	return
}

// NewPublicKeyFromDerFile 通过DER证书设置RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *AlipayClient) SetPublicKeyFromDerFile(pemFile string) (err error) {
	c.pubKey, err = NewPublicKeyFromDerFile(pemFile)

	return
}

// WithLogger 设置日志记录
func (c *AlipayClient) WithLogger(f func(ctx context.Context, method, url, body, resp string)) {
	c.logger = f
}

// Do 向支付宝网关发送请求
func (c *AlipayClient) Do(ctx context.Context, action *Action, options ...HTTPOption) (gjson.Result, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	body, err := action.URLEncode(c.appid, c.prvKey)

	if err != nil {
		return fail(err)
	}

	log.SetBody(body)

	options = append(options, WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	resp, err := c.client.Do(ctx, http.MethodPost, c.gateway, []byte(body), options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	log.SetResp(string(b))

	return c.verifyResp(action.RespKey(), b)
}

func (c *AlipayClient) verifyResp(key string, body []byte) (gjson.Result, error) {
	if c.pubKey == nil {
		return fail(errors.New("public key is nil (forgotten configure?)"))
	}

	ret := gjson.ParseBytes(body)

	sign, err := base64.StdEncoding.DecodeString(ret.Get("sign").String())

	if err != nil {
		return fail(err)
	}

	hash := crypto.SHA256

	if ret.Get("sign_type").String() == "RSA" {
		hash = crypto.SHA1
	}

	if errResp := ret.Get("error_response"); errResp.Exists() {
		if err = c.pubKey.Verify(hash, []byte(errResp.String()), sign); err != nil {
			return fail(err)
		}

		return fail(errors.New(errResp.String()))
	}

	data := ret.Get(key)

	if err = c.pubKey.Verify(hash, []byte(data.String()), sign); err != nil {
		return fail(err)
	}

	if data.Get("code").String() != CodeOK {
		return fail(errors.New(data.String()))
	}

	return data, nil
}

// Buffer 向支付宝网关发送请求
func (c *AlipayClient) Buffer(ctx context.Context, action *Action, options ...HTTPOption) ([]byte, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	body, err := action.URLEncode(c.appid, c.prvKey)

	if err != nil {
		return nil, err
	}

	log.SetBody(body)

	options = append(options, WithHTTPHeader("Content-Type", "application/x-www-form-urlencoded"))

	resp, err := c.client.Do(ctx, http.MethodPost, c.gateway, []byte(body), options...)

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetResp(string(b))

	return b, nil
}

// Decrypt 数据解密
func (c *AlipayClient) Decrypt(encryptData string) (gjson.Result, error) {
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

// VerifyNotify 验证回调通知表单数据
func (c *AlipayClient) VerifyNotify(form url.Values) (V, error) {
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

// NewAlipayClient 设置支付宝客户端
func NewAlipayClient(appid, aesKey string) *AlipayClient {
	return &AlipayClient{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi.alipay.com/gateway.do",
		client:  NewDefaultHTTPClient(),
	}
}
