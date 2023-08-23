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

// SetHTTPClient 设置自定义Client
func (c *Client) SetHTTPClient(cli *http.Client) {
	c.httpCli = NewHTTPClient(cli)
}

// SetPrivateKeyFromPemBlock 通过PEM字节设置商户RSA私钥
func (c *Client) SetPrivateKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPrivateKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// SetPrivateKeyFromPemFile 通过PEM文件设置商户RSA私钥
func (c *Client) SetPrivateKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPrivateKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// SetPrivateKeyFromPfxFile 通过pfx(p12)证书设置商户RSA私钥
// 注意：证书需采用「TripleDES-SHA1」加密方式
func (c *Client) SetPrivateKeyFromPfxFile(pfxFile, password string) error {
	key, err := NewPrivateKeyFromPfxFile(pfxFile, password)

	if err != nil {
		return err
	}

	c.prvKey = key

	return nil
}

// NewPublicKeyFromPemBlock 通过PEM字节设置平台RSA公钥
func (c *Client) SetPublicKeyFromPemBlock(mode RSAPaddingMode, pemBlock []byte) error {
	key, err := NewPublicKeyFromPemBlock(mode, pemBlock)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromPemFile 通过PEM文件设置平台RSA公钥
func (c *Client) SetPublicKeyFromPemFile(mode RSAPaddingMode, pemFile string) error {
	key, err := NewPublicKeyFromPemFile(mode, pemFile)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromDerBlock 通过DER字节设置平台RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *Client) SetPublicKeyFromDerBlock(pemBlock []byte) error {
	key, err := NewPublicKeyFromDerBlock(pemBlock)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// NewPublicKeyFromDerFile 通过DER证书设置平台RSA公钥
// 注意PEM格式: -----BEGIN CERTIFICATE----- | -----END CERTIFICATE-----
// DER转换命令: openssl x509 -inform der -in cert.cer -out cert.pem
func (c *Client) SetPublicKeyFromDerFile(pemFile string) error {
	key, err := NewPublicKeyFromDerFile(pemFile)

	if err != nil {
		return err
	}

	c.pubKey = key

	return nil
}

// WithLogger 设置日志记录
func (c *Client) WithLogger(f func(ctx context.Context, data map[string]string)) {
	c.logger = f
}

// Do 向支付宝网关发送请求
func (c *Client) Do(ctx context.Context, action *Action) (gjson.Result, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	body, err := action.FormEncode(c.appid, c.aesKey, c.prvKey)

	if err != nil {
		return fail(err)
	}

	log.SetReqBody(body)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, c.gateway, []byte(body),
		WithHTTPHeader(HeaderAccept, "application/json"),
		WithHTTPHeader(HeaderContentType, "application/x-www-form-urlencoded"),
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

	if err = c.verifyResp(action.RespKey(), b); err != nil {
		return fail(err)
	}

	ret := gjson.GetBytes(b, action.RespKey())

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

	log.Set("decrypt", data.String())

	return data, nil
}

func (c *Client) verifyResp(key string, body []byte) error {
	if c.pubKey == nil {
		return errors.New("public key is nil (forgotten configure?)")
	}

	ret := gjson.ParseBytes(body)

	sign := ret.Get("sign").String()

	if len(sign) == 0 {
		return nil
	}

	signByte, err := base64.StdEncoding.DecodeString(sign)

	if err != nil {
		return err
	}

	hash := crypto.SHA256

	if ret.Get("sign_type").String() == "RSA" {
		hash = crypto.SHA1
	}

	if errResp := ret.Get("error_response"); errResp.Exists() {
		if err = c.pubKey.Verify(hash, []byte(errResp.Raw), signByte); err != nil {
			return err
		}

		return fmt.Errorf("%s | %s (sub_code = %s, sub_msg = %s)", errResp.Get("code").String(), errResp.Get("msg").String(), errResp.Get("sub_code").String(), errResp.Get("sub_msg").String())
	}

	resp := ret.Get(key)

	if err = c.pubKey.Verify(hash, []byte(resp.Raw), signByte); err != nil {
		return err
	}

	return nil
}

// Buffer 向支付宝网关发送请求
func (c *Client) Buffer(ctx context.Context, action *Action) ([]byte, error) {
	log := NewReqLog(http.MethodPost, c.gateway)
	defer log.Do(ctx, c.logger)

	body, err := action.FormEncode(c.appid, c.aesKey, c.prvKey)

	if err != nil {
		return nil, err
	}

	log.SetReqBody(body)

	resp, err := c.httpCli.Do(ctx, http.MethodPost, c.gateway, []byte(body), WithHTTPHeader(HeaderContentType, "application/x-www-form-urlencoded"))

	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	log.SetRespHeader(resp.Header)
	log.SetStatusCode(resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP Request Error, StatusCode = %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	log.SetRespBody(string(b))

	return b, nil
}

// Encrypt 数据加密
func (c *Client) Encrypt(plainText string) (string, error) {
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
func (c *Client) Decrypt(encryptData string) (gjson.Result, error) {
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

// NewClient 生成支付宝客户端
func NewClient(appid, aesKey string) *Client {
	return &Client{
		appid:   appid,
		aesKey:  aesKey,
		gateway: "https://openapi.alipay.com/gateway.do",
		httpCli: NewDefaultHTTPClient(),
	}
}
