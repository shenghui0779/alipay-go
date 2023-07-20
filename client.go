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
}

// SetHTTPClient 设置 HTTP Client
func (c *AlipayClient) SetHTTPClient(cli *http.Client) {
	c.client = NewHTTPClient(cli)
}

// Do 向支付宝网关发送请求
func (c *AlipayClient) Do(ctx context.Context, action *Action, options ...HTTPOption) (gjson.Result, error) {
	body, err := action.URLEncode(c.appid, c.prvKey)

	if err != nil {
		return fail(err)
	}

	resp, err := c.client.Do(ctx, http.MethodPost, c.gateway, []byte(body), options...)

	if err != nil {
		return fail(err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("unexpected http status: %d", resp.StatusCode))
	}

	b, err := io.ReadAll(resp.Body)

	if err != nil {
		return fail(err)
	}

	ret := gjson.ParseBytes(b)

	sign, err := base64.StdEncoding.DecodeString(ret.Get("sign").String())

	if err != nil {
		return fail(err)
	}

	hash := crypto.SHA256

	if ret.Get("sign_type").String() == "RSA" {
		hash = crypto.SHA1
	}

	if errResp := ret.Get("error_response"); errResp.Exists() {
		if err = c.pubKey.Verify(hash, []byte(errResp.Raw), sign); err != nil {
			return fail(err)
		}

		return fail(errors.New(errResp.Raw))
	}

	data := ret.Get(action.RespKey())

	if err = c.pubKey.Verify(hash, []byte(data.Raw), sign); err != nil {
		return fail(err)
	}

	if data.Get("code").String() != CodeOK {
		return fail(errors.New(data.Raw))
	}

	return data, nil
}

// Decrypt 数据解密
func (c *AlipayClient) Decrypt(encryptDdata string) (gjson.Result, error) {
	key, err := base64.StdEncoding.DecodeString(c.aesKey)

	if err != nil {
		return fail(err)
	}

	cbc := NewAesCBC(key, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, AES_PKCS5)

	cipherText, err := base64.StdEncoding.DecodeString(encryptDdata)

	if err != nil {
		return fail(err)
	}

	b, err := cbc.Decrypt(cipherText)

	if err != nil {
		return fail(err)
	}

	return gjson.ParseBytes(b), nil
}

// Verify 验证回调通知表单数据
func (c *AlipayClient) Verify(form url.Values) error {
	sign, err := base64.StdEncoding.DecodeString(form.Get("sign"))

	if err != nil {
		return err
	}

	v := make(V)

	for key, vals := range form {
		if len(vals) != 0 {
			v.Set(key, vals[0])
		}
	}

	str := v.Encode("=", "&", WithIgnoreKeys("sign_type", "sign"))

	hash := crypto.SHA256

	if form.Get("sign_type") == "RSA" {
		hash = crypto.SHA1
	}

	return c.pubKey.Verify(hash, []byte(str), sign)
}

// NewAlipayClient 生成支付宝客户端
func NewAlipayClient(appid, aesKey string, prvKey *PrivateKey, pubKey *PublicKey) *AlipayClient {
	return &AlipayClient{
		appid:   appid,
		aesKey:  aesKey,
		prvKey:  prvKey,
		pubKey:  pubKey,
		gateway: "https://openapi.alipay.com/gateway.do",
		client:  NewDefaultHTTPClient(),
	}
}
