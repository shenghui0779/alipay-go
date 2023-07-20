package alipay

import (
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"

	"github.com/tidwall/gjson"
	"golang.org/x/crypto/pkcs12"
)

var (
	fail     = func(err error) (gjson.Result, error) { return gjson.Result{}, err }
	timezone = time.FixedZone("CST", 8*3600)
)

const CodeOK = "10000" // API请求成功

type GrantType string

const (
	OAuthCode    GrantType = "authorization_code"
	RefreshToken GrantType = "refresh_token"
)

// X 类型别名
type X map[string]any

// LoadCertFromPfxFile 通过pfx(p12)证书文件生成TLS证书
// 注意：证书需采用「TripleDES-SHA1」加密方式
func LoadCertFromPfxFile(filename, password string) (tls.Certificate, error) {
	fail := func(err error) (tls.Certificate, error) { return tls.Certificate{}, err }

	certPath, err := filepath.Abs(filepath.Clean(filename))

	if err != nil {
		return fail(err)
	}

	pfxdata, err := os.ReadFile(certPath)

	if err != nil {
		return fail(err)
	}

	blocks, err := pkcs12.ToPEM(pfxdata, password)

	if err != nil {
		return fail(err)
	}

	pemData := make([]byte, 0)

	for _, b := range blocks {
		pemData = append(pemData, pem.EncodeToMemory(b)...)
	}

	return tls.X509KeyPair(pemData, pemData)
}
