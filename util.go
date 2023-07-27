package alipay

import (
	"crypto/tls"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
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

// FormatPKCS1PrivateKey 格式化支付宝应用私钥(PKCS#1)
func FormatPKCS1PrivateKey(pemStr string) (RSAPaddingMode, string) {
	rawLen := 64
	keyLen := len(pemStr)

	raws := keyLen / rawLen
	temp := keyLen % rawLen

	if temp > 0 {
		raws++
	}

	start := 0
	end := start + rawLen

	var builder strings.Builder

	builder.WriteString("-----BEGIN RSA PRIVATE KEY-----\n")

	for i := 0; i < raws; i++ {
		if i == raws-1 {
			builder.WriteString(pemStr[start:])
		} else {
			builder.WriteString(pemStr[start:end])
		}

		builder.WriteByte('\n')

		start += rawLen
		end = start + rawLen
	}

	builder.WriteString("-----END RSA PRIVATE KEY-----\n")

	return RSA_PKCS1, builder.String()
}

// FormatPKCS8PrivateKey 格式化支付宝应用私钥(PKCS#8)
func FormatPKCS8PrivateKey(pemStr string) (RSAPaddingMode, string) {
	rawLen := 64
	keyLen := len(pemStr)

	raws := keyLen / rawLen
	temp := keyLen % rawLen

	if temp > 0 {
		raws++
	}

	start := 0
	end := start + rawLen

	var builder strings.Builder

	builder.WriteString("-----BEGIN PRIVATE KEY-----\n")

	for i := 0; i < raws; i++ {
		if i == raws-1 {
			builder.WriteString(pemStr[start:])
		} else {
			builder.WriteString(pemStr[start:end])
		}

		builder.WriteByte('\n')

		start += rawLen
		end = start + rawLen
	}

	builder.WriteString("-----END PRIVATE KEY-----\n")

	return RSA_PKCS8, builder.String()
}

// FormatPKCS1PublicKey 格式化支付宝应用公钥(PKCS#1)
func FormatPKCS1PublicKey(pemStr string) (RSAPaddingMode, string) {
	rawLen := 64
	keyLen := len(pemStr)

	raws := keyLen / rawLen
	temp := keyLen % rawLen

	if temp > 0 {
		raws++
	}

	start := 0
	end := start + rawLen

	var builder strings.Builder

	builder.WriteString("-----BEGIN RSA PUBLIC KEY-----\n")

	for i := 0; i < raws; i++ {
		if i == raws-1 {
			builder.WriteString(pemStr[start:])
		} else {
			builder.WriteString(pemStr[start:end])
		}

		builder.WriteByte('\n')

		start += rawLen
		end = start + rawLen
	}

	builder.WriteString("-----END RSA PUBLIC KEY-----\n")

	return RSA_PKCS1, builder.String()
}

// FormatPKCS8PublicKey 格式化支付宝应用公钥(PKCS#8)
func FormatPKCS8PublicKey(pemStr string) (RSAPaddingMode, string) {
	rawLen := 64
	keyLen := len(pemStr)

	raws := keyLen / rawLen
	temp := keyLen % rawLen

	if temp > 0 {
		raws++
	}

	start := 0
	end := start + rawLen

	var builder strings.Builder

	builder.WriteString("-----BEGIN PUBLIC KEY-----\n")

	for i := 0; i < raws; i++ {
		if i == raws-1 {
			builder.WriteString(pemStr[start:])
		} else {
			builder.WriteString(pemStr[start:end])
		}

		builder.WriteByte('\n')

		start += rawLen
		end = start + rawLen
	}

	builder.WriteString("-----END PUBLIC KEY-----\n")

	return RSA_PKCS8, builder.String()
}
