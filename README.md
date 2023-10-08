# alipay

[![golang](https://img.shields.io/badge/Language-Go-green.svg?style=flat)](https://golang.org) [![GitHub release](https://img.shields.io/github/release/shenghui0779/alipay.svg)](https://github.com/shenghui0779/alipay/releases/latest) [![pkg.go.dev](https://img.shields.io/badge/dev-reference-007d9c?logo=go&logoColor=white&style=flat)](https://pkg.go.dev/github.com/shenghui0779/alipay) [![Apache 2.0 license](http://img.shields.io/badge/license-Apache%202.0-brightgreen.svg)](http://opensource.org/licenses/apache2.0)

支付宝 Go SDK

```sh
go get -u github.com/shenghui0779/alipay
```

### 使用说明

- 发送HTTP请求，使用 `Client.Do(...)`
- 以下场景使用 `Action.Encode(...)`
  * alipay.trade.app.pay(app支付接口2.0)
  * alipay.fund.auth.order.app.freeze(线上资金授权冻结接口)
- 以下场景使用 `Client.PageExecute(...)`
  * alipay.trade.wap.pay(手机网站支付接口2.0)
  * alipay.trade.page.pay(统一收单下单并支付页面接口)
  * alipay.user.certify.open.certify(身份认证开始认证)
- 验证回调通知，使用 `Client.VerifyNotify(...)`
- 解析加密数据，如：授权的用户信息和手机号，使用 `Client.DecodeEncryptData(...)`
