# alipay
支付宝 Go SDK

### 说明

- 服务端发送HTTP请求，使用 `Client.Do(...)`
- 以下应用直接使用 `Action.Encode(...)`
  * alipay.trade.app.pay(app支付接口2.0)
  * alipay.fund.auth.order.app.freeze(线上资金授权冻结接口)
- 以下应用请使用 `Client.PageExecute(...)`
  * alipay.trade.wap.pay(手机网站支付接口2.0)
  * alipay.trade.page.pay(统一收单下单并支付页面接口)
  * alipay.user.certify.open.certify(身份认证开始认证)
