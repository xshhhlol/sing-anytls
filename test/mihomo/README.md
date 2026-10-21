# Mihomo 会话互操作

```sh
cd test/mihomo
go test -race ./...
```

固定使用 `github.com/metacubex/mihomo v1.19.32` 的实际 `transport/anytls/session.Client` 和 padding parser，测试本地增强服务端的标准 WASTE、策略更新、TCP 流、复用，以及带证书校验的 TLS 1.2/1.3。

为避免将 Mihomo 的整个出站/TLS 框架引入协议库测试，此测试用标准 `crypto/tls` 提供连接，并按照 Mihomo `transport/anytls/client.go` 的格式发送 SHA-256 密码摘要、两字节填充长度和认证填充，再交给真实会话客户端。目标地址也按标准 SocksAddr 写入。测试不覆盖 Mihomo 的 uTLS、ALPN 配置、完整应用配置、UoT 适配或闭源客户端。

这个独立模块不改变根模块或 `test` 模块的依赖。测试证明所列路径可互操作，不证明 DPI 抗识别效果。
