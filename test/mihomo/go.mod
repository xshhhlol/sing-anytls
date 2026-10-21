module github.com/sagernet/sing-anytls/test/mihomo

go 1.24.0

require (
	github.com/metacubex/mihomo v1.19.32
	github.com/sagernet/sing v0.8.14
	github.com/sagernet/sing-anytls v0.0.0
)

require (
	github.com/metacubex/sing v0.5.8 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/sagernet/sing-anytls => ../..
