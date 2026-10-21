# 实际客户端测试与流量测量

独立模块，只依赖标准库。包含三部分：

- **客户端矩阵**（`TestClientMatrix`）：用真实客户端二进制连接 sing-box 服务端，逐项验证首次连接、空闲会话复用、16 MiB 下载后再小请求、服务端先发、并发、取消、UDP（UoT）、RST 断线重连、服务端重启。
- **主动探测与回落**（`TestFallbackProbes`）：不经 AnyTLS 客户端，直接对入站发起普通 HTTPS 请求、错误密码、短请求带 EOF、短请求不结束、明文 TCP。
- **配对测量**（`TestMeasure`）：同一工作负载分别经过各客户端和各服务端模式，并加上直接访问同一页面的 HTTPS 基线，在客户端和服务端之间的中继记录每条 TLS record 的方向、类型、长度和时间。

服务端是同一个 sing-box 进程中的多个 AnyTLS 入站，除流量整形外配置相同：

| 模式 | 来源 | 含义 |
| --- | --- | --- |
| `legacy` | `sing-box-legacy`，即 sing-box_mod 修改前的提交 | 原 `github.com/anytls/sing-anytls v0.0.13` 服务端，无回落 |
| `control` | `sing-box`，当前 sing-box_mod 工作区 | 本库，`traffic_shaping` 关闭，作为对照实例 |
| `shaped` | 同上 | 本库，`traffic_shaping: {"enabled": true}` 默认参数 |
| 自定义 | `REALCLIENT_PROFILES` | 调参用，见下 |

客户端：

| 名称 | 二进制 | 说明 |
| --- | --- | --- |
| sing-box | `sing-box` | 出站使用 `github.com/anytls/sing-anytls v0.0.13`，与基于 sing-box 的图形客户端相同；用测试 CA 校验证书 |
| mihomo | `mihomo` | Mihomo v1.19.32 完整程序，按 SHA-256 指纹固定证书 |
| anytls-go | `anytls-client` | 官方参考客户端 v0.0.13，示例程序跳过证书校验 |

## 运行

```sh
./build.sh                          # 构建到 ./bin，需要 ../../../sing-box_mod 和模块代理
REALCLIENT=1 go test -v -run 'TestClientMatrix|TestFallbackProbes' .
REALCLIENT_MEASURE=1 REALCLIENT_OUT=out go test -timeout 60m -v -run TestMeasure .
```

或在仓库根目录执行 `make realclient`、`make measure`。没有 `REALCLIENT=1` 时只运行解析器等单元测试，`make test` 即如此。

| 环境变量 | 作用 |
| --- | --- |
| `REALCLIENT_BIN` | 二进制目录，默认 `./bin`；缺少的客户端被跳过，缺少 `sing-box-legacy` 时不测 legacy |
| `REALCLIENT_OUT` | 保留日志、配置与报告（`matrix.md`、`fallback.md`、`measure.md`、`measure.json`、`traces.json`） |
| `REALCLIENT_SAMPLES` | 每个客户端和模式的冷启动次数，默认 10 |
| `REALCLIENT_PROFILES` | 额外整形参数，JSON 对象，如 `{"lean":{"max_padding_bytes":8192,"max_records":12}}` |
| `REALCLIENT_LOG` | sing-box/Mihomo 日志级别，默认 `warn` |
| `SING_BOX_DIR`、`SING_BOX_LEGACY_REF` | `build.sh` 使用的 sing-box 工作区和修改前提交，默认 `HEAD`；提交修改后应改为之前的提交 |

测试服务端的 `handshake_timeout` 设为 3 秒以缩短探测用时，默认值是 10 秒。

## 指标含义

- 每个冷启动样本是一个新客户端进程的第一条 TCP 连接，从外层 TLS 握手到第一个页面完成后 300 ms。复用阶段是同一进程继续通过新流获取 5 个页面，按时间窗口统计，包括可能新建的连接。
- TLS 字节包含 5 字节 record 头；`short` 是不超过 64 字节的 record，只能承载裸控制帧；`distinct` 是前 16 个应用数据 record 中不同长度的个数；`top len (share)` 是最常见长度及其占比，固定长度表现为占比高。
- 可分离度是对前 16 个应用数据 record 的带方向长度做留一法最近邻分类，每个样本是独立进程的独立连接。它只说明本地实验中序列差异有多大，**不是 DPI 识别率**：真实分类器还会用时序、流量规模和大量真实样本，本地回环的时序也不代表真实网络。

## 分析真实网络抓包

中继测量只覆盖本地回环。灰度时在节点上抓包，再用同一套统计比较：

```sh
tcpdump -i eth0 -s 0 -w control.pcap 'tcp port 443'   # 对照节点或时间段
tcpdump -i eth0 -s 0 -w shaped.pcap  'tcp port 443'   # 启用整形的节点或时间段
go run ./cmd/tlstrace -port 443 control=control.pcap shaped=shaped.pcap https=baseline.pcap
```

`tlstrace` 读取经典 pcap（不支持 pcapng，可用 `editcap -F pcap` 转换），按序号重组 TCP，忽略重传与乱序，再切分 TLS record；输出每组的连接数、上下行字节、前 N 个 record 的形状，以及其他组相对第一组的可分离度。被截断的包（应使用 `-s 0`）、未抓到握手的连接和抓包丢失会标为 malformed 并排除。两组抓包必须来自相同客户端、相同网络和相同业务负载，否则差异不能归因于服务端设置。
