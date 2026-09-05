# wg-subscriber

**WireGuard 客户端订阅器** – 通过 MQTT 协议自动接收服务端配置，动态管理本地 WireGuard 接口，支持 LAN 切换、端口更换、中继、流量上报等功能。

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org/)

---

## 特点

- 🔌 MQTT 订阅 – 订阅 full/delta 主题，实时同步服务端 Peer 配置
- 🧠 智能端点切换 – 支持自动切换至同网段 LAN 端点（ENABLE_LAN_SWITCHING）
- 🔁 端口更换 – 网络故障时自动更换监听端口（可选）
- 🧩 中继支持 – 当直连 Peer 失效时，自动通过中继节点转发（需服务端配合）
- 📊 流量上报 – 定期向 MQTT 上报本节点流量统计（ENABLE_TRAFFIC_REPORT）
- 🛡️ AmneziaWG 支持 – 支持协议混淆（需设置 WG_USE_AWG=1 并配置）
- 🗄️ 纯客户端 – 无状态，仅依赖本地 WireGuard 接口和 MQTT Broker

---

## 架构概览

    ┌─────────────────────────────────────────────────┐
    │              wg-subscriber                      │
    ├─────────────────────────────────────────────────┤
    │  MQTT 订阅  →  解析配置  →  本地 WireGuard 接口 │
    │  (full/delta)   (路由/Peer)   (wg/awg 工具)    │
    └─────────────────────────────────────────────────┘
            │                        │
            ▼                        ▼
       MQTT Broker            WireGuard 内核/用户态
       (Mosquitto)            (wg0 接口)

- 通过 MQTT 接收服务端发布的全量快照和增量更新。
- 应用路由、添加/更新/删除 Peer。
- 可选功能：LAN 切换、端口更换、中继、流量上报。

---

## 快速开始

### 前置条件

- Linux 系统（支持内核 WireGuard）
- 已安装 WireGuard（或 AmneziaWG / GoTun）
- MQTT Broker（如 Mosquitto）

### 1. 获取二进制
```bash
# cargo安装
catgo install wg-subscriber
# 编译（需要 Rust 工具链）
git clone https://github.com/automate-org/wg-subscriber
cd wg-subscriber
cargo build --release

# 或者下载预编译版本
```

### 2. 配置环境变量
```bash
export MQTT_HOST=<your-mqtt-broker-ip>
export MQTT_PORT=1883
export WG_INTERFACE=wg0
export WG_BACKEND=kernel   # 可选 kernel / gotatun / amneziawg
# 若使用 userspace 后端，需指定命令（示例）
export WG_USERSPACE_CMD="/usr/bin/gotatun -loglevel=info"
# 可选功能开关
export ENABLE_LAN_SWITCHING=1
export ENABLE_PORT_CHANGE_ON_NETWORK_LOSS=1
export ENABLE_TRAFFIC_REPORT=1
```
### 3. 启动服务
```bash
./target/release/wg-subscriber
```
首次运行会自动创建 WireGuard 接口（若不存在）并生成私钥。

---

## 配置参考

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| MQTT_HOST | ✅ | - | MQTT Broker 地址 |
| MQTT_PORT | - | 1883 | MQTT 端口 |
| MQTT_USER | - | - | 用户名 |
| MQTT_PASS | - | - | 密码 |
| MQTT_TLS_ENABLE | - | false | 启用 TLS |
| MQTT_TLS_CA_CERT | - | 系统 CA | CA 证书路径 |
| WG_INTERFACE | - | wg0 | 接口名称 |
| WG_LISTEN_PORT | - | 51822 | 监听端口 |
| WG_BACKEND | - | kernel | 后端类型：kernel, gotatun, amneziawg |
| WG_USERSPACE_CMD | 条件 | - | 用户态后端命令（当 WG_BACKEND 非 kernel 时必填） |
| ENABLE_LAN_SWITCHING | - | false | 启用 LAN 端点自动切换 |
| ENABLE_PORT_CHANGE_ON_NETWORK_LOSS | - | false | 网络失联时自动更换监听端口 |
| ENABLE_SCHEDULED_PORT_CHANGE | - | false | 定时更换端口（防止 NAT 老化） |
| SCHEDULED_PORT_CHANGE_INTERVAL | - | 7200 | 定时更换间隔（秒） |
| ENABLE_TRAFFIC_REPORT | - | false | 启用流量上报（MQTT） |
| RE_REGISTER_INTERVAL | - | 600 | 定期重注册间隔（秒） |
| WG_PORT_MIN / WG_PORT_MAX | - | 1024 / 65535 | 端口更换范围 |
| RELAY_CIDR_V4 / RELAY_CIDR_V6 | - | 10.254.1.0/24 / fd00:1:1::/64 | 中继网段 |
| LAN_HANDSHAKE_WAIT_SECS | - | 8 | 切换 LAN 后等待握手超时（秒） |
| WG_STATE_CACHE_TTL | - | 2 | 缓存 WireGuard 状态的秒数 |
| WG_USE_AWG | - | false | 使用 awg 命令（启用 AmneziaWG） |

---

## MQTT 主题

客户端订阅以下主题（服务端发布）：

| 主题 | 说明 |
|------|------|
| wg/<interface>/full | 全量快照（Zstd 压缩 JSON） |
| wg/<interface>/delta | 增量更新（add/update/remove/set_routes） |
| wg/<interface>/full/response/<client_id> | 服务端回复的单播快照（用于注册后即时同步） |

客户端发布：

| 主题 | 说明 |
|------|------|
| wg/<interface>/register | 注册请求（包含公钥、hostname、本地 LAN IP 列表） |
| wg/<interface>/full/request/<client_id> | 请求全量快照 |
| wg/<interface>/traffic | 流量上报（若启用） |

---

## 高级功能

### LAN 端点切换

当设置 ENABLE_LAN_SWITCHING=1 时，客户端会尝试将 Peer 的端点切换为同网段的内网 IP，以获得更低延迟和更高吞吐量。切换后会在一定时间内验证握手，若失败则自动回退。

### 端口更换

- 网络失联触发：ENABLE_PORT_CHANGE_ON_NETWORK_LOSS=1 时，若所有 Peer 无握手且无 LAN 活动，则更换监听端口。
- 定时触发：ENABLE_SCHEDULED_PORT_CHANGE=1 时，每隔 SCHEDULED_PORT_CHANGE_INTERVAL 秒更换一次端口，以绕过 NAT 端口限制。

### 中继

当服务端配置了中继网段（RELAY_CIDR_V4/V6）时，客户端会动态发现中继节点。若直连 Peer 持续无握手，客户端会将该 Peer 的 IP 挂载到某个健康中继节点下，实现流量转发。

### 流量上报

启用 ENABLE_TRAFFIC_REPORT=1 后，客户端每隔 30 秒向 wg/<interface>/traffic 发布本机所有 Peer 的收发增量及总量，便于服务端监控。

---

## AmneziaWG 支持

设置 WG_USE_AWG=1 并使用 amneziawg 后端（WG_BACKEND=amneziawg）时，客户端会从全量快照中读取 amnezia 字段并应用到本地接口。需确保 awg 命令可用。

---

## 持久化

客户端本身不存储任何持久化数据。所有配置均从 MQTT 快照动态获取，接口私钥保存在 /etc/wireguard/<interface>.key。重启后会自动重新注册并拉取最新配置。

---

## 贡献

欢迎提交 Issue 和 Pull Request。开发前请确保：

- Rust 1.85+
- 遵循现有代码风格
- 添加必要的测试
```bash
cargo fmt
cargo clippy -- -D warnings
cargo test
```
---

## 许可证

[MIT License](LICENSE)

---

## 常见问题

**Q: 注册后长时间未收到配置？**  
A: 检查 MQTT 连接和服务端是否正常工作，客户端会自动重试注册。

**Q: LAN 切换后无法通信？**  
A: 确保同网段路由可达，且防火墙允许 UDP 端口。客户端会在超时后回退。

**Q: 如何更换私钥？**  
A: 删除 /etc/wireguard/<interface>.key 后重启，客户端会重新生成并自动注册。

**Q: 中继如何工作？**  
A: 服务端预先配置中继网段，客户端自动发现中继节点并维护路由，详细机制参见源码。

---
