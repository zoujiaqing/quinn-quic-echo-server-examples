# QUIC Echo Server

一个基于QUIC协议的高性能回声服务器实现，使用Rust和Quinn库构建。该服务器可以接收客户端消息并将其回传，支持三种简洁的认证模式。

## 架构简化

该项目已经简化为三种合理的认证模式：

### 1. 不安全模式（默认）
- **用途**：测试和开发
- **特点**：完全跳过证书验证，连接速度快
- **适用场景**：本地测试、开发环境、内网通信

### 2. 单向认证模式（PEM证书）
- **用途**：生产环境的基本安全验证
- **特点**：客户端验证服务器证书，确保连接到正确的服务器
- **适用场景**：大多数生产部署场景

### 3. 双向认证模式（Mutual TLS）
- **用途**：高安全要求的生产环境
- **特点**：服务器和客户端互相验证证书，双向身份认证
- **适用场景**：企业级应用、API服务、高安全要求的通信

### 我们删除了什么？

我们移除了"自动生成证书并保存"的模式，因为：
- **与标准不符**：QUIC/TLS标准流程中没有这种用法
- **逻辑冗余**：自动生成的证书还是需要客户端读取文件验证，和PEM模式没有区别
- **实用性差**：每次生成的证书都不同，客户端无法预先知道

## 特性

- 基于QUIC协议的高性能通信
- 三种简洁的认证模式（不安全模式用于测试，PEM证书模式用于生产，Mutual TLS用于高安全要求）
- 自动证书生成和管理
- 客户端和服务器之间的双向通信
- 简单的Echo服务示例
- 可配置的接收窗口大小和超时参数

## 构建

```bash
cargo build --release
```

## 证书管理

对于生产环境，您需要准备PEM格式的证书文件。

### 使用OpenSSL生成证书

您可以使用以下命令生成自签名证书：

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout private.pem -out public.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

这将生成两个文件：
- `public.pem`: 包含公钥和证书
- `private.pem`: 包含私钥

## 运行服务器

### 默认模式（不安全 - 适合测试）

```bash
cargo run --example server
```

### PEM证书模式（安全 - 适合生产）

使用PEM格式证书和私钥运行服务器：

```bash
cargo run --example server -- --cert-pem server.pem --key-pem private.pem
```

### 客户端认证模式

要求客户端提供有效证书：

```bash
cargo run --example server -- --cert-pem server.pem --key-pem private.pem --require-client-cert
```

## 服务器参数

服务器支持以下命令行参数：

- `<listen_address>`: 监听地址，默认为 `127.0.0.1:5001`
- `--cert-pem <PATH>`: PEM格式证书路径
- `--key-pem <PATH>`: PEM格式私钥路径
- `--require-client-cert`: 要求客户端提供证书进行认证

## 运行客户端

### 默认模式（不安全 - 完美适合测试）

```bash
cargo run --example client
```

### 安全模式（使用证书验证服务器）

```bash
cargo run --example client -- --cert-pem server.pem
```

### 客户端认证模式

使用客户端证书进行双向认证：

```bash
cargo run --example client -- --cert-pem client.pem --key-pem client-key.pem --client-auth
```

### 客户端认证 + 跳过服务器验证

用于特殊测试场景：

```bash
cargo run --example client -- --cert-pem client.pem --key-pem client-key.pem --client-auth --insecure
```

## 客户端参数

客户端支持以下命令行参数：

- `-m, --message <MESSAGE>`: 要发送的消息内容，默认为 "Hello, world!"
- `-r, --repeat <COUNT>`: 重复发送次数，默认为 1
- `-t, --timeout <MILLISECONDS>`: 超时时间（毫秒），默认为 5000
- `--insecure`: 不验证证书（不安全模式）
- `--cert-pem <PATH>`: PEM证书文件路径
- `--key-pem <PATH>`: 私钥文件路径
- `--server <ADDRESS>`: 服务器地址，默认为 `127.0.0.1:5001`
- `--client-auth`: 启用客户端证书认证

## 使用示例

### 基本测试（最简单）

```bash
# 终端1：启动服务器
cargo run --example server

# 终端2：运行客户端
cargo run --example client -- -m "Hello QUIC!" -r 3
```

### 安全连接测试

```bash
# 1. 生成证书
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout server-key.pem -out server.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 2. 启动安全服务器
cargo run --example server -- --cert-pem server.pem --key-pem server-key.pem

# 3. 使用安全客户端连接
cargo run --example client -- --cert-pem server.pem -m "Secure Hello!"
```

### 双向认证测试

```bash
# 1. 生成服务器证书
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout server-key.pem -out server.pem \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 2. 生成客户端证书
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes \
  -keyout client-key.pem -out client.pem \
  -subj "/CN=client"

# 3. 启动要求客户端认证的服务器
cargo run --example server -- --cert-pem server.pem --key-pem server-key.pem --require-client-cert

# 4. 使用客户端证书连接
cargo run --example client -- --cert-pem server.pem --key-pem client-key.pem --client-auth -m "Mutual TLS Hello!"
```

## 项目哲学

该库设计理念是**测试友好和便利优先**：
- **默认**：不安全模式（无证书验证）- 适合快速测试
- **基础安全**：单向认证（客户端验证服务器）- 适合大多数生产环境
- **高安全**：双向认证（Mutual TLS）- 适合高安全要求场景
- **简洁**：最少参数，最大可用性

这种设计让开发者能够：
1. 立即开始测试，无需配置任何证书
2. 在需要时轻松添加基础安全性
3. 在高安全要求时启用双向认证
4. 避免复杂的证书管理
