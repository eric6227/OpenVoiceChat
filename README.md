# OpenVoiceChat

一个简单的实时语音聊天系统。

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)
[![Docker Image](https://img.shields.io/badge/ghcr.io-eric6227%2Fopenvoicechat-2496ED?logo=docker)](https://github.com/eric6227/OpenVoiceChat/pkgs/container/openvoicechat)

## 项目概述

OpenVoiceChat 是一个轻量级、低延迟的语音聊天解决方案，采用客户端-服务器-管理员三端架构。适用于团队协作、在线客服、语音会议等场景。

### 核心组件

| 组件 | 说明 | 端口 |
|------|------|------|
| **服务器 (Server)** | 音频数据转发、用户管理、设备指纹识别、封禁管理 | 9090 (客户端), 9091 (管理员) |
| **客户端 (Client)** | 用户语音聊天界面（GUI/CLI），支持独听、静音、音量调节 | 连接 9090 |
| **管理员 (Admin)** | 监控和管理界面，可踢人、封禁设备、查看在线用户 | 连接 9091 |

## 功能特性

### 实时通信
- 低延迟语音传输（基于UDP + RUDP协议）
- Opus 音频编解码器（32kbps，16kHz采样率），高质量低带宽
- 音频抖动缓冲（Jitter Buffer）平滑网络波动（96帧 = 1.92s缓冲，首次填充480ms，恢复填充120ms）
- 音频包超时丢弃机制（200ms），防止延迟累积
- 智能音量均衡：实际音量 = 用户音量设置 / 未静音活跃用户数，防止多用户同时说话时音量叠加
- 降噪功能：RMS 门限降噪，用户可调节强度（0-100），默认关闭，在发送前处理

### 安全特性
- **AES-256-GCM 加密传输**：所有音频数据端到端加密
- **PBKDF2-HMAC-SHA256 密钥派生**：100,000次迭代，从密码派生会话密钥
- **RSA-2048 公钥加密**：认证时加密密码传输
- **设备指纹识别**：基于MAC、CPU、主板、BIOS的硬件指纹
- **速率限制**：防止暴力破解（5次失败后封禁5分钟）
- **心跳检测**：30秒超时自动断开，防止未授权连接
- **Windows DPAPI**：安全存储本地密码
- **服务器公钥指纹验证**：类似SSH的信任机制

### 管理功能
- 实时在线用户监控
- 封禁设备（Ban）- 基于硬件指纹永久封禁，IP封禁7天自动过期
- 解除封禁（Unban）
- 查看封禁列表
- 踢出用户（Kick）
- 不合规硬件自动封禁：客户端缺少关键硬件指纹（MAC/CPU/主板/BIOS）时自动封禁

### 文字聊天
- 文字聊天与音频共用同一UDP端口，使用RUDP协议传输
- 文本长度限制200字，所有人可见，显示格式为 `[用户名] 文本内容`
- 消息在服务器解密，确保管理员可见
- 悄悄话模式：使用 `/msg 用户名 内容` 向指定用户发送私密消息，服务器解密后定向加密发送给目标用户和管理员
- 文字聊天可用性与语音一致：可选管理员加入后才可用（共用 `OVC_REQUIRE_ADMIN` 环境变量），服务器端双重校验
- 全部文字消息在服务器端记录日志（`logs/chat.log`），管理员消息单独标记
- 管理员也可以发送文字消息，与客户端功能一致

### 其他特性
- 图形化界面 (Tkinter GUI)
- 音量调节和增益控制
- 静音功能（全局/指定用户）
- 独听功能（Solo Mode，只听指定用户）
- 用户独立音量控制
- 本地监听（听自己的声音）
- 音频录制（可选，需用户同意）
- 隐私协议弹窗（首次连接时显示设备指纹收集、管理员监听、免责声明）
- 自动重连：连接断开后自动重连，指数退避（1s → 2s → 4s → ... 最大60s），手动断开不重连
- 配置文件持久化
- 已知服务器自动记忆（类似SSH known_hosts）
- 支持打包为独立可执行文件
- Docker 容器化部署（服务器端）
- 服务器 RSA 密钥持久化（首次启动自动生成 `server_rsa_key.pem`）

## 系统架构

```mermaid
graph LR
    Client["👤 Client<br/>(GUI App)"] <-->|"UDP<br/>Port: 9090"| Server["🖧 Server<br/>(Backend)"]
    Server <-->|"UDP<br/>Port: 9091"| Admin["👨‍💼 Admin<br/>(GUI App)"]

    classDef clientClass fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef serverClass fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef adminClass fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    
    class Client clientClass
    class Server serverClass
    class Admin adminClass
```

### 端口说明

| 端口 | 协议 | 用途 |
|------|------|------|
| 9090 | UDP | 客户端连接（认证+音频数据+文字聊天） |
| 9091 | UDP | 管理员连接（认证+音频数据+文字聊天） |

## 技术栈

- **Python 3.11+**
- **PyAudio**: 音频采集和播放
- **PyCryptodome**: AES-256-GCM 加密、RSA 公钥加密
- **PyYAML**: 配置文件管理
- **Tkinter**: 图形用户界面
- **PyInstaller**: 可执行文件打包
- **Docker**: 服务器容器化
- **Opus**: 音频编解码（libopus，32kbps 低延迟语音编码）
- **RUDP**: 可靠UDP协议（自定义实现，用于控制消息和文字聊天）

## 版本说明

### 现有版本
> 格式： `0.大版本.小版本.内部版本`
发行版取前三段，即 `0.大版本.小版本`
[](内部测试使用后三段加-test，即大版本.小版本-test)
- **最新客户端版本**: 0.1.6
- **最新管理员版本**: 0.1.6
- **最新服务器版本**: 0.1.6
> **注意**：服务器端与客户端和管理员端的小版本必须匹配，否则可能会导致连接失败。
例如 0.1.6 的客户端、管理员端可以连接 0.1.6 的服务端。

### 更新说明
- **0.1.6 (2026-07-25)**：添加文字聊天功能（公聊/悄悄话，共用UDP端口），RMS降噪功能，智能音量均衡，JitterBuffer 恢复模式（防止短暂中断后burst-silence），服务器端文字聊天日志与管理门控，RUDP协议传输控制消息和文本，服务器文件日志（server.log + chat.log），修复新客户端连接时OS socket缓冲区积压导致的3秒音频延迟
- **0.1.5 (2026-07-24)**：换用 Opus 编码器
- **0.1.4 (2026-07-24)**：换用新的版本号格式： `0.大版本.小版本.内部版本`
- **1.3.2 (2026-07-22)**: 修复服务器端在多个客户端连接时由于单线程处理导致的音频断断续续以及巨大延迟问题。
- **1.3.1 (2026-07-22)**: 修复了部分敏感数据明文传输的漏洞。
- **1.0.0 (2026-忘了-忘了)**: 初始版本，支持基本的语音聊天功能，但是有巨多bug以及安全漏洞。

## 快速开始

### 前置要求

- Python 3.11 或更高版本（运行源码时需要）
- 麦克风设备
- 公网服务器（远程部署时需要）
- Docker 和 docker-compose（容器化部署时）

### 服务器端安装（推荐 Docker）

**方式一：使用 docker-compose（推荐）**

1. 确保已安装 Docker 和 docker-compose

2. 在项目根目录创建 `docker-compose.yml` 文件，内容如下：

```yaml
version: '3.8'

services:
  openvoicechat-server:
    image: ghcr.io/eric6227/openvoicechat:latest
    container_name: openvoicechat-server
    environment:
      # 必须使用环境变量注入密码，且务必使用强密码
      - OVC_PASSWORD=your_password_here
      # 必须使用环境变量注入密码，且务必使用强密码
      - OVC_ADMIN_PASSWORD=your_admin_password_here
      # 是否启用音频录制 True/False
      - OVC_RECORDING_ENABLED=false
      - OVC_RECORDING_DIR=/app/recordings
      - OVC_RECORDING_DURATION=5
      - OVC_RECORDING_MAX_SIZE=10240
      - OVC_RECORDING_RETENTION=30
      # 是否要求管理员在线才允许语音和文字聊天（默认 false）
      - OVC_REQUIRE_ADMIN=false
    ports:
      - "9090:9090/udp"
      - "9091:9091/udp"
    volumes:
      - ./recordings:/app/recordings
      - ./logs:/app/logs
    restart: unless-stopped
```

> **重要**：请将 `your_password_here` 和 `your_admin_password_here` 替换为强密码。
>
> 建议使用长度超过 24 个字符的字母、数字混合密码，不建议使用特殊字符，以免出现问题。
>
> 提示：若要开启录制，请与用户确认，确保用户同意。

3. 启动服务：

```bash
docker-compose up -d
```

4. 查看日志确认服务启动：

```bash
docker-compose logs -f
```

5. 停止服务：

```bash
docker-compose down
```

#### 日志文件说明

服务器会自动在 `logs/` 目录下生成两类日志文件（需在 `docker-compose.yml` 中挂载 `./logs:/app/logs`）：

| 日志文件 | 说明 | 轮转策略 |
|----------|------|----------|
| `logs/server.log` | 服务器系统日志（认证、连接、错误等） | 10MB/文件，保留5个备份 |
| `logs/chat.log` | 文字聊天日志（公聊、悄悄话、管理员消息） | 10MB/文件，保留5个备份 |

> **注意**：`logs/` 目录通过 Docker volume 挂载到宿主机，日志文件在容器重启后不会丢失。文字聊天日志记录所有用户发送的消息内容，请妥善保管。

**方式二：使用 docker 命令**

```bash
# 在项目根目录下构建（注意 -f 指定 Dockerfile 路径）
docker build -t openvoicechat-server -f server/Dockerfile .

# 运行容器
docker run -d \
  --name openvoicechat-server \
  -e OVC_PASSWORD=your_password_here \
  -e OVC_ADMIN_PASSWORD=your_admin_password_here \
  -p 9090:9090/udp \
  -p 9091:9091/udp \
  openvoicechat-server
```

> **重要**：请将密码替换为强密码。

### 环境变量说明

服务器支持以下环境变量配置：

| 变量名 | 必填 | 默认值 | 说明 |
|--------|------|--------|------|
| `OVC_PASSWORD` | ✅ | 无 | 客户端连接密码 |
| `OVC_ADMIN_PASSWORD` | ✅ | 无 | 管理员连接密码 |
| `OVC_RECORDING_ENABLED` | ❌ | `false` | 是否启用音频录制 |
| `OVC_RECORDING_DIR` | ❌ | `./recordings` | 录音文件存储目录 |
| `OVC_RECORDING_DURATION` | ❌ | `5` | 单个录音文件时长（分钟） |
| `OVC_RECORDING_MAX_SIZE` | ❌ | `10240` | 录音文件最大总大小（MB，默认10GB） |
| `OVC_RECORDING_RETENTION` | ❌ | `30` | 录音文件保留天数（超过期限自动删除） |
| `OVC_REQUIRE_ADMIN` | ❌ | `false` | 管理员离线时是否断开所有客户端（设为 `true` 要求管理员在线才允许语音和文字聊天） |

> **注意**：`OVC_PASSWORD` 和 `OVC_ADMIN_PASSWORD` 是必填项，未设置时服务器将拒绝启动。

### 客户端安装（Windows 推荐 exe 安装包）

直接运行 release 界面的安装包：

- **客户端**：在 release 界面下载并运行 Client 的安装包
- **管理员**：在 release 界面下载并运行 Admin 的安装包

> **注意**：
> - 首次运行可能需要允许Windows防火墙访问网络
> - 安装包可选创建桌面快捷方式

### 客户端安装（其它平台运行源码）

```bash
# 克隆项目
git clone https://github.com/eric6227/OpenVoiceChat.git
cd OpenVoiceChat

# 安装依赖
cd client
pip install -r requirements.txt

# 启动客户端
python main.py
```

### 管理端安装（其它平台运行源码）

```bash
# 安装依赖
cd admin
pip install -r requirements.txt

# 启动管理员界面
python main.py
```

### 服务器端安装（从源码运行）

```bash
# 安装依赖（服务器需要 pycryptodome 和 shared 模块）
cd server
pip install -r requirements.txt

# 返回项目根目录，确保 shared 模块可用
cd ..

# 设置环境变量并启动服务器
# Windows (PowerShell):
$env:OVC_PASSWORD="your_strong_password_here"
$env:OVC_ADMIN_PASSWORD="your_strong_admin_password_here"
python server/main.py

# Linux/macOS:
export OVC_PASSWORD="your_strong_password_here"
export OVC_ADMIN_PASSWORD="your_strong_admin_password_here"
python server/main.py
```

> **注意**：从源码运行时，服务器需要访问项目根目录下的 `shared/` 模块，请确保从项目根目录启动，或保持目录结构完整。

### 命令行参数

**服务器端**：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--log-level` | `INFO` | 日志级别：`DEBUG`、`INFO`、`WARNING`、`ERROR` |
| `--log-dir` | `server/logs` | 日志文件存储目录 |

**客户端**：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--name` | 无 | 预设昵称（跳过GUI输入） |

**管理端**：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--host` | `127.0.0.1` | 服务器地址 |
| `--admin-port` | `9091` | 管理员端口 |
| `--name` | 无 | 管理员昵称 |
| `--password` | 无 | 管理员密码 |
| `--volume` | `1.0` | 播放音量 0.0-2.0 |
| `--list-devices` | - | 列出所有音频设备后退出 |

### 打包为可执行文件

使用 PyInstaller 打包应用程序：

1. 略

### 创建 Windows 安装包（可选）

使用 Inno Setup 创建 Windows 安装程序：

1. 略

## 使用指南

### 客户端使用

1. **首次连接**：
   - 输入服务器地址和端口
   - 输入用户名和连接密码
   - 点击"连接"按钮
   - 验证服务器指纹
  
   > **注意**：首次连接时，务必验证服务器指纹。
指纹应当从可靠的、不可被篡改的渠道获得，如服务器官网或直接由管理员通过微信、QQ等社交软件告知。
获得的指纹只有前一部分，仅需对比客户端收到的指纹的前一部分即可。
若指纹不匹配，请不要连接，先向管理员确认你获得的指纹是否正确。若仍然不匹配，请不要连接，切换网络连接（如开启 VPN 或使用移动网络）进行尝试。只要指纹不匹配，就不能连接。
若连接指纹不匹配的服务器导致被中间人攻击，开发者概不负责。

   - **查看录音状态提示**：
     - 若服务器已开启录音：显示详细录音信息（目的、存储期限、方式、范围），需用户同意
     - 若服务器未开启录音：显示"未开启录音"提示
   - 用户同意后开始发送和接收音频

2. **音频控制**：
   - **静音**：点击用户旁的"M"按钮，停止接收该用户音频
   - **独听**：点击用户旁的"S"按钮，只听指定用户
   - **音量调节**：拖动滑块调整接收音量（全局）
   - **用户音量**：为每个用户独立调节音量
   - **增益控制**：调整麦克风输入增益
   - **本地监听**：听自己的声音，测试麦克风

3. **用户管理**：
   - 在线用户列表显示当前连接的用户
   - 可为每个用户单独设置静音和音量

4. **配置保存**：
   - 连接配置自动保存到 `config.yaml`
   - 已知服务器自动记录到 `known_servers.json`

### 管理员使用

1. **连接服务器**：
   - 输入服务器地址和端口
   - 输入管理员名称和管理员密码
   - 点击"连接"按钮

2. **监控功能**：
   - 实时查看所有在线用户（含设备ID、IP地址、硬件指纹）
   - 监听所有用户或指定用户的音频
   - 查看用户加入/离开事件
   - 标签页切换：在线用户 / 封禁列表

3. **管理操作**：
   - **封禁设备**：点击用户昵称 → 封禁选中用户（基于硬件指纹，永久生效；IP地址7天自动过期）
   - **解除封禁**：在封禁列表标签页中点击"一键解封选中设备"
   - **踢出用户**：点击用户昵称 → 踢出选中用户
   - **静音用户**：点击用户旁的"M"按钮，停止接收该用户音频
   - **刷新封禁列表**：点击"刷新封禁列表"按钮

4. **文字聊天**：
   - 管理员也可以发送文字消息（公聊/悄悄话），与客户端功能一致
   - 管理员能看到所有悄悄话的目标用户名称

5. **封禁列表**：
   - 硬件指纹封禁：永久生效
   - IP地址封禁：7天后自动过期
   - 查看封禁原因、封禁管理员、关联昵称和IP

### 配置文件说明

> 配置文件会自动生成，无需手动配置

**客户端配置 (`client/config.yaml`)**：
```yaml
host: 127.0.0.1
port: 9090
name: 用户名
password_encrypted: <DPAPI加密后的密码>
mute_on_connect: false
mute: false
listen_own: false
volume: 1.0
gain: 1.0
```

**管理员配置 (`admin/config_admin.yaml`)**：
```yaml
host: 127.0.0.1
port: 9091
name: 管理员
password_encrypted: <DPAPI加密后的密码>
volume: 1.0
```

## 安全说明

- 所有音频数据使用 AES-256-GCM 加密传输
- 密码使用 PBKDF2-HMAC-SHA256 派生密钥（100,000 次迭代）
- Windows 平台支持 DPAPI 加密存储密码
- 心跳检测防止未授权连接
- 设备指纹识别防止恶意用户更换IP重新连接
- 速率限制防止暴力破解攻击

### 隐私保护

- 音频录制功能默认关闭
- 连接时自动显示录音状态提示
  - 服务器已开启录音：显示详细录音信息（目的、存储期限、方式、范围），需用户明确同意
  - 服务器未开启录音：显示"未开启录音"提示
- 启用录制需明确用户同意并遵守当地隐私法律
- 录音文件存储在服务器
- 录音目的：用于审查用户言论是否违规
- 录音方式：WAV格式，PCM 32-bit，16000Hz采样率，单声道
- 录音范围：用户发送的所有音频数据，解密后的原始音频保存到服务器
- 存储期限：录音文件最多保存 30 天，超过期限的文件将被自动删除
> 若不同意录音，则无法加入开启录音功能的服务器

## 常见问题

### 音频无法正常工作

- 检查麦克风权限
- 确认 PyAudio 已正确安装（若直接运行源码）
- Linux 用户可能需要安装 PortAudio：`sudo apt-get install portaudio19-dev`
- 检查音频设备是否被其他程序占用

### 连接失败

- 联系服务器管理员，确认服务器正在运行
- 检查防火墙设置，确保端口 9090/9091 已开放
- 验证配置中的服务器地址和端口
- 检查网络连接是否正常
- 删除安装目录下的 `known_servers.json` 文件，重新启动软件
> 默认安装目录：`C:\Users\用户名\AppData\Local\Programs\OpenVoiceChat-Client`或`C:\Users\用户名\AppData\Local\Programs\OpenVoiceChat-Admin`

### 服务器启动失败

- 确认已设置 `OVC_PASSWORD` 和 `OVC_ADMIN_PASSWORD` 环境变量
- 检查端口是否被其他程序占用
- Docker 部署时检查容器日志：`docker logs openvoicechat-server`

### 忘记密码

- 服务器端：重新设置环境变量并重启服务器
- 客户端：输入新密码

### 运行出错

- 确保已安装所有依赖：`pip install -r requirements.txt`
- Windows 用户可能需要安装 Visual C++ Redistributable
- 检查杀毒软件是否误删可执行文件

### 音频质量差

- 调整增益控制（Gain）避免音量过小
- 检查网络延迟和带宽
- 尝试调整抖动缓冲区大小（需修改源码）

### 项目结构

```
OpenVoiceChat/
├── shared/                         # 共享模块
│   ├── __init__.py                  # 模块导出
│   ├── constants.py                 # 消息协议常量
│   ├── crypto.py                    # AES-256-GCM 加密 / Nonce 池
│   ├── audio_utils.py               # Opus 压缩 / 抖动缓冲 / 音频播放
│   ├── opus_utils.py                # Opus 编解码器封装
│   ├── noise.py                     # RMS 降噪
│   ├── rudp.py                      # 可靠 UDP 协议
│   ├── device_fingerprint.py        # 设备指纹采集
│   └── security_utils.py            # DPAPI 加密 / 指纹验证
│
├── server/                          # 服务器端
│   ├── main.py                      # 服务器主程序
│   ├── requirements.txt             # 服务器依赖
│   ├── Dockerfile                   # Docker 镜像构建
│   ├── server_rsa_key.pem           # RSA 密钥对（自动生成，首次启动时创建）
│   ├── ban_list.json                # 封禁列表
│   ├── device_fingerprints.json     # 设备指纹库
│   ├── recordings/                  # 录音文件目录
│   └── logs/                        # 日志文件目录（server.log + chat.log）
│
├── client/                          # 客户端
│   ├── main.py                      # 客户端主程序 (GUI)
│   ├── config.yaml                  # 客户端配置
│   ├── requirements.txt             # 客户端依赖
│   └── known_servers.json           # 已知服务器指纹
│
├── admin/                           # 管理员端
│   ├── main.py                      # 管理员主程序 (GUI)
│   ├── config_admin.yaml            # 管理员配置
│   ├── requirements.txt             # 管理员依赖
│   └── known_servers_admin.json     # 已知服务器指纹
│
├── VoiceChatClient.spec             # 客户端 PyInstaller 打包配置
├── VoiceChatAdmin.spec              # 管理员 PyInstaller 打包配置
├── dist/
│   ├── OpenVoiceChatClient.iss      # 客户端 Inno Setup 安装脚本
│   └── OpenVoiceChatAdmin.iss       # 管理员 Inno Setup 安装脚本
├── docker-compose.yml               # Docker Compose 配置
├── requirements.txt                 # 项目根依赖
└── README.md                        # 项目文档
```

| 模块 | 文件 | 说明 |
|------|------|------|
| 协议常量 | `shared/constants.py` | 所有消息类型常量、音频参数、缓冲区大小 |
| 加密 | `shared/crypto.py` | AES-256-GCM 加解密、全局 Nonce 池 |
| 音频 | `shared/audio_utils.py` | Opus 压缩/解压、JitterBuffer、AudioPlayer |
| 编解码 | `shared/opus_utils.py` | Opus 编解码器跨平台封装 |
| 降噪 | `shared/noise.py` | RMS 门限降噪（0-100 强度可调） |
| 可靠UDP | `shared/rudp.py` | RUDP 协议实现（ACK/重传/去重） |
| 设备指纹 | `shared/device_fingerprint.py` | 硬件指纹采集（MAC/CPU/主板/BIOS） |
| 安全 | `shared/security_utils.py` | DPAPI 密码存储、服务器指纹验证 |
| 服务器 | `server/main.py` | UDP 接收循环、认证、转发、管理 |
| 客户端 | `client/main.py` | Tkinter GUI、音频采集/播放、聊天 |
| 管理员 | `admin/main.py` | Tkinter GUI、监控面板、封禁管理 |

## 数据包规范

系统使用自定义二进制协议进行通信，分为三类：**RUDP 控制消息**、**音频数据包** 和 **文本消息**。

所有消息均通过 UDP 传输。音频包使用原始 UDP（低延迟），控制消息和文本消息使用 RUDP 协议（可靠传输）。

---

### 一、RUDP 基础格式

所有非音频消息均使用 RUDP（Reliable UDP）协议封装：

```
字节偏移 | 大小  | 字段         | 说明
---------|-------|-------------|--------------------------
0        | 1     | msg_type    | 消息类型（见下方消息类型表）
1        | 2     | seq_num     | 序列号（大端序，0-65535循环）
3        | 1     | flags       | 标志位（见下方标志说明）
4        | 4     | payload_len | 负载长度（大端序，不含头部）
8        | N     | payload     | 负载数据（长度由 payload_len 指定）
```

**RUDP 头部总长度：8 字节**

**Flags 标志位：**

| 值   | 常量               | 说明                               |
|------|-------------------|------------------------------------|
| 0x01 | NEEDS_ACK         | 发送方期望接收方回复 ACK            |
| 0x02 | IS_ACK            | 此消息是一个 ACK 确认               |
| 0x04 | IS_RESPONSE       | 此消息是对请求的响应                |

**常见组合：**
- `flags=0`：单向通知，无需确认（用于心跳、广播等）
- `flags=0x01` (NEEDS_ACK)：请求，期望对方回复
- `flags=0x03` (NEEDS_ACK | IS_ACK)：无效组合
- `flags=0x05` (NEEDS_ACK | IS_RESPONSE)：响应，期望对方回复 ACK

---

### 二、音频数据包格式（MSG_TYPE_AUDIO = 2）

音频包**不使用 RUDP 封装**，直接通过 UDP 发送以获得最低延迟。

#### 客户端 → 服务器

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 1     | msg_type       | 固定为 2 (MSG_TYPE_AUDIO)
1        | 4     | user_id        | 发送者用户ID（大端序）
5        | 8     | timestamp      | 发送时间戳（double，大端序，Unix秒）
13       | 4     | encrypted_len  | 加密后音频数据长度（大端序）
17       | N     | encrypted_data | AES-256-GCM 加密的 Opus 压缩音频
```

**加密前流程：** PCM(16bit, 16kHz, 单声道) → Opus编码(32kbps) → AES-256-GCM加密

#### 服务器 → 客户端/管理员

```
字节偏移 | 大小  | 字段             | 说明
---------|-------|-----------------|--------------------------
0        | 1     | msg_type        | 固定为 2 (MSG_TYPE_AUDIO)
1        | 4     | sender_id       | 发送者用户ID（大端序）
5        | 1     | sender_name_len | 发送者昵称字节长度
6        | N     | sender_name     | 发送者昵称（UTF-8）
6+N      | 8     | timestamp       | 原始时间戳（double，大端序）
14+N     | 4     | encrypted_len   | 重新加密后音频数据长度（大端序）
18+N     | M     | encrypted_data  | 使用接收者会话密钥重新加密的音频
```

---

### 三、消息类型总览

| 类型 | 值  | 方向              | 说明               | 传输方式     |
|------|-----|-------------------|--------------------|-------------|
| MSG_TYPE_JOIN | 1 | C→S | 客户端加入请求 | RUDP(可靠) |
| MSG_TYPE_AUDIO | 2 | C↔S↔C/A | 音频数据包 | UDP(原始) |
| MSG_TYPE_ADMIN_JOIN | 4 | A→S | 管理员加入请求 | RUDP(可靠) |
| MSG_TYPE_USER_LIST | 5 | S→C/A | 用户列表 | RUDP(广播) |
| MSG_TYPE_USER_JOINED | 6 | S→C/A | 用户加入/离开事件 | RUDP(广播) |
| MSG_TYPE_HEARTBEAT | 7 | C/A→S | 心跳包 | RUDP(单向) |
| MSG_TYPE_LEAVE | 8 | C/A→S, S→C | 离开/踢出通知 | RUDP |
| MSG_TYPE_AUTH_SUCCESS | 9 | S→C/A | 认证成功 | RUDP(可靠) |
| MSG_TYPE_AUTH_FAIL | 10 | S→C/A | 认证失败 | RUDP(可靠) |
| MSG_TYPE_ADMIN_BAN | 11 | A→S | 封禁设备命令 | RUDP(可靠) |
| MSG_TYPE_ADMIN_KICK | 12 | A→S | 踢出用户命令 | RUDP(可靠) |
| MSG_TYPE_BANNED | 13 | S→C | 设备被封禁通知 | RUDP |
| MSG_TYPE_ADMIN_GET_BAN_LIST | 14 | A→S | 请求封禁列表 | RUDP(可靠) |
| MSG_TYPE_BAN_LIST | 15 | S→A | 封禁列表数据 | RUDP(广播) |
| MSG_TYPE_ADMIN_UNBAN | 16 | A→S | 解除封禁命令 | RUDP(可靠) |
| MSG_TYPE_ADMIN_NOT_ONLINE | 17 | S→C | 管理员不在线通知 | RUDP |
| MSG_TYPE_RECORDING_NOTICE | 18 | S→C | 录音状态通知 | RUDP |
| MSG_TYPE_RECORDING_CONSENT | 19 | C→S | 客户端录音同意响应 | RUDP(单向) |
| MSG_TYPE_UDP_PORT | 20 | (保留) | UDP端口通知 | - |
| MSG_TYPE_ADMIN_ONLINE | 21 | S→C | 管理员上线通知 | RUDP(广播) |
| MSG_TYPE_ADMIN_OFFLINE | 22 | S→C | 管理员下线通知 | RUDP(广播) |
| MSG_TYPE_DUPLICATE_NAME | 23 | S→C | 昵称重复通知 | RUDP(可靠) |
| MSG_TYPE_TEXT_CHAT | 24 | C/A→S | 发送文本消息 | RUDP(单向) |
| MSG_TYPE_TEXT_MESSAGE | 25 | S→C/A | 广播文本消息 | RUDP(广播) |

> 方向说明：C=客户端(Client)，A=管理员(Admin)，S=服务器(Server)

---

### 四、各消息详细格式

#### 4.1 MSG_TYPE_JOIN (1) — 客户端加入

**步骤1：客户端请求 RSA 公钥**
```
payload: 空（0字节）
```
服务器回复：`[pub_key_len(4)][public_key_bytes(N)]`（RUDP 响应）

**步骤2：客户端发送认证信息**
```
字节偏移 | 大小  | 字段                  | 说明
---------|-------|----------------------|--------------------------
0        | 4     | name_len             | 昵称字节长度（UTF-8）
4        | N     | name                 | 昵称（UTF-8，最大128字节）
4+N      | 4     | encrypted_pwd_len    | RSA加密密码长度
8+N      | M     | encrypted_password   | RSA-2048 OAEP 加密的密码
8+N+M    | 4     | fingerprints_len     | 设备指纹JSON长度
12+N+M   | K     | fingerprints_json    | 设备指纹JSON（UTF-8，最大1024字节）
```

**设备指纹 JSON 格式：**
```json
{
  "mac": "mac地址哈希",
  "cpu": "CPU ID哈希",
  "motherboard": "主板序列号哈希",
  "bios": "BIOS序列号哈希"
}
```

#### 4.2 MSG_TYPE_ADMIN_JOIN (4) — 管理员加入

格式与 MSG_TYPE_JOIN 完全相同，但使用管理员端口（9091）和 `ADMIN_PASSWORD` 验证。

#### 4.3 MSG_TYPE_AUTH_SUCCESS (9) — 认证成功

```
字节偏移 | 大小  | 字段                   | 说明
---------|-------|-----------------------|--------------------------
0        | 32    | salt                  | PBKDF2 盐值
32       | 12    | nonce                 | AES-GCM nonce
44       | 16    | tag                   | AES-GCM 认证标签
60       | 32    | encrypted_session_key | 加密的会话密钥
92       | 4     | user_id               | 服务器分配的用户ID（大端序）
```

**会话密钥派生：** `PBKDF2-HMAC-SHA256(password, salt, 100000 iterations) → AES-256-GCM decrypt(session_key)`

#### 4.4 MSG_TYPE_AUTH_FAIL (10) — 认证失败

```
payload: 空（0字节）
```

#### 4.5 MSG_TYPE_HEARTBEAT (7) — 心跳包

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度
4        | N     | encrypted_name | AES-256-GCM 加密的昵称（UTF-8）
```

心跳间隔：3秒，超时：30秒（服务器端）

#### 4.6 MSG_TYPE_USER_LIST (5) — 用户列表

```
payload: AES-256-GCM 加密的 JSON 字符串
```

**客户端收到的解密后 JSON：**
```json
[{"id": 1, "name": "用户A"}, {"id": 2, "name": "用户B"}]
```

**管理员收到的解密后 JSON（含详细信息）：**
```json
[{
  "id": 1,
  "name": "用户A",
  "ip": "192.168.1.100",
  "fingerprints": {"mac": "abc123...", "cpu": "def456..."}
}]
```

#### 4.7 MSG_TYPE_USER_JOINED (6) — 用户事件

```
payload: AES-256-GCM 加密的事件文本
```

解密后格式：`"{name} has joined"` 或 `"{name} has left"`

#### 4.8 MSG_TYPE_LEAVE (8) — 离开/踢出

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度
4        | N     | encrypted_name | AES-256-GCM 加密的昵称（UTF-8）
```

当服务器踢出用户时，发送空 payload（0字节）。

#### 4.9 MSG_TYPE_BANNED (13) — 设备被封禁

```
payload: 空（0字节）
```

#### 4.10 MSG_TYPE_ADMIN_BAN (11) — 封禁设备命令

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度
4        | N     | encrypted_json | AES-256-GCM 加密的 JSON
```

**解密后 JSON：**
```json
{"user_id": 1, "reason": "违规行为"}
```

#### 4.11 MSG_TYPE_ADMIN_KICK (12) — 踢出用户命令

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度
4        | N     | encrypted_json | AES-256-GCM 加密的 JSON
```

**解密后 JSON：**
```json
{"user_id": 1}
```

#### 4.12 MSG_TYPE_ADMIN_GET_BAN_LIST (14) — 请求封禁列表

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度（通常为0）
4        | N     | encrypted_data | AES-256-GCM 加密的数据（通常为空）
```

#### 4.13 MSG_TYPE_BAN_LIST (15) — 封禁列表数据

```
payload: AES-256-GCM 加密的 JSON 数组
```

**解密后 JSON 数组元素格式：**
```json
{
  "device_id": "唯一标识",
  "fingerprints": [{"type": "mac", "value": "abc123...", "value_short": "abc123...", "reason": "", "expires_at": ""}],
  "names": ["关联昵称"],
  "ips": ["关联IP"],
  "banned_at": "ISO时间戳",
  "first_banned": "ISO时间戳",
  "banned_by": "管理员名",
  "reason": "原因",
  "expires_at": "过期时间（IP封禁）或空（永久）"
}
```

#### 4.14 MSG_TYPE_ADMIN_UNBAN (16) — 解除封禁命令

```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 4     | encrypted_len  | 加密数据长度
4        | N     | encrypted_json | AES-256-GCM 加密的 JSON
```

**解密后 JSON：**
```json
{"device_key": "封禁设备唯一标识"}
```

#### 4.15 MSG_TYPE_ADMIN_NOT_ONLINE (17) — 管理员不在线

```
payload: 空（0字节）
```

#### 4.16 MSG_TYPE_ADMIN_ONLINE (21) / MSG_TYPE_ADMIN_OFFLINE (22)

```
payload: 空（0字节）
```

当 `OVC_REQUIRE_ADMIN=true` 时，管理员上下线会广播给所有客户端。客户端收到后启用/禁用语音发送和文字聊天。

#### 4.17 MSG_TYPE_DUPLICATE_NAME (23) — 昵称重复

```
payload: 空（0字节）
```

#### 4.18 MSG_TYPE_RECORDING_NOTICE (18) — 录音状态通知

```
payload: AES-256-GCM 加密的二进制数据
```

**解密后格式：**
```
字节偏移 | 大小  | 字段            | 说明
---------|-------|----------------|--------------------------
0        | 1     | enabled        | 0=未开启, 1=已开启
1        | 4     | purpose_len    | 录音目的文本长度
5        | N     | purpose        | 录音目的（UTF-8）
5+N      | 4     | duration_min   | 单个录音文件时长（分钟）
9+N      | 4     | max_size_mb    | 录音总大小限制（MB）
```

#### 4.19 MSG_TYPE_RECORDING_CONSENT (19) — 录音同意响应

```
字节偏移 | 大小  | 字段     | 说明
---------|-------|---------|--------------------------
0        | 1     | consent | 0=拒绝, 1=同意
```

#### 4.20 MSG_TYPE_TEXT_CHAT (24) — 发送文本消息

```
payload: AES-256-GCM 加密的 UTF-8 文本
```

**解密后格式：** 纯文本 UTF-8 字符串，最大 200 字符。

**普通消息：** 任意文本，服务器广播为 `[用户名] 文本内容`

**悄悄话：** 以 `/msg 用户名 内容` 开头，服务器解析后定向发送：
- 发送给目标用户：`[发送者 → you] 内容`
- 发送给所有管理员：`[发送者 → 目标用户] 内容`
- 发送给发送者确认：`[You → 目标用户] 内容`

#### 4.21 MSG_TYPE_TEXT_MESSAGE (25) — 广播文本消息

```
payload: AES-256-GCM 加密的 UTF-8 文本
```

**解密后格式：** 已格式化的 UTF-8 字符串，可直接显示。

**显示格式：**
- 普通消息：`[用户名] 文本内容`
- 悄悄话（目标用户）：`[发送者 → you] 内容`
- 悄悄话（管理员）：`[发送者 → 目标用户] 内容`
- 悄悄话（发送者确认）：`[You → 目标用户] 内容`
- 系统消息：`[System] 提示内容`

---

### 五、加密体系

```
┌─────────────────────────────────────────────────────────┐
│                    认证阶段（RSA-2048）                    │
│  客户端密码 ──RSA公钥加密──▶ 服务器 ──RSA私钥解密──▶ 验证  │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                  会话密钥派生（PBKDF2）                    │
│  password + salt ──PBKDF2-HMAC-SHA256(100k次)──▶ 密钥    │
│  服务器生成随机 session_key ──AES-256-GCM加密──▶ 客户端    │
└─────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 数据传输（AES-256-GCM）                    │
│  客户端 ──session_key加密──▶ 服务器 ──解密──▶             │
│  服务器 ──接收者session_key重新加密──▶ 接收者              │
│  Nonce池：全局共享，每次加密使用新 nonce                   │
└─────────────────────────────────────────────────────────┘
```

---

### 六、音频数据处理流程

```
发送端（客户端）：
  麦克风 ──PCM──▶ 降噪(RMS门限) ──▶ 增益调节 ──▶ Opus编码(32kbps)
  ──▶ AES-256-GCM加密 ──▶ UDP发送

服务器：
  UDP接收 ──▶ AES-256-GCM解密 ──▶ 录音(可选) ──▶
  ──▶ 接收者session_key重新加密 ──▶ UDP转发

接收端（客户端/管理员）：
  UDP接收 ──▶ AES-256-GCM解密 ──▶ Opus解码 ──▶
  ──▶ 音量均衡 ──▶ 抖动缓冲 ──▶ 音频播放
```

---

### 七、连接建立流程

```
客户端                          服务器                         管理员
  │                               │                               │
  │──── RUDP: JOIN(空)──────────▶│                               │
  │◀─── RUDP: RSA公钥 ───────────│                               │
  │                               │                               │
  │──── RUDP: JOIN(加密认证) ────▶│                               │
  │         (RSA加密密码+指纹)     │                               │
  │                               │── 验证密码 + 检查封禁           │
  │                               │── 派生会话密钥                  │
  │◀─── RUDP: AUTH_SUCCESS ──────│                               │
  │       (加密的session_key)     │                               │
  │                               │                               │
  │◀─── RUDP: RECORDING_NOTICE ──│                               │
  │                               │                               │
  │◀─── RUDP: ADMIN_ONLINE/OFFLINE│                              │
  │                               │                               │
  │──── UDP: AUDIO ──────────────▶│──── UDP: AUDIO ──────────────▶│
  │◀─── UDP: AUDIO ──────────────│◀─── UDP: AUDIO ──────────────│
  │                               │                               │
  │──── RUDP: TEXT_CHAT ─────────▶│──── RUDP: TEXT_MESSAGE ──────▶│
  │◀─── RUDP: TEXT_MESSAGE ──────│◀─── RUDP: TEXT_MESSAGE ──────│
  │                               │                               │
  │──── RUDP: HEARTBEAT(3s) ─────▶│◀─── RUDP: HEARTBEAT(3s) ─────│
```

## AI声明

本项目使用AI编写，在人类指引下开发，经过人工验证

## 贡献

欢迎提交 Issue 和 Pull Request！

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](./LICENSE) 文件。