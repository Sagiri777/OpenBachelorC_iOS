# OpenBachelorC 重构脚本与抓包使用教程

本文说明两个根目录脚本的用途与用法：

- `launch_reconstructed.py`：模仿项目启动器，启动并加载重构版 JS。
- `start_packet_capture.py`：一键配置抓包代理，启动 SSL bypass + Unity 请求捕获。

路径基准：

```text
/Users/chino/Downloads/OpenBachelorC
```

---

## 0. 前置条件

### 0.1 模拟器 / adb

确保模拟器已经启动，adb 能看到设备：

```bash
adb devices -l
```

示例设备：

```text
127.0.0.1:26624 device
```

本文后续都以这个设备号为例：

```text
127.0.0.1:26624
```

如果你的设备号不同，请替换命令里的 `--device` 参数。

### 0.2 Python 环境

已在项目目录创建 `.venv`，推荐统一使用：

```bash
.venv/bin/python
```

### 0.3 Frida / npm 依赖

已安装项目所需的 Python 和 npm 依赖。重构脚本会自动调用 `frida-compile` 编译 TS 到 JS。

### 0.4 当前配置注意

当前模拟器是 root adbd，`su -c` 不兼容，因此：

```json
"use_su": false
```

位于：

```text
conf/config.json
```

---

## 1. 脚本一：启动重构版完整 JS

脚本：

```text
launch_reconstructed.py
```

作用：

- 模仿原项目启动器；
- 编译并加载重构版：
  - `reconstructed/script/java/index.ts`
  - `reconstructed/script/native/index.ts`
  - `reconstructed/script/extra/index.ts`
  - `reconstructed/script/trainer/index.ts`
- 启动 Frida Server；
- 配置 adb forward / reverse；
- 启动游戏并注入重构版 JS；
- 如果 `conf/config.json` 里 `enable_trainer=true`，进入 trainer CLI。

### 1.1 基本启动

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624
```

### 1.2 使用 Frida spawn 启动

如果希望更早注入：

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --spawn
```

### 1.3 不加载 trainer

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --no-trainer
```

### 1.4 不加载 extra

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --no-extra
```

### 1.5 trainer CLI 用法

如果启用了 trainer，会进入类似：

```text
>
```

可以输入：

```text
enable zero_cost
disable zero_cost
enable all
disable all
```

也可以直接发送内部命令：

```text
!dump
```

---

## 2. 脚本二：一键配置抓包并启动

脚本：

```text
start_packet_capture.py
```

作用：

- 编译 `reconstructed/script/unity_capture/index.ts`；
- 启动 Frida Server；
- 配置 adb forward；
- 配置 Android 全局 HTTP 代理；
- 启动游戏；
- 注入 Unity capture + SSL bypass；
- 打印 UnityWebRequest 内部 URL；
- 退出时清理代理、Frida Server、forward。

这个脚本适合你的主要目标：

> 绕过 SSL，并尽量抓到 Unity 内部请求。

---

## 3. 标准抓包流程

### 3.1 启动 Burp / Charles / mitmproxy

先在电脑上启动抓包工具。

示例：Burp 监听：

```text
127.0.0.1:8080
```

### 3.2 安装 CA 证书

确保抓包工具的 CA 证书已经安装到模拟器里。

如果证书没有安装，即使脚本绕过部分校验，某些 Java / WebView / 系统请求仍可能显示 TLS 错误或无法解密。

### 3.3 一键启动抓包

如果抓包代理监听在宿主机：

```text
127.0.0.1:8080
```

运行：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080
```

脚本会自动执行等价操作：

```bash
adb -s 127.0.0.1:26624 reverse tcp:8080 tcp:8080
adb -s 127.0.0.1:26624 shell settings put global http_proxy 127.0.0.1:8080
```

然后启动游戏并注入抓包脚本。

### 3.4 保持终端打开

运行后终端会显示：

```text
capture active. Keep this terminal open while using Burp/Charles/mitmproxy. Ctrl-C to stop and clear proxy.
```

保持这个终端打开，然后在游戏内操作。

### 3.5 退出与清理

按：

```text
Ctrl-C
```

脚本会自动清理：

- Android 全局代理；
- adb reverse；
- Frida Server；
- adb forward。

---

## 4. 不同代理地址的用法

### 4.1 Burp / Charles 监听 8888

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8888
```

### 4.2 代理在局域网机器上

例如代理地址是：

```text
192.168.1.10:8080
```

运行：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 192.168.1.10:8080 --no-reverse
```

因为不是宿主机回环地址，所以不需要 `adb reverse`。

### 4.3 游戏已经启动时附加

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --attach
```

---

## 5. Unity 内部请求说明

Unity 内部请求通常来自：

```text
UnityEngine.Networking.UnityWebRequest
```

新增的 `unity_capture` 会 hook：

- `UnityWebRequest.Get(System.String)`
- `UnityWebRequest.SendWebRequest()`

因此终端里会打印类似：

```text
unity_capture: UnityWebRequest.Get https://game-config.hypergryph.com/api/remote_config/1/prod/default/Android/network_config
unity_capture: SendWebRequest https://game-config.hypergryph.com/api/remote_config/1/prod/default/Android/network_config
unity_capture: UnityWebRequest.Get https://ak-conf.hypergryph.com/config/prod/official/Android/version
```

这表示 Unity 内部 URL 已经被捕获。

---

## 6. 如果 Burp 看不到 Unity 请求怎么办

这通常说明：

> Unity native 网络栈没有遵守 Android 系统代理。

这时有三种路线。

### 6.1 先确认 Frida 日志

看终端是否出现：

```text
unity_capture: UnityWebRequest.Get ...
unity_capture: SendWebRequest ...
```

如果出现，说明 Unity 请求确实发出了，且 Frida 已经捕获到 URL。

### 6.2 使用透明代理 / VPN 抓包

如果系统代理抓不到 Unity 请求，需要更底层的方式，例如：

- mitmproxy transparent mode；
- Android VPN 抓包工具；
- ProxyDroid；
- iptables 透明代理；
- 模拟器网络层透明转发。

这种方案不依赖应用是否读取系统代理，而是在网络层转发流量。

### 6.3 强制改写 Unity URL，仅特殊场景使用

脚本支持强制改写 Unity URL：

```bash
.venv/bin/python start_packet_capture.py \
  --device 127.0.0.1:26624 \
  --proxy 127.0.0.1:8080 \
  --rewrite-unity-url \
  --rewrite-proxy-url http://127.0.0.1:8443
```

注意：这不是标准 HTTP 代理语义。

它会把 Unity 请求的 host 替换为 `--rewrite-proxy-url`，更适合 OpenBachelor 这类本地服务接管请求，不适合普通 Burp 抓包作为首选方案。

---

## 7. SSL bypass 覆盖范围

抓包脚本会绕过 / hook：

### Java 层

- `com.hypergryph.gameupdate.utils.OkHttpUtils$TrustAllCerts.checkServerTrusted`
- `com.hypergryph.platform.hgsdk.http.NetworkService$TrustAllCerts.checkServerTrusted`
- `com.android.org.conscrypt.TrustManagerImpl.checkTrusted`
- `android.security.net.config.ConfigNetworkSecurityPolicy.isCleartextTrafficPermitted`

### IL2CPP / Unity 层

- `Torappu.Network.Certificate.CertificateHandlerFactory.BouncyCastleCertVerifyer.IsValid`
- `Torappu.CryptUtils.VerifySignMD5RSA`
- `System.Security.Cryptography.RSACryptoServiceProvider.VerifyHash`
- `UnityEngine.Networking.UnityWebRequest.Get`
- `UnityEngine.Networking.UnityWebRequest.SendWebRequest`

### Native 层

轻量过滤：

- `android_dlopen_ext`
- 跳过部分检测库名：`msaoaidsec`、`anogs`

---

## 8. 手动清理代理

如果脚本异常退出，可以手动清理 Android 全局代理：

```bash
adb -s 127.0.0.1:26624 shell settings put global http_proxy :0
adb -s 127.0.0.1:26624 shell settings delete global global_http_proxy_host
adb -s 127.0.0.1:26624 shell settings delete global global_http_proxy_port
```

如果使用了本机回环代理，还可以清理 reverse：

```bash
adb -s 127.0.0.1:26624 reverse --remove tcp:8080
```

---

## 9. 常见问题

### Q1：只想抓包，不想启用 trainer 怎么办？

使用：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080
```

这个脚本不会启用 trainer，也不会改战斗逻辑。

### Q2：终端打印 Unity URL，但 Burp 没看到？

说明 Unity 请求可能没走系统代理。使用透明代理 / VPN 抓包方案。

### Q3：Burp 看到 CONNECT，但解不开 HTTPS？

检查：

1. CA 证书是否安装到模拟器；
2. `unity_capture` 是否打印：

```text
unity_capture: Java SSL hooks installed
unity_capture: IL2CPP SSL/signature + UnityWebRequest hooks installed
```

3. 是否过早启动游戏，导致 hook 太晚。建议用默认 spawn 模式，不要 `--attach`。

### Q4：游戏启动失败或 Frida 连不上？

确认：

```bash
adb devices -l
adb -s 127.0.0.1:26624 shell id
```

当前配置要求：

```json
"use_su": false
```

因为该模拟器是 root adbd。

---

## 10. 推荐命令

最常用抓包命令：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080
```

最常用重构版启动命令：

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624
```
