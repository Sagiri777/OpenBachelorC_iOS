# OpenBachelorC 等价实现重构稿

本目录是从 `rel/*.js` 运行产物反向整理出的 **功能等价 TypeScript 实现稿**，目标不是字节级恢复原始源码，而是尽量保持：

- 相同的 Frida 配置收发语义；
- 相同的 Java / IL2CPP / Native hook 点；
- 相同的代理 URL 重写策略；
- 相同的证书、签名、检测绕过策略；
- 相同或接近的 extra / trainer 行为。

## 文件结构

```text
reconstructed/script/util/index.ts      公共配置、URL 改写、等待模块等工具
reconstructed/script/java/index.ts      Java 层 hook 等价实现
reconstructed/script/native/index.ts    Native / IL2CPP hook 等价实现
reconstructed/script/extra/index.ts     pause_deploy / 3x_speed / vision 等价实现
reconstructed/script/trainer/index.ts   trainer 命令等价实现
```

## 当前完成度

| 模块 | 状态 | 说明 |
|---|---|---|
| `java` | 已实现核心逻辑 | SDK 降噪、OkHttp URL 改写、TLS / cleartext 绕过、`deoptimizeEverything()` (try/catch) |
| `native` | 已实现核心逻辑 | `android_dlopen_ext` 过滤、UnityWebRequest.Get/Post URL 改写、证书 / RSA 验签绕过、`CertificateHandler.ValidateCertificate` 绕过 |
| `extra` | 已实现核心逻辑 | 暂停部署、3x 速度、vision overlay |
| `trainer` | 已实现主要命令 | 大部分命令按 release hook 点重构；`global_range` 保留稳定核心效果，未逐字复刻所有版本敏感边角 hook |

## 与原始 `rel/*.js` 的关系

原项目中真实运行的是：

```text
rel/java.js
rel/native.js
rel/extra.js
rel/trainer.js
```

这些文件已经是可执行 JS bundle，里面包含完整逻辑，但变量名和字符串有混淆。`src/script/*/index.ts.encrypted` 是加密源码，当前项目根目录没有 `locker.py` 需要的 `key_v1.png`，因此不能直接解密出原 TS。

本目录的实现来自对 `rel/*.js` 的轻量反混淆与语义重构。

## 后续验证建议

如果要将这些重构稿编译为 Frida bundle，可临时添加一份 webpack / frida-compile 配置，或直接执行类似：

```bat
npx frida-compile -S reconstructed\script\java\index.ts -o tmp\reconstructed-java.js
npx frida-compile -S reconstructed\script\native\index.ts -o tmp\reconstructed-native.js
npx frida-compile -S reconstructed\script\extra\index.ts -o tmp\reconstructed-extra.js
npx frida-compile -S reconstructed\script\trainer\index.ts -o tmp\reconstructed-trainer.js
```

当前已完成依赖安装，并使用 `frida-compile` 成功生成 `tmp/reconstructed/java.js`、`native.js`、`extra.js`、`trainer.js`。

## 重要差异 / 注意点

1. 原始 bundle 的变量名、函数拆分、注释、TypeScript 类型无法从 bundle 中精确恢复。
2. `trainer.global_range` 在原 bundle 中包含更多版本敏感处理；当前稿实现了主要效果：友方范围选择器的 collider 扩大。
3. Frida / Il2Cpp bridge API 对版本较敏感，实际运行时可能需要根据目标游戏版本微调 overload 签名。
4. 如果后续能拿到 `key_v1.png`，应优先用 `locker.py decrypt` 解密原源码，再用本目录作为对照。

## syncData 请求捕获说明

syncData 是游戏核心状态同步请求（玩家数据、进度等），通常为 POST 请求，目标地址类似：
- `https://ak-gs.hypergryph.com/api/syncData`
- `https://ak-gs.hypergryph.com/online/v1/syncData`

### 捕获原理

1. Java 层 hook (`okhttp3.HttpUrl.get`) 拦截所有 OkHttp 请求（包括 POST），将 URL 重写为 `http://127.0.0.1:8443/<host>/<path>`
2. IL2CPP 层 hook (`UnityWebRequest.Get` / `UnityWebRequest.Post`) 拦截 Unity 原生 HTTP 请求
3. 转发代理接收重写后的请求，提取 host，转发到真实 HTTPS 服务器并记录到 `captured/capture.jsonl`

### 捕获步骤

```bash
# 1. 编译脚本
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/java/index.ts -o tmp/reconstructed/java.js
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/native/index.ts -o tmp/reconstructed/native.js

# 2. 启动捕获（自动编译、启动代理、注入脚本）
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624

# 3. 等待游戏加载并登录
# 4. 检查捕获日志
cat captured/capture.jsonl | grep -i sync
```

### 调试技巧

如果 syncData 未被捕获，检查以下几点：

1. **确认 hook 已安装**：查看 Frida 控制台输出，应看到 `java: hooks installed` 和 `native: IL2CPP hooks installed`
2. **确认 URL 重写生效**：应看到类似 `okhttp: https://ak-gs.hypergryph.com/... -> http://127.0.0.1:8443/...` 的日志
3. **确认代理转发正常**：应看到 `-> POST https://ak-gs.hypergryph.com/...` 的代理日志
4. **检查 SSL bypass**：如果出现 SSL 握手错误，可能需要调整 TrustManager 或 BouncyCastle hook 的 overload 签名



## 本机验证记录（2026-06-14）

已在已连接的 `127.0.0.1:26624` arm64-v8a root 模拟器上完成验证：

1. 创建并初始化 `.venv`。
2. 安装 npm 依赖与 Python/Frida 依赖。
3. 将 `conf/config.json` 中 `use_su` 调整为 `false`（该模拟器是 root adbd，`su -c` 参数不兼容），部署 `/data/local/tmp/florida-17.9.1`，启动 Frida Server，并配置 `adb forward tcp:27042 tcp:9443`。
4. 使用 `frida-compile` 编译四个重构脚本到 `tmp/reconstructed/`。
5. 使用 `reconstructed/tools/validate_reconstructed.py` 以 Frida spawn 方式启动 `com.hypergryph.arknights` 并加载脚本。
6. `java + native` 单独加载验证通过：未捕获 Frida runtime error。
7. `java + native + extra + trainer` 全量加载验证通过，并成功触发 `enable:zero_cost` / `disable:zero_cost`。
8. 批量触发所有 trainer enable 命令均成功打印 `info: invoking ...`，未捕获 Frida runtime error。

验证命令示例：

```bash
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/java/index.ts -o tmp/reconstructed/java.js
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/native/index.ts -o tmp/reconstructed/native.js
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/extra/index.ts -o tmp/reconstructed/extra.js
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/trainer/index.ts -o tmp/reconstructed/trainer.js

.venv/bin/python reconstructed/tools/validate_reconstructed.py --mode spawn --scripts java native extra trainer --wait 45 --trainer-command enable:zero_cost --trainer-command disable:zero_cost
```

注意：验证证明脚本能在真实游戏进程中加载、解析目标类/方法并安装 hook；具体战斗内 UI/数值效果仍建议进入相应场景做人工确认。


## 专用 SSL bypass / 抓包模式

如果目标只是抓包，不建议启用 trainer/extra，也不建议把 URL 强制改写到 `proxy_url`。更稳的方式是：

1. 在模拟器系统 Wi-Fi / 代理设置里配置 Burp、Charles、mitmproxy 等代理。
2. 安装抓包工具的 CA 证书到模拟器。
3. 启动 Frida Server / `adb forward tcp:27042 tcp:9443`。
4. 只加载专用脚本 `tmp/reconstructed/ssl_bypass.js`。

编译：

```bash
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/ssl_bypass/index.ts -o tmp/reconstructed/ssl_bypass.js
```

验证：

```bash
.venv/bin/python reconstructed/tools/validate_ssl_bypass.py --mode spawn --wait 35
```

实际抓包时保持脚本常驻：

```bash
.venv/bin/python reconstructed/run_ssl_bypass.py
```

如果游戏已经启动，则使用：

```bash
.venv/bin/python reconstructed/run_ssl_bypass.py --attach
```

本脚本只做 SSL / 证书 / 签名校验绕过和轻量 native 加载过滤，不启用战斗 trainer，不改 URL host。2026-06-14 已在 `127.0.0.1:26624` 上验证：`ssl_bypass: Java SSL hooks installed` 与 `ssl_bypass: IL2CPP SSL/signature hooks installed` 均成功打印，未捕获 Frida runtime error。


## Unity 内部请求捕获模式

仅绕过 SSL 后，如果 UnityWebRequest 不走 Android 系统代理，Burp/Charles 可能仍看不到 Unity 内部请求。因此新增 `unity_capture` 模式：

- 保留 Java + IL2CPP SSL / 签名绕过；
- hook `UnityEngine.Networking.UnityWebRequest.Get/Delete/Head/Post/Put` 和 `set_url`；
- hook `UnityWebRequest.SendWebRequest()`；
- hook Unity/libcurl 的 `curl_easy_setopt` / `curl_easy_perform`，可把不遵守 Android 系统代理的游戏内请求强制走抓包代理；
- 默认只打印 Unity 内部 URL，不改写 URL；
- 可选开启 URL rewrite，但这更适合对接自定义本地代理/服务，不是标准 Burp HTTP proxy 语义。

编译：

```bash
npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/unity_capture/index.ts -o tmp/reconstructed/unity_capture.js
```

运行并保持常驻：

```bash
.venv/bin/python reconstructed/run_unity_capture.py
```

如果游戏已启动：

```bash
.venv/bin/python reconstructed/run_unity_capture.py --attach
```

2026-06-14 验证时已捕获到 UnityWebRequest 内部 URL，例如：

```text
unity_capture: UnityWebRequest.Get https://game-config.hypergryph.com/api/remote_config/1/prod/default/Android/network_config
unity_capture: SendWebRequest https://game-config.hypergryph.com/api/remote_config/1/prod/default/Android/network_config
unity_capture: UnityWebRequest.Get https://ak-conf.hypergryph.com/config/prod/official/Android/version
```

如果你需要这些 Unity 请求进入 Burp/Charles，有三条路线：

1. 先试系统代理：模拟器 Wi-Fi/系统代理指向 Burp，CA 证书装进模拟器，同时运行 `unity_capture`。如果 UnityWebRequest 遵守系统代理，就能直接看到。
2. 如果 UnityWebRequest 不遵守系统代理，使用透明代理/VPN/TUN 方案，比如 mitmproxy transparent mode、ProxyDroid、VPN 抓包工具等，让 TCP 流量被系统层转发。
3. 使用 `unity_capture` 的 URL 日志作为兜底，至少能确认 Unity 内部真实请求 URL；如确实要强制改道，可用 `--rewrite-unity-url --proxy-url http://127.0.0.1:8443`，但这会把 URL host 替换成本地服务，适合 OpenBachelor 这类自定义服务，不等价于标准 HTTP 代理。

## 根目录两个一键脚本

### 1. 启动重构版完整 JS

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624
```

说明：

- 模仿原项目启动器；
- 编译并加载 `reconstructed/script/java|native|extra|trainer`；
- 使用项目 `conf/config.json`；
- 如果 `enable_trainer=true`，会进入 trainer CLI。

常用参数：

```bash
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --spawn
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --no-trainer
.venv/bin/python launch_reconstructed.py --device 127.0.0.1:26624 --no-extra
```

### 2. 一键配置代理并启动抓包

默认你的抓包代理在宿主机 `127.0.0.1:8080`：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080
```

脚本会：

1. 编译 `reconstructed/script/unity_capture/index.ts`；
2. 启动 Frida Server；
3. 对 `127.0.0.1:8080` 做 `adb reverse tcp:8080 tcp:8080`；
4. 设置 Android 全局代理为 `127.0.0.1:8080`；
5. 默认按原项目 `no_spawn=true` 的兼容路线用 `monkey` 启动游戏并 attach；如需更早注入可显式加 `--spawn`；
6. 默认对 Unity/libcurl 设置 `CURLOPT_PROXY=http://127.0.0.1:8080`，补上“登录包能抓到、游戏内包抓不到”的系统代理盲区；
7. 退出时自动清理 Android 全局代理、Frida Server 和 forward。

如果 Burp/Charles 监听的不是 8080，例如 8888：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8888
```

如果你要连接局域网代理，不需要 adb reverse：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 192.168.1.10:8080 --no-reverse
```

如果游戏已经启动：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --attach
```

如果日志出现 `ProcessNotRespondingError: unexpectedly timed out trying to sync up with agent`，说明进程已找到但 attach 时目标暂时无响应。脚本默认会等待 6 秒并重试 10 次；仍失败时可把等待拉长：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --post-launch-delay 15 --attach-retries 20
```

少数模拟器环境需要 emulated realm：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --emulated-realm
```

如果确认当前模拟器的 Frida spawn 稳定，并希望在应用入口前注入：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --spawn
```

如果强制 libcurl 代理导致某个环境启动异常，可退回只记录 URL / 只走系统代理：

```bash
.venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --proxy 127.0.0.1:8080 --no-libcurl-proxy
```

注意：`start_packet_capture.py` 默认仍是标准抓包代理模式：设置系统代理 + SSL bypass + UnityWebRequest/libcurl 日志，并通过 `CURLOPT_PROXY` 指向 Burp/Charles/mitmproxy；它不会把 URL host 改成本地服务。只有你明确需要 OpenBachelor 这类本地服务接管请求时，才使用 `--rewrite-unity-url`。
