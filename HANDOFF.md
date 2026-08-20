# OpenBachelorC 抓包调试 — 交接文档

> 给接手 Agent 的内功心法。先读这个再动手。

## 1. 项目是什么

`/Users/chino/Downloads/OpenBachelorC` 是一个 **Frida 注入式明日方舟客户端**：Python 启
动器加载 `rel/{java,native,extra,trainer}.js`（混淆+webpack bundle）到
`com.hypergryph.arknights` 进程，做：
- Java 层 hook OkHttp / Okio / SDK
- IL2CPP hook `UnityWebRequest` / `BouncyCastle` 等证书校验
- extra 是战斗 UI 增强（pause_deploy、3x_speed、vision overlay）
- trainer 是指令式修改（zero_cost、heal_everyone 等）

`reconstructed/` 是从 `rel/` 的 bundle 里**反混淆** 出来的等价 TypeScript 稿。
`tmp/reconstructed/{java,native,extra,trainer}.js` 是 `frida-compile` 产物，运行时实际加载的就是它。

## 2. 用户最终目标（必读，别忘）

> "我只要最终能抓到游戏内 Unity 层的 `syncData` 包，登录游戏的那一刻的 syncData 以及之后的同层请求。"

唯一命令：

```bash
cd /Users/chino/Downloads/OpenBachelorC && \
  .venv/bin/python start_packet_capture.py --device 127.0.0.1:26624 --no-trainer --no-extra
```

脚本做：
1. 上传 `frida-server-17.9.1-android-arm64.xz` → `/data/local/tmp/florida-17.9.1`（已存在跳过）
2. `pkill florida-17.9.1` 后 `nohup /data/local/tmp/florida-17.9.1 -l 127.0.0.1:9443` 启动
3. `adb forward tcp:27042 tcp:9443` + `adb reverse tcp:8443 tcp:8443`
4. `frida.spawn('com.hypergryph.arknights')` 后 attach
5. 起 `ForwardingHandler` 在 `127.0.0.1:8443`：URL 重写后的 HTTP 进这里，转发到原 HTTPS，回包发回游戏
6. 加载 `tmp/reconstructed/{java,native,extra,trainer}.js` 到游戏
7. `for (;;) sleep(1)` 直到 Ctrl-C
8. 包落 `captured/capture.jsonl`

捕获内容每行 JSON：
```json
{"timestamp":"2026-07-17T...","method":"POST",
 "url":"https://ak-gs.hypergryph.com/online/v2/syncData",
 "request_headers":{...},"request_body":"...",
 "response_status":200,"response_headers":{...},"response_body":"..."}
```

## 3. **最关键的事** —— 易踩坑清单

### 3.1 模拟器 + adb 极不稳定，必崩
- 用户的 MuMu Player Pro 经常 `adb` 假死（macOS sandbox 限制），需要**每隔几分钟**就可能要：
  ```bash
  cd /tmp/com.netease.mumu.nemux-global && ./mumutool restart 0  # 完全重启
  sleep 30
  # 官方 adb setup（关键路径在 /Applications/.../tools/adb）
  /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
    connect 127.0.0.1:26624
  /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
    -s 127.0.0.1:26624 unroot
  /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
    connect 127.0.0.1:26624
  # 重启 frida（保证有 listener）
  /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
    -s 127.0.0.1:26624 shell "pkill -9 -f florida-17.9.1; sleep 1; nohup /data/local/tmp/florida-17.9.1 -l 127.0.0.1:9443 > /data/local/tmp/florida.log 2>&1 </dev/null &"
  ```
- 端口可能从 `26624` 变 `26625`，每次跑前**先 `mumutool info 0` 看 `adb_port`**。
- 任何 adb shell 命令 hang 住超过 8 秒，**就当模拟器死了**，不要傻等。

### 3.2 直接 `mumutool show` 没东西
那命令是看**所有** MuMu 进程，但这个用户只跑一个 device，看 `mumutool info 0`（device 0）才对。

### 3.3 模拟器 hot-restart 后 frida-server 没起来
`nohup` 之后必须看到 `127.0.0.1:9443` LISTEN：
```bash
/Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
  -s 127.0.0.1:26624 shell "netstat -tln 2>/dev/null | grep 9443"
```
没有就要再 `nohup` 一次。**这个坑很常见**，frida 启动失败的话 Python 端会
`ServerNotRunningError: Could not connect to 127.0.0.1: Operation not permitted`（注意：那是
Python 沙盒在搞鬼，必须用 escalation 见下方 §4）。

### 3.4 Mac sandbox 限制
- **沙盒 shell 无法连 `127.0.0.1:27042`**（adb forward 入口），也开不了 5037
  daemon。会爆 `Could not connect to 127.0.0.1: Operation not permitted`
- **解决办法：所有 adb 命令 / Python start_packet_capture.py 都加 `sandbox_permissions:
  "require_escalated"`**

### 3.5 UI 操作断点
- syncData **只在用户点 "开始唤醒" 后** 才会发
- 玩家**先要点黄菱形**进登录页 → **再点 "开始唤醒"** 才触发 syncData
- 我写的 `reconstructed/tools/capture_login.py` 有自动 tap 但容易卡
- **最稳**：让人工跑模拟器、跑命令，**人手动点两下**，捕获程序只要待命

### 3.6 frida-il2cpp-bridge 的非静态方法调用约定
2026-07-17 修过的坑：

```typescript
// ❌ 错 — 黑屏
setter.implementation = function (url) {
    return setter.invoke(this, Il2Cpp.string(rewritten));
};

// ✅ 对
setter.implementation = function (url) {
    return this.method("set_url").invoke(Il2Cpp.string(rewritten));
};

// ctor 同理：
ctor.implementation = function (url, method) {
    return this.method(".ctor").invoke(Il2Cpp.string(rewritten), method);
};
```

硬规：**任何非静态方法的"原始调用"，必须 `this.method(name).invoke(args)`，不要
`Class.method(name).invoke(this, args)`**。

### 3.7 gameupdate 错误弹窗
`com.hypergryph.gameupdate.utils.OkHttpUtils$TrustAllCerts.checkServerTrusted`
被绕过 → gameupdate https 走我们 8443 转发 → 我们的 `ForwardingHandler`
碰到 `event_log` / `batch_event` 也会 `204 No Content` 短路。但 gameupdate
主 URL 不该被代理：**`rewritten/index.ts` 的 `PASSTHROUGH_HOST_SUFFIXES`
黑名单就是这个用途**，gameupdate / bi-* / event-log-* 都直连真服务器。

如果在终端看到 `ERROR GAMEUPDATE COMMON` 弹窗，看是不是把 gameupdate 加入白名单了。

## 4. 关键文件 / 路径

| 文件 | 用途 |
|---|---|
| `start_packet_capture.py` | 主力抓包入口。**正确命令**就是 `python start_packet_capture.py --device ...` |
| `reconstructed/script/util/index.ts` | **改这里**以扩展 `PASSTHROUGH_HOST_SUFFIXES` 或重写 URL 逻辑 |
| `reconstructed/script/java/index.ts` | **改这里**以扩展 Java hook 覆盖范围 |
| `reconstructed/script/native/index.ts` | **改这里**以扩展 IL2CPP hook 覆盖范围 |
| `tmp/reconstructed/{java,native,extra,trainer}.js` | frida-compile 产物，**改完 .ts 必须重编**：<br>`npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/<name>/index.ts -o tmp/reconstructed/<name>.js` |
| `captured/capture.jsonl` | 抓包落盘。看包直接 `wc -l` + `head -3` |
| `captured/capture.before-*.jsonl` | 旧 capture 存档（按时间标记，方便区分） |
| `conf/config.json` | `use_su:false`、`frida_port:9443`、`port:8443`，改之前先备份 |
| `.agents/HANDOVER.md` | **就是你在读的这个** |

## 5. 接手第一时间检查清单

按顺序做，不要跳：

1. **emulator 还活着吗**：
   ```bash
   cd /tmp/com.netease.mumu.nemux-global && ./mumutool info 0
   ```
   看 `state` 和 `adb_port`（26624 还是 26625）。

2. **adb 通吗**（带 `sandbox_permissions:"require_escalated"`）：
   ```bash
   /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
     connect 127.0.0.1:<port>
   /Applications/MuMuPlayer\ Pro.app/Contents/MacOS/MuMu\ Android\ Device.app/Contents/MacOS/tools/adb \
     -s 127.0.0.1:<port> shell "echo OK"
   ```

3. **frida 在监听 9443**：
   ```bash
   ... shell "netstat -tln 2>/dev/null | grep 9443"
   ```
   没就 `pkill -9 florida-17.9.1; nohup /data/local/tmp/florida-17.9.1 -l 127.0.0.1:9443 ... &`

4. **adb forward 架好**：
   ```bash
   ... -s <port> forward tcp:27042 tcp:9443
   ... -s <port> reverse tcp:8443 tcp:8443
   ```

5. **先用一个非常小的验证**确认链路通，再跑 `start_packet_capture.py`：
   ```python
   # .venv/bin/python
   import frida
   d = frida.get_remote_device()
   print(d)  # 不爆 'Operation not permitted' 即 OK
   print(len(d.enumerate_processes()))  # > 0 即 OK
   ```

6. **打包前，删 `captured/capture.jsonl`**——避免读到昨天的旧包。

7. **跑主力命令**（escalation）：
   ```bash
   .venv/bin/python start_packet_capture.py --device 127.0.0.1:<port> --no-trainer --no-extra
   ```

8. **判断成败**：看终端里
   - `java: hooks installed (proxy_url=...)`
   - `native: IL2CPP hooks installed (proxy_url=...)`
   - `okhttp: ... -> http://127.0.0.1:8443/...`
   - `UnityWebRequest.Get: ... -> http://127.0.0.1:8443/...`

   没这些就说明 hook 没装上，**先看 `ERROR [java] ...`**。

9. **让用户登游戏**：盯着 `captured/capture.jsonl` 的 `wc -l`。看到
   `https://ak-gs.hypergryph.com` 或 `/online/v1/syncData` 或 `/online/v2/syncData`
   之类的 URL 就说明登录成功了。

10. **Ctrl-C 收尾**：脚本会调用 `cleanup` 杀 frida 进程、清 forward。
    `mumutool close 0` 关模拟器是礼貌但不必。

## 6. 终端日志「什么算成功 / 什么算失败」

**✅ 成功标志**
```
forwarding proxy on 127.0.0.1:8443              ← forwarding proxy 起来了
loaded reconstructed java: .../java.js
loaded reconstructed native: .../native.js
loaded reconstructed extra: .../extra.js  (不加 --no-extra 的话)
loaded reconstructed trainer: .../trainer.js  (不加 --no-trainer 的话)
Capture active. All game traffic -> http://127.0.0.1:8443/<host>/<path> -> real server
java: hooks installed (proxy_url=http://127.0.0.1:8443, no_proxy=false)
native: IL2CPP hooks installed (proxy_url=...)
okhttp: https://xxx -> http://127.0.0.1:8443/xxx        ← java hook 起作用
UnityWebRequest.Get: https://xxx -> http://127.0.0.1:8443/xxx  ← IL2CPP hook 起作用
[2026-07-17T...] GET 200 https://xxx                        ← 真服务器回包了
```

**❌ 失败标志**
- `ERROR [java] ... Instrumentation field offsets` ← **忽略**（已知无害）
- `Il2CppError: cannot invoke non-static method X as it must be invoked throught a Il2Cpp.Object` ← **黑屏原因**，见 §3.6
- `ServerNotRunningError: Could not connect to 127.0.0.1: Operation not permitted` ← 沙盒限制没加 escalation
- `Address already in use` ← 老的 Python capture 进程没死干净，`lsof -i :8443` 然后 `kill -9`
- `frida-server ... failed to connect` ← florida 没起来，看 §5.3
- 终端没 `okhttp:` 或 `UnityWebRequest:` 输出 → hook 完全没装，去查 .ts 编译后的 .js

## 7. **如何加一层新 hook**

假设你想 hook 一个新的 Java class `com.hypergryph.game.X`：

1. **编辑** `reconstructed/script/java/index.ts`，在 `installHooks()` 里加：
   ```typescript
   safe("game X hook", () => {
       const X = Java.use("com.hypergryph.game.X");
       X.someMethod.implementation = function (...) { /* your code */ };
   });
   ```

2. **重编译**：
   ```bash
   npm_config_cache=.npm-cache npx frida-compile -S reconstructed/script/java/index.ts -o tmp/reconstructed/java.js
   ```

3. 如果类名带 `,` 或 `$`，Java.use() 能识别；如果含 `[]` 表示数组类型。

4. 如果是 IL2CPP（Unity WebRequest / 类），改 `reconstructed/script/native/index.ts`：
   ```typescript
   safe("Foo hook", () => {
       Il2Cpp.perform(() => {
           const cls = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Foo");
           cls.method("Bar").implementation = function (a) {
               // 'this' is Il2Cpp.Object; b.call(this, ...) to invoke
               return this.method("Bar").invoke(/* args */);
           };
       });
   });
   ```

5. **避免用 `Class.method(name).invoke(this, args)`** 模式，会黑屏。见 §3.6。

## 8. **调试 capture.jsonl 的几个小工具**

```bash
# 抓 log 文件（旧存档）
ls /Users/chino/Downloads/OpenBachelorC/captured/

# 只看 Unity 层请求
.venv/bin/python << 'PY'
import json
from collections import Counter
unity = Counter()
total = 0
with open('/Users/chino/Downloads/OpenBachelorC/captured/capture.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: e = json.loads(line)
        except: continue
        total += 1
        ua = e.get('request_headers', {}).get('User-Agent', '"''"')
        if 'UnityPlayer' in ua or 'UnityWebRequest' in ua: unity[e['url'].split('/')[2]] += 1
print(f'total {total}, unity hosts: {dict(unity.most_common(20))}')
PY

# 只看 syncData、登录态相关
grep -E "syncData|ak-gs|game-state|login|TokenGrant|playerInfo" captured/capture.jsonl | wc -l

# 找一个特定方法的响应 body
.venv/bin/python << 'PY'
import json
with open('captured/capture.jsonl') as f:
    for line in f:
        line = line.strip()
        if not line: continue
        try: e = json.loads(line)
        except: continue
        if 'network_config' in e.get('url', '"''"'):
            print(json.dumps(e, indent=2, ensure_ascii=False))
            break
PY
```

## 9. 如果用户问「script 改了之后没生效」

99% 是缓存了。**`tmp/reconstructed/*.js` 是 frida-compile 缓存产物**，`start_packet_capture.py`
加载的是缓存 .js 不是 .ts。改完 .ts 必须：

```bash
npm_config_cache=.npm-cache npx frida-compile -S <src.ts> -o <out.js>
```

或让脚本自己跑：`compile_all()` 在 `start_packet_capture.py:67` 已会调。

如果路径对得上，但脚本内容没变——查 `compile_script()` 函数（line 38-46），它检测
`out.stat().st_mtime >= src.stat().st_mtime` 即跳过重编。删 `tmp/reconstructed/*.js`
强迫重编。

## 10. 进阶/未来工作的方向

按价值排序：

1. **捕获 `syncData` / `syncData` 同层包**：当务之急，没它不要结案。手动让用户点登录。
2. **再扩展 gameupdate 白名单**：观察端到端还有什么被 SDK 误判为失败，往 `PASSTHROUGH_HOST_SUFFIXES` 加。
3. **加 trainer 模块**：现在 `--no-trainer` 关着的。bundle 里有 `trainer.js` 暴露出 16 个指令（zero_cost / heal_everyone 等）。编 `tmp/reconstructed/trainer.js` 后去掉 `--no-trainer`，CLI 会进 prompt 模式。
4. **`global_range` 是版本敏感**：trainer.ts 里的 `global_range` 只覆盖了 `AutoLoadBoxRange` 字段名，hook `Reset`/`OnAbilityExtendUpdated`，新版本游戏可能改名。要对应查 `AutoLoadBoxRange` / `RangeSelector` 当前实际字段。
5. **ssl_bypass.ts / unity_capture.ts**：reconstructed/ 里这两个独立脚本没动。如果想跑
   `reconstructed/run_unity_capture.py`（这个在 approved prefix 里），它会单独加载 unity_capture.js
   ——这个 bundle 行为和 `start_packet_capture.py` 不一样，**只 hook 不转发**，适合纯日志模式。

## 11. 仓库根 README

`README.md`、`RECONSTRUCTED_USAGE.md`、`injection_analysis_report.md` 是项目历史文
档，不一定反映当前脚本行为。**以代码为准**，只看 doc 会过时。

「`start_packet_capture.py --help`」是 source of truth，里面每一行注释都告诉你它在做啥。
