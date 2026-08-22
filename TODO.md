# iOS Direct / Extra / Trainer TODO 与技术依据

> 最后分析日期：2026-08-22
> 当前目标：`明日方舟 2.7.61 (59)`，仅面向 iOS。
> 基线：以当前未提交工作树为准，不等同于 `origin/master`。

## 1. 文档目的和使用规则

本文件用于固化已经完成的源码/IL2CPP dump 分析、当前能力边界、候选实现和验收条件，避免每次继续开发前重复搜索同一批方法。这里的 Direct 同时包含网络/捕获主 Agent 和不依赖 `frida-il2cpp-bridge` 的 Extra/Trainer RVA 实现。

状态含义：

- `[x]`：当前工作树已有代码路径；**不代表已经通过本轮 iPhone 实机验证**。
- `[~]`：已有降级实现，语义不完整或仍有明确风险。
- `[ ]`：尚未实现。
- “dump 候选”：只在 2.7.61 (59) 的 `script.json` / `dump.cs` 中确认了符号、签名或布局；尚未加入 profile，也未验证 prologue 和实机行为。

后续更新必须遵守：

1. profile RVA 必须由 `openbachelor_ios/profile_generator.py` 的 `MethodSpec` 自动生成，不在 Agent 中写死地址。
2. 对象字段必须由 profile generator 生成 layout；不得把 `dump.cs` 字段偏移直接固化在 TypeScript 中。
3. Agent 只有在所需 RVA、prologue、layout 全部存在并校验成功时才报告 capability；否则 fail closed。
4. 每完成一项，同步勾选本文件，并记录游戏版本/build、Mach-O UUID、设备/iOS、输入、输出、恢复结果和失败原因。
5. 证据冲突时按“实机行为 > 当前 profile/prologue > `script.json` > `dump.cs` > 旧 bridge 实现/推测”判断。

## 2. 当前能力基线

### 2.1 Direct

| 状态 | 功能 | 当前后端 | 已知边界/依据 |
|---|---|---|---|
| [x] | UnityWebRequest 重写与请求/响应捕获 | Direct RVA | 支持 GET/POST/ctor/setter/header/upload/download/completion；依赖 profile offset/layout |
| [x] | BestHTTP 重写与请求/响应/stream 捕获 | Direct RVA | 通过 `Networker`、`HTTPRequest`、`HTTPResponse` 入口关联请求；部分 header 读取是 optional |
| [x] | ServerNet / LongService 原始帧捕获 | Direct RVA | 已记录 main/sub id、方向、帧头和 payload；尚未做消息名映射与 schema 解码 |
| [x] | SSL/签名测试开关 | Direct RVA | 只用于获授权测试；当前 capability 主要表示配置与 hook 安装，不表示每条网络链都命中 |
| [x] | 阻止战斗记录上传 | Direct RVA + layout | 仅匹配已知 battle-finish URL 并构造本地成功响应；默认关闭，必须继续 fail closed |
| [~] | 捕获完整性和隐私控制 | Host writer | 已有 JSONL/HAR/body sidecar、截断和 `0600` 权限；缺少规则过滤、脱敏、覆盖率和实时暂停 |

相关入口：

- `frida/direct.ts`：三类传输、URL 重写、capture、SSL/签名和 battle-finish blocker。
- `openbachelor_ios/capture.py`：JSONL/HAR/body sidecar 落盘与关联。
- `openbachelor_ios/capture_proxy.py`：到 Requable/Fiddler 的实时桥接。
- `openbachelor_ios/profile_generator.py`：所有网络、Extra、Trainer RVA/prologue/layout 的生成入口。

### 2.2 Extra

| 状态 | 功能 | 当前后端 | 已知边界/依据 |
|---|---|---|---|
| [x] | 暂停时部署 | Direct RVA | `direct.ts` 的 `installNativeExtraHooks` 使用 UI pause/interactable 方法；profile 已有对应 RVA 与 prologue |
| [x] | 1x/2x/3x 循环 | Direct RVA | `extraUiTopBar*` 三个方法齐全时安装；不依赖 IL2CPP bridge |
| [x] | 战斗时间和 Tick | Direct RVA | 复用 `BattleController.Update`，默认每 200 ms 读取 `fixedPlayTime` / `fixedFrameCnt` |
| [~] | Vision 单位信息 | Legacy bridge | `extra-hooks.ts` 已有 managed overlay，但当前 2.7.61 (59) 裁剪了所需 IL2CPP exports，Direct 模式没有等价实现 |

相关入口：

- `frida/direct.ts`：Direct Extra 安装、capability 和降级判断。
- `frida/extra-hooks.ts`：依赖 `frida-il2cpp-bridge` 的旧 Extra。
- `frida/floating-overlay.ts`：iOS 原生悬浮窗。
- `profiles/arknights-2.7.61-59.json`：当前已生成 RVA/prologue。

### 2.3 Trainer

`frida/direct-trainer.ts` 目前声明 20 个命令；当前 profile 预计可安装 18 个，其中 2 个只是 partial：

- Direct 代码路径可用（16）：`unlock_fps`、`battle_speed_16x`、`tas_pause`、`tas_step`、`zero_cost`、`zero_deploy_cnt`、`deploy_everywhere`、`zero_cooldown`、`no_sp`、`withdraw_everything`、`heal_everyone`、`unlimited_ammo`、`eat_enemy`、`anti_air`、`no_ban_card`、`cloner_assist`。
- Partial（2）：`unlimited_token`、`true_aoe`。
- Direct 不可用（2）：`global_range`、`allow_dup_char`；目前只能依赖兼容的 legacy bridge。

当前 profile 含 36 个 `trainer*` RVA。上述“可用”只表示 profile 和安装条件满足；本轮没有把它们视为已完成实机语义验证。

### 2.4 当前验证快照

以下自动化结果沿用当前工作树已有记录；本次只修改 TODO 并复核 dump/profile 证据，没有重跑完整测试：

- Python：`114 passed in 84.39s`。
- Ruff：通过。
- TypeScript：`npm run typecheck` 通过。
- iPhone 实机：本轮未验证。
- 两个代理相关测试曾在沙箱内因不能绑定 `127.0.0.1` 失败；沙箱外完整 pytest 已通过，因此不能把该失败归因于业务代码。

## 3. 架构限制和实现原则

1. **Direct 优先。** 当前游戏裁剪 IL2CPP exports，不能把 bridge 能加载作为 iOS 功能的前提。
2. **每个版本都重新生成和校验 profile。** dump 中存在方法不等于运行地址可安全 hook；必须同时校验 Mach-O UUID、text 范围和 prologue。
3. **返回 ABI 必须分类。**
   - `bool` / `int32_t` / 指针：优先 `Interceptor.attach` + `retval.replace`。
   - `Torappu.FP`：按 arm64 单寄存器 32.32 定点值处理前，需先做原值采样和边界验证。
   - `ObscuredInt` 或大结构体：不得直接按普通整数替换返回值。
4. **所有单位类 Trainer 必须按 side 限制。** 复用 `BObject.get_side`；selector 类先取 owner 再判定，不能无条件同时修改敌我双方。
5. **恢复和生命周期与启用同等重要。** 战斗结束、`UIController.OnDestroy`、detach 或“全部关闭”时清空缓存指针、待执行 TAS、临时速度/FPS 和 overlay 状态。
6. **高频 getter 不做重日志。** 运行日志限频、聚合，悬浮窗刷新建议 100–2000 ms，默认 200 ms。

## 4. P0：先加固已有 Direct / Extra / Trainer

### 4.1 全部关闭与状态恢复

- [ ] 增加“全部关闭 / 恢复游戏默认”命令，并在悬浮窗提供单独按钮。
- [ ] 禁用 `unlock_fps` 时主动恢复：
  - 优先保存 hook 首次观察到的原始 `Application.set_targetFrameRate` 参数；
  - 如果启用前没有观察值，使用明确的配置 fallback，而不是猜测设备刷新率；
  - 验收必须覆盖“启用 → 禁用 → 切后台/前台 → 新战斗”。
- [ ] 保留现有战斗速度恢复逻辑，并验证 1x/2x/3x 状态都能正确还原。
- [ ] `UIController.OnDestroy` 或战斗退出时清理 `uiController`、`tasOwnsPause`、step pending/state、临时 controller/logger/entity 指针。
- [ ] detach 前尽最大努力恢复状态；恢复失败时发出结构化事件，不静默吞掉。

**完成标准：** 连续进入两场战斗，第一场启用并关闭全部功能，第二场在不重启游戏的情况下保持原生 FPS、速度、暂停和部署行为。

### 4.2 安全的 `enable all`

- [ ] 将 `enable all` 改为显式安全 allowlist，不再简单选择所有非 action 命令。
- [ ] 默认排除 `battle_speed_16x`、partial、high-risk、一次性 action 和尚未实机验收的功能。
- [ ] 如需全开高风险项，使用名称明确的二次命令，例如 `enable unsafe-all`，并要求确认。

当前问题依据：`openbachelor_ios/runner.py` 的 `_trainer_cli` 只排除了 `TRAINER_ACTION_COMMANDS`，没有排除 `battle_speed_16x` 等高风险状态命令。

### 4.3 capability、风险和冲突可见化

- [ ] 显示 backend（`direct-rva` / `bridge`）、profile id、游戏 version/build、Mach-O UUID 和 hook error 摘要。
- [ ] 检查 Extra 与 Trainer 对 `BattleController.Update`、pause、speed 的重复 hook；定义唯一状态所有者。
- [ ] 同一个地址安装多个 `Interceptor` 前做注册表检查，事件中输出冲突来源。

### 4.4 Direct 捕获正确性

- [ ] 修正 `webHttpResponseStatus()` 的 layout 依赖：检查/读取 `webHttpResponseCode`，不得复用 `bestHttpResponseCode`。
- [ ] 新增一个故意让 `bestHttpResponseCode != webHttpResponseCode` 的 profile fixture，防止当前两个偏移刚好同为 `0x18` 掩盖错误。
- [ ] `direct-ready.capabilities` 分开报告“配置启用”“offset/layout 满足”“hook 已安装”“运行时实际命中”，不把前两项等同于链路成功。
- [ ] 每次 response、exception、cancel、detach 都清理关联 request/body/stream state；增加 map 高水位和未清理计数测试。
- [ ] battle-finish blocker 所需 layout 任一缺失时保持 unavailable；合成响应失败不得放行一个被部分修改的对象。

## 5. P1：优先实现的 Extra

### 5.1 战斗仪表盘（最高优先级，纯读取）

- [ ] 在现有 `extraBattleControllerUpdate` 中复用 live `BattleController*`。
- [ ] 默认每 200 ms 读取并显示：
  - 关卡进度：`get_completeProgress`；
  - Seed：`get_randomSeed`；
  - 当前速度档：`get_speedLevel`；
  - 玩家 side：`get_playerSide`。
- [ ] 任意读调用异常后停用对应指标，不拖垮其他 Extra。
- [ ] 悬浮窗折叠时停止高频格式化，保留低频采样。

**依据：** 上述方法均在 2.7.61 (59) `script.json` 中有明确标量签名，见第 11 节；当前 `BattleController.Update` hook 和刷新限频已经存在，可做最小增量。

### 5.2 实时统计与战斗总结

- [ ] 通过 `BattleController.get_logger` 获取 `BattleLogger`，再读取生成到 profile 的 layout。
- [ ] 首版只读并显示 `killedEnemiesCnt`、`totalHeal`、`totalDamage`。
- [ ] 战斗结束时输出一份本地 JSON 摘要；不得上传或伪造结算。
- [ ] 后续可增加角色伤害、受伤、治疗和技能触发次数，但先验证容器布局和列表遍历。

布局依据：

- `BattleLogger.m_stats`：对象偏移 `0x30`。
- `BattleLogger.BattleStats.killedEnemiesCnt`：`0x10`。
- `totalHeal`：`0xB8`。
- `totalDamage`：`0xBC`。

这些偏移来自当前 `dump.cs`，**只作为 generator 输入证据**；Agent 中不得硬编码。

### 5.3 操作时间轴和诊断导出

- [ ] 在当前时间/Tick 展示基础上记录部署、撤退、技能触发事件。
- [ ] 每条事件保存 Tick、战斗秒数、操作类型、单位标识、格子和方向。
- [ ] 悬浮窗只显示最近 N 条，完整记录写本地 JSON；提供复制诊断摘要。
- [ ] 记录丢包/无法解析字段时保留原始指针事件和错误，不伪造缺失值。

### 5.4 条件自动暂停

- [ ] 支持指定 Tick 暂停。
- [ ] 支持剩余敌人数达到阈值暂停。
- [ ] 支持费用达到阈值暂停。
- [ ] 支持指定单位技能可用时暂停。
- [ ] 条件只触发一次；用户继续后不得在同一 Tick 立即重复暂停。

复用现有 `tas_pause` / `tas_step` 状态机，不再创建第二套 pause owner。

### 5.5 Profile 健康面板

- [ ] 显示 offset/prologue 校验通过数、缺失数和首个失败符号。
- [ ] 显示 Extra/Trainer 实际安装 hook 数，不以配置开关冒充 capability。
- [ ] 提供导出诊断信息按钮，内容不包含 token、账号凭据或隐私请求体。
- [ ] 游戏更新后 profile 不匹配时明确显示“未启用”，禁止尝试旧 RVA。

### 5.6 悬浮窗完善

- [ ] 把 Extra 开关、时间线刷新间隔、目标 FPS、速度倍率放入原生悬浮窗。
- [ ] 增加 compact / dashboard 两种布局，避免遮挡战斗。
- [ ] 支持拖动吸边、透明度、字体缩放和安全区。
- [ ] 截图模式：一键隐藏控制按钮，仅保留只读数据，再次点击恢复。

### 5.7 波次、首领倒计时与击杀拆分

- [ ] 在仪表盘增加首领倒计时开关：
  - `BattleController.get_enemyBossCountDownActivated`，RVA `0x14B894`；
  - `BattleController.get_enemyBossCountDown`，RVA `0x14B960`。
- [ ] 捕获 live `Scheduler*`，显示总敌人、总波次、已生成波次、击杀/漏怪/完成数。
- [ ] 首版只调用返回 `int32_t` / `uint32_t` / `float` 的 getter，不遍历 `waves` 和 managed list。
- [ ] 记录波次切换、首领倒计时开始/结束事件，为自动暂停和回放提供统一时间点。
- [ ] 特殊模式中统计语义不一致时显示 mode 和 raw counters，不擅自换算成普通关卡语义。

**Scheduler 候选：** `get_totalEnemiesCnt @ 0x40B71C`、`get_totalWavesCnt @ 0x40B814`、`get_spawnedEnemiesCnt @ 0x40BAC0`、`get_spawnedWavesCnt @ 0x40BB38`、`get_killedEnemiesCnt @ 0x40BC28`、`get_validMissedEnemiesCnt @ 0x40BE98`。

### 5.8 原生血条、技能条和范围提示

- [ ] `always_show_enemy_hp`：仅对 enemy 组合覆盖：
  - `Enemy.get_hideHp @ 0x536078` → false；
  - `Enemy.get_alwaysShowHpFlag @ 0x5361B0` → true。
- [ ] 可选 `show_enemy_sp`：`Enemy.get_showSpUIFlag @ 0x536128` → true；默认关闭，避免把“SP”误标为所有敌人的同一种机制。
- [ ] `keep_skill_range_visible`：以 `BasicSkill.get_owner @ 0x44A5E4` 判定 ally，再让 `get_forceToShowRange @ 0x450EC8` 返回 true。
- [ ] UI getter 只改变本地展示，不把它们作为实体枚举或战斗逻辑的 source of truth。
- [ ] 分别验证普通敌人、Boss、隐匿单位、无 SP 单位、陷阱和多形态敌人。

### 5.9 无障碍与画面诊断

- [ ] `disable_camera_shake`：为 `CameraController.ShakeCamera @ 0x1DDE08` 增加可恢复的 no-op hook；保留原始调用计数用于诊断。
- [ ] `disable_battle_slow_motion`：评估仅对 `BattleController.get_isDisableSlowMotion @ 0x14E028` 返回 true；确认不会跳过必须等待的剧情/结算状态。
- [ ] 实时 FPS/帧时面板：显示 render frame、battle tick、平均/95 分位帧时和当前 target FPS，采样与日志都限频。
- [ ] 卡顿标记：帧时超过阈值时只记录时间点和当前战斗状态，不在高频线程执行堆栈回溯。
- [ ] 所有画面开关在截图模式和第二场战斗中自动恢复，不写入游戏持久配置。

### 5.10 敌人路径、ETA 与攻击范围诊断（P2）

- [ ] 在 Direct Vision 建立稳定实体生命周期后，再显示敌人到下一 checkpoint 的距离和估算 ETA。
- [ ] 候选：`Enemy.TryGetDistanceToNextCheckpoint @ 0x53FB74` 的 `float* out`、`Entity.get_moveSpeed @ 0x218A04`。
- [ ] ETA 必须标记为估算值；停顿、传送、路线切换、加减速和特殊移动模式会使简单的 `distance / speed` 失真。
- [ ] 攻击范围首版复用游戏已有 range id / selector，不自行猜测格子；提供“原始范围”和“当前 buff 后范围”的区分。
- [ ] overlay 不保留已销毁 `Enemy*`，所有调用都必须在已确认的游戏线程和生命周期内完成。

## 6. P1/P2：Direct 网络、捕获与诊断候选

### 6.1 传输覆盖率与关联质量（P1）

- [ ] 按 `UnityWebRequest` / `BestHTTP` / `ServerNet` / `LongService` 显示 hook 已安装数、请求数、响应数、孤立请求、孤立响应、stream 数和 warning 数。
- [ ] 为 HTTP 请求记录 monotonic 起止时间和 duration；不能只依赖 wall-clock ISO 时间计算延迟。
- [ ] session 结束时输出 capture summary，明确“没有流量”“只有 request”“body 被截断”和“该 transport unavailable”的区别。
- [ ] 为重复 URL 和重试保留独立 `request_id`，不得按 URL 合并；BestHTTP pointer 复用时验证旧 state 已清理。
- [ ] 增加最小链路自检：发出/观察一个已知低风险请求后，报告实际命中的 transport，而不是只看 `direct-ready`。

### 6.2 捕获规则、脱敏和实时控制（P1）

- [ ] 增加 host/path/method/transport allowlist 与 denylist；规则只影响落盘，不改变网络请求本身。
- [ ] 增加 header 脱敏默认集：`Authorization`、`Cookie`、`Set-Cookie`、token/session/device-id 类字段；JSON body 使用显式 key 规则。
- [ ] 脱敏发生在 JSONL/HAR/body sidecar 写入之前；不能先写原文再二次覆盖。
- [ ] overlay/CLI 支持 `capture pause`、`capture resume`、`mark <label>` 和“导出最近 N 秒”；暂停捕获不 detach hooks。
- [ ] 规则命中、丢弃字节数和脱敏字段数进入 summary；日志不得输出被脱敏原值。
- [ ] 原始全量捕获只能由显式 unsafe 配置开启，并在 UI 持续显示敏感数据警告。

### 6.3 Body、压缩与协议可读性（P2）

- [ ] Host 端按 `Content-Encoding` 解 gzip/br/deflate，保留原始 sidecar、派生文件和哈希，解码失败不覆盖原始证据。
- [ ] 对 JSON、文本、图片、protobuf/未知 binary 分类型预览；未知类型只显示长度、SHA-256 和前 N 字节十六进制。
- [ ] 为 ServerNet / LongService 建立 `main_id + sub_id -> 消息名/schema` 的版本化映射；未确认 schema 时只保留原始 frame。
- [ ] 请求/响应语义关联优先在 Host 端完成，Direct Agent 只采集最小元数据，避免增加游戏线程负担。
- [ ] 解码产物记录 decoder 版本、输入 hash 和错误，不能把启发式解析结果标成原始包内容。

### 6.4 可审阅的 URL 规则与隐私阻断（P2）

- [ ] 将 URL rewrite 从单一全局 origin 扩展为有序规则表：match host/path/method，action 仅允许 passthrough/rewrite/block。
- [ ] `block` 必须为每条规则明确选择“真实失败”或“本地合成响应”；默认真实失败，不能泛用 battle-finish 的成功响应。
- [ ] battle-finish blocker 增加 route 命中计数、原始状态读取失败原因和 response layout 自检。
- [ ] 为 telemetry/privacy 候选先做只观察命中报告，再允许用户显式阻断；登录、更新、支付和账号接口不得进入默认阻断表。
- [ ] 规则配置包含 schema/version 并做冲突检测；同一请求只能有一个最终 action，UI 显示命中的规则 id。

### 6.5 Direct 运行时管理（P1）

- [ ] 统一 hook registry，记录地址、profile key、模块、安装者、capability 和冲突；覆盖 Direct/Extra/Trainer 重复地址。
- [ ] 增加运行时状态快照 RPC：profile id/UUID、配置摘要、capture counters、active request map 大小、Extra/Trainer 状态。
- [ ] 对 `requests`、`uploadBodies`、`downloadRequests`、BestHTTP state 和 stream fragment map 增加生命周期上限与泄漏计数。
- [ ] 配置热更新只允许安全字段；需要重装 hook 的字段明确返回 `restart-required`，不伪装成已生效。
- [ ] detach/脚本销毁前输出最终 summary 并清理 Agent 内状态；Host 落盘失败应反向显示在 overlay/CLI。

## 7. P1：低风险 Trainer 候选

这些候选相对容易 Direct 化，但都必须先加入 `MethodSpec`、生成 profile/prologue，并逐项实机启用/禁用。

| TODO | 建议命令 | 方法候选 | Direct 行为 | 关键边界 |
|---|---|---|---|---|
| [ ] | `ally_invincible` | `Entity.get_isInvincible` | 仅 ally 返回 true | 必须用 `BObject.get_side`；确认召唤物 side |
| [ ] | `reveal_enemies` | `Entity.get_isHiddenToAlly` | 仅 enemy 返回 false | 不修改 ally/中立对象；检查 UI 与目标选择是否共用 |
| [ ] | `freeze_enemy_movement` | `Entity.get_canMove` | 仅 enemy 返回 false | 可能影响出生/退出流程，必须验证关卡能结束 |
| [ ] | `ally_status_immunity` | `get_isStunned/Frozen/Sleeping/Silenced/Disarmed` | 仅 ally 返回 false | 分状态开关，不能用一个失败 hook 隐藏全部 capability |
| [ ] | `ally_extended_status_immunity` | `get_isCold/Doze/Feared/Palsy/Attracted` | 仅 ally 分项返回 false | 不把 Levitate/Doze 等可能有正面用途的状态默认合并 |
| [ ] | `ally_atk_multiplier` | `Entity.get_atk` | ally 的 FP 原值乘倍率 | 32.32 定点、溢出和负值需校验 |
| [ ] | `ally_attack_speed_multiplier` | `Entity.get_attackSpeed` | ally 的 FP 原值乘倍率 | 设上限，验证动画与实际攻击间隔 |
| [ ] | `ally_block_count` | `Entity.get_blockCnt` | ally 返回配置值或原值增量 | 正确 RVA 是 `0x218968`，见第 11 节纠错 |
| [ ] | `unlimited_deploy_slots` | `GetRemainingAvailableCharacterCnt` | player side 返回配置上限 | 与 `zero_deploy_cnt` 分开，避免概念混淆 |
| [ ] | `dont_occupy_deploy_limit` | `Card.get_dontOccupyMaxDeployCnt` + `get_playerSide` | 仅 player card 返回 true | 与现有 `dontOccupyDeployCnt` 是两条不同限制 |
| [ ] | `instant_redeploy` | `Card.get_respawnValid/Progress/RemainingTime` | player card 立即 ready | FP 的 0/1 返回 ABI、卡片状态机和 UI 必须一起验证 |
| [ ] | `withdraw_refund` | `Character/Token.get_allowWithdrawGainCost` | 仅 ally 撤退允许返费 | “允许返费”不保证 100% 比例，首版名称不要写 full refund |
| [ ] | `skill_sp_free` | `BasicSkill.get_spCostZero/canCastWithNoSp/spEnough/canSkipReduceSp` | 仅 ally skill 返回 true | 通过 `BasicSkill.get_owner` 判 side；不能影响敌方技能 |
| [ ] | `target_camouflage` | `Ability.get_canSelectCamouflageTarget` + selector force flag | 仅 ally ability/selector 忽略 camouflage | 与只改变画面的 `reveal_enemies` 分开 |
| [ ] | `cost_lock` | `BattleController.GetCost` | player side 返回锁定值 | 先验证 getter 是否也是逻辑真实来源 |
| [ ] | `battle_speed` | 复用当前 speed 方法 | 将固定 16x 改为可调倍率 | 保留旧配置迁移，默认上限 3x 或 4x |

补充要求：

- [ ] 每个倍率型功能支持配置上下限，非法值 fail closed。
- [ ] side 判断失败时调用原方法，不做全局替换。
- [ ] 高频方法用一个共享 side helper，避免递归调用自身 hook。
- [ ] Card 使用 `Card.get_playerSide`，BasicSkill/Ability/selector 分别通过 owner 再调用 `BObject.get_side`；不得把一种对象的 side helper 强套给另一种对象。
- [ ] 所有功能在敌我混合、召唤物、陷阱、无人机和中立物件场景分别验证。

## 8. P1：补完整 `true_aoe`

当前 Direct 实现只提高目标数，没有跳过 legacy bridge 使用的两个泛型 post-filter，因此仍标记 partial。

- [ ] profile generator 增加：
  - `RandomSelector.OnPostFilter(List<Entity>)`，RVA `0x4D9500`；
  - `ParallelGroupSelector.OnPostFilter(List<Entity>)`，RVA `0x4D7B18`。
- [ ] Direct 使用保留引用的 `NativeFunction` + `NativeCallback` / `Interceptor.replace`：
  - selector owner 是 ally：跳过原 post-filter；
  - selector owner 不是 ally或无法判定：调用原方法。
- [ ] 明确选择 `List<Entity>` overload，不能误用同名 `List<Tile>` overload。
- [ ] 只有“目标上限”和两个 post-filter hook 全部成功时才移除 partial 标记。
- [ ] 禁用时恢复原实现；连续开关至少 20 次且无崩溃。

## 9. P2：TAS、回放和自动化

### 9.1 Seed 控制

- [ ] 显示当前 seed。
- [ ] 支持为**下一次重开**设置 seed，并保留恢复随机 seed 的选项。
- [ ] 不宣称“战斗中改 seed 即可回到相同状态”；随机数状态之外还有完整战斗状态。
- [ ] 使用 `BattleController.ResetSeed(int)` 前确认调用时机和 controller 生命周期。

### 9.2 操作录制与回放

- [ ] hook `PlayerOp_Spawn`、`PlayerOp_Withdraw`、`PlayerOp_TrigSkill` 记录操作。
- [ ] 录制至少包含：
  - 游戏 version/build、profile id、Mach-O UUID；
  - seed、levelId、阵容；
  - Tick、部署 uniqueId、格子、方向；
  - 撤退目标和技能目标/extraInfo。
- [ ] 回放前校验关卡、阵容、profile 和 seed 一致，不一致则拒绝执行。
- [ ] 回放每一步都等待预期 Tick/状态，失败即暂停并报告，不盲目继续。

### 9.3 检查点

- [ ] 检查点采用“重开关卡 + 固定 seed + 快速回放到目标 Tick”。
- [ ] 不尝试复制整个 Unity/IL2CPP heap；对象引用、native 资源、线程和 GC 状态无法安全还原。
- [ ] 首版只支持本地调试记录，不接管服务器结算。

### 9.4 选择性自动技能

- [ ] 用 `BasicSkill.IsTriggerable` / `IsAutoSkillTriggerable` 观察技能是否就绪。
- [ ] 只对用户显式选择的单位生效。
- [ ] 支持 once / cooldown / 指定 Tick 窗口，默认关闭。
- [ ] 复用操作记录格式，使自动触发也能被回放和审计。

### 9.5 已有日志结构的使用边界

`BattleLogger.Journal` 已包含：

- `metadata`：`0x0`；
- `squad`：`0x38`；
- `logs`：`0x40`；
- `randomSeed`：`0x48`。

它是较大的值类型。Direct 模式不要直接调用返回完整 `Journal` 的方法；优先 hook 玩家操作入口或读取 `BattleLogger` 内部列表，并让 generator 提供所有 layout。

## 10. P2/P3：其他 Extra 与高复杂度 Trainer

### 10.1 自由镜头/缩放

- [ ] 捕获 live `CameraController*`，提供缩放、恢复和跟随开关。
- [ ] 候选方法：`ResetAll`、`UpdateCameraControllerScale`、`ResetFocusAndScale`。
- [ ] 限制 scale 范围；进入/退出战斗、横竖屏或 UI 重建后自动恢复。
- [ ] 先完成截图模式，再考虑自由平移；避免破坏触摸坐标映射。

### 10.2 Direct/原生 Vision

- [ ] 不依赖 `frida-il2cpp-bridge` 创建单位头顶信息。
- [ ] 先找到稳定的 entity 枚举源、world-to-screen 转换和对象销毁信号。
- [ ] 首版只显示 side、HP、SP、模板 ID；不得长期保留已销毁 entity 指针。
- [ ] overlay 更新与游戏 getter 解耦，统一 100–200 ms 采样。
- [ ] 后续再做敌人路径、ETA、阻挡预测和攻击范围，避免首版范围过大。

### 10.3 `global_range`（P3）

- [ ] 先画出候选生成链：RangeSelector / collider / tile query / post-filter。
- [ ] 不能只把 `CheckTargetIn` 改成 true；如果候选集根本没有全图单位，后续判断永远看不到目标。
- [ ] 需要扩展碰撞/范围查询或提供全局候选集，并保留 ally owner 限制。
- [ ] 单独验证远程、近战、治疗、随机选择和 tile selector。

### 10.4 `allow_dup_char`（P3）

- [ ] 梳理 `uniqueId`、`tokenOrHostUniqueId`、deck/list、对象注册、日志和回放的完整关系。
- [ ] 不只绕过编队 UI 检查；战斗内 ID 冲突会影响选择、撤退和技能。
- [ ] 在 Direct 方案完整前维持 unavailable，不能以“hook 成功”冒充可用。

### 10.5 完整 `unlimited_token`（P3）

- [ ] 当前标量检查保留 partial。
- [ ] 分析 `ObscuredInt get_maxDeployCnt` 的 arm64/arm64e 返回 ABI 后再决定实现。
- [ ] 优先修改标量消费点或受控字段，不直接把结构体 getter 当 `int32_t` 替换。
- [ ] 覆盖 token host、重复部署、撤退后重部署和上限 UI。

### 10.6 完整 `no_sp` 与技能次数拆分（P2）

- [ ] 将“SP 足够”“不扣 SP”“技能可用次数”拆成三个 capability，不再由一个命令静默混合。
- [ ] ally side 链：`BasicSkill.get_owner @ 0x44A5E4` → `BObject.get_side`。
- [ ] no-cost 候选：`get_spCostZero @ 0x450838`、`get_canCastWithNoSp @ 0x450E3C`、`get_spEnough @ 0x44E404`、`get_canSkipReduceSp @ 0x44A758`。
- [ ] SP 恢复停滞保护候选：`Entity.get_canRecoverSp @ 0x2154B8` → true、`get_spRecoverStopped @ 0x219520` / `get_spModifyStopped @ 0x2195BC` → false；仅 ally。
- [ ] 技能次数候选保留 `BasicSkill.get_availableCnt` / `get_isUsedUp`，但必须 side-gated；验证弹药制、过载、自动回复和无限持续技能。
- [ ] 首版不 replace `BasicSkill.ReduceSp`；如果 getter 组合仍会真实扣 SP，再单独分析其返回值和调用者语义。

### 10.7 敌方动作控制（P2，高风险）

- [ ] `enemy_no_attack` 候选：`Entity.get_canUseAtkOrCbt @ 0x215C20` 对 enemy 返回 false。
- [ ] `enemy_no_ability` 候选：`Entity.get_canUseAbility @ 0x21581C` 对 enemy 返回 false。
- [ ] 与 `freeze_enemy_movement` 分离，允许逐项组合；UI 持续显示“可能阻止脚本推进/关卡结束”。
- [ ] 必须覆盖依赖攻击/技能切阶段的 Boss、剧情敌人、装置和中立单位；任何无法结束的关卡都维持 high-risk。
- [ ] 禁用后只恢复 getter 行为，不尝试强制修改已经进入的 ability/state machine。

### 10.8 Ally 不死与异常状态强制（P3）

- [ ] `ally_undead` 候选：`Entity.get_isUndeadable @ 0x21A130` 仅 ally 返回 true；不得与 `ally_invincible` 混成一个 capability。
- [ ] `ally_skill_in_abnormal` 候选：`get_isSkillActivatable @ 0x21A4D8`、`get_isSkillActivatableInAbnormal @ 0x21A57C` 仅 ally 返回 true。
- [ ] 不默认覆盖 `get_inAbnormalState` 总判断；它可能被动画、输入和技能逻辑共同依赖。
- [ ] 验证 HP=0、强制退场、坠落、剧情撤离、复活和第二形态；如果只阻止回收却不能恢复可操作状态，标记不可用。

### 10.9 Ability 冷却与必中特性（P3）

- [ ] `ability_no_cooldown` 候选链：`Ability.get_owner @ 0x1063AC` 判 ally，覆盖 `get_isReady @ 0x106880`、`get_isReadyIgnoreAttachAndCooldown @ 0x1069E0`、`get_isCooledDown @ 0x10693C`。
- [ ] `get_cooldownProgress @ 0x10664C` 是 FP；只有原始 0/1 采样和 ABI 测试通过后才返回 1.0。
- [ ] `always_hit` 候选：`Projectile.get_source @ 0x3C7218` 判 ally，再让 `get_damageMissFlag @ 0x3D1D38` 返回 false；同时观察 `Entity._VerifyAbilityDamageMiss @ 0x22A174` 是否仍会在更早阶段判定 miss。
- [ ] Ability 是通用能力基类，可能覆盖普攻、技能、剧情和机关；必须按 owner side 且默认排除 owner=null。
- [ ] 不能仅因 getter 被调用且返回值被替换就宣布语义完成；至少用闪避/必闪、弹道丢失和多段攻击关卡验证。

### 10.10 卡片可用性与隐藏状态补全（P2）

- [ ] 当前 `no_ban_card` 只覆盖 `Card.get_isAvailable`；分析 `get_isHidden`、`get_isHiddenByCardState`、`get_readyToSpawn` 和 `get_readyToSpawnWithoutCheckCost` 的实际调用顺序。
- [ ] 任何覆盖都先用 `Card.get_playerSide @ 0x1EABF4` 限制 player side。
- [ ] 剧情隐藏卡、内部触发卡和未解锁卡默认不强制显示；先按 unique id/白名单选择具体卡片。
- [ ] `instant_redeploy`、`no_ban_card`、`unlimited_token` 对同一 Card getter 的 hook 需由统一 registry 合成结果，不能叠加多个 `Interceptor` 猜执行顺序。

## 11. 2.7.61 (59) Method/RVA 证据表

> 来源：`dumps/2.7.61-59/il2cppdumper/script.json`。
> 下表除已进入当前 profile 的项目外，都是 **dump 候选**；地址存在不代表已经生成 prologue 或通过实机验证。

### 11.1 Direct 网络（当前 profile 已有）

| Profile key / 方法 | RVA | 当前用途 | 新候选依赖 |
|---|---:|---|---|
| `unityWebRequestSend` | `0x7342F50` | UnityWebRequest request 发出 | duration、覆盖率、孤立请求清理 |
| `asyncOperationInvokeCompletionEvent` | `0x70B765C` | UnityWebRequest completion | response 关联和 monotonic 结束时间 |
| `networkerGenerateHttpPostRequest` | `0x6E75E08` | BestHTTP URL/body/request 捕获 | rule id、请求计时和 state 生命周期 |
| `networkerProcessBestHttpResponse` | `0x6E766E8` | BestHTTP response 捕获 | response 关联和 blocker 诊断 |
| `bestHttpResponseAddStreamedFragment` | `0x6CB24D0` | streaming fragment 捕获 | stream 完整性/乱序/截断统计 |
| `serverNetMsgSerialize/TryDeserialize` | `0x262BC28` / `0x262BD20` | ServerNet 帧 | main id 消息映射 |
| `longServiceNetMsgSerialize/TryDeserialize` | `0x2A26B6C` / `0x2A26CA8` | LongService 帧 | main/sub id 消息映射 |
| `networkerPostImplMoveNext` | `0x6E78C8C` | battle-finish 本地拦截 | route 命中、自检和失败诊断 |

这些 key 已进入当前 profile，但新功能仍需单独的 Agent/Host 逻辑和测试；不得把“当前 RVA 存在”写成候选功能已完成。

### 11.2 Extra / 观测

| 方法 | RVA | 签名要点 | 用途 |
|---|---:|---|---|
| `BattleController.get_remainingEnemiesCnt` | `0x151074` | `int32_t` | 剩余敌人 |
| `BattleController.get_completeProgress` | `0x15110C` | `float` | 关卡进度 |
| `BattleController.GetLifePoint` | `0x14F8AC` | `int32_t(side)` | 玩家生命 |
| `BattleController.GetCost` | `0x1505F0` | `int32_t(side)` | 当前费用 |
| `BattleController.get_randomSeed` | `0x14BCCC` | `int32_t` | Seed |
| `BattleController.get_speedLevel` | `0x14F1A8` | `int32_t` | 速度档；当前 profile 已有 Trainer 项 |
| `BattleController.get_playerSide` | `0x149B2C` | `int32_t` | side 判断 |
| `BattleController.get_levelId` | `0x14EF44` | `String*` | 关卡身份 |
| `BattleController.get_logger` | `0x14CDDC` | `BattleLogger*` | 实时统计入口 |
| `BattleController.get_enemyBossCountDownActivated` | `0x14B894` | `bool` | 首领倒计时开关 |
| `BattleController.get_enemyBossCountDown` | `0x14B960` | `float` | 首领倒计时值 |
| `BattleController.get_isDisableSlowMotion` | `0x14E028` | `bool` | 关闭战斗慢动作候选 |
| `Scheduler.get_totalEnemiesCnt` | `0x40B71C` | `int32_t` | 总敌人数 |
| `Scheduler.get_totalWavesCnt` | `0x40B814` | `int32_t` | 总波次数 |
| `Scheduler.get_spawnedEnemiesCnt` | `0x40BAC0` | `uint32_t` | 已生成敌人数 |
| `Scheduler.get_spawnedWavesCnt` | `0x40BB38` | `int32_t` | 已生成波次数 |
| `Scheduler.get_validMissedEnemiesCnt` | `0x40BE98` | `int32_t` | 漏怪拆分 |
| `Enemy.get_hideHp` | `0x536078` | `bool` | 原生敌人血条 |
| `Enemy.get_showSpUIFlag` | `0x536128` | `bool` | 原生敌人 SP 条 |
| `Enemy.get_alwaysShowHpFlag` | `0x5361B0` | `bool` | 常驻血条 |
| `BasicSkill.get_forceToShowRange` | `0x450EC8` | `bool` | ally 技能范围常驻 |
| `Enemy.TryGetDistanceToNextCheckpoint` | `0x53FB74` | `bool(float* out)` | 路径距离/ETA |
| `CameraController.ResetAll` | `0x1DD1F0` | `void(bool tween)` | 镜头恢复 |
| `CameraController.ShakeCamera` | `0x1DDE08` | `void(float, Vector3, int, float)` | 关闭镜头震动 |
| `CameraController.GetCameraScale` | `0x1DF648` | `float` | 当前缩放 |
| `CameraController.ResetFocusAndScale` | `0x1DED48` | `void(float, int, int)` | 恢复焦点/缩放 |
| `CameraController.UpdateCameraControllerScale` | `0x1DF9D4` | `void(float)` | 自由缩放 |

### 11.3 Trainer 候选

| 方法 | RVA | 返回/参数 | 注意 |
|---|---:|---|---|
| `Entity.get_isInvincible` | `0x21A07C` | `bool` | 仅 ally |
| `Entity.get_isHiddenToAlly` | `0x219F8C` | `bool` | 仅 enemy 返回 false |
| `Entity.get_canMove` | `0x215DA0` | `bool` | 冻结可能阻止退出 |
| `Entity.get_isStunned` | `0x2158E4` | `bool` | ally 异常免疫 |
| `Entity.get_isFrozen` | `0x2159B0` | `bool` | ally 异常免疫 |
| `Entity.get_isSleeping` | `0x219484` | `bool` | ally 异常免疫 |
| `Entity.get_isSilenced` | `0x21A43C` | `bool` | ally 异常免疫 |
| `Entity.get_isDisarmed` | `0x215CBC` | `bool` | ally 异常免疫 |
| `Entity.get_isCold` | `0x21934C` | `bool` | 扩展异常免疫 |
| `Entity.get_isDoze` | `0x215B84` | `bool` | 扩展异常免疫；可能有正面语义 |
| `Entity.get_isFeared` | `0x2199A4` | `bool` | 扩展异常免疫 |
| `Entity.get_isPalsy` | `0x219A70` | `bool` | 扩展异常免疫 |
| `Entity.get_isAttracted` | `0x219B0C` | `bool` | 扩展异常免疫 |
| `Entity.get_atk` | `0x218488` | `Torappu.FP` | 32.32 定点/ABI |
| `Entity.get_attackSpeed` | `0x2180CC` | `Torappu.FP` | 32.32 定点/ABI |
| `Entity.get_blockCnt` | `0x218968` | `int32_t` | 通用 Entity block getter |
| `Entity.get_canUseAbility` | `0x21581C` | `bool` | enemy ability 控制；高风险 |
| `Entity.get_canUseAtkOrCbt` | `0x215C20` | `bool` | enemy attack 控制；高风险 |
| `Entity.get_isUndeadable` | `0x21A130` | `bool` | ally 不死候选；高风险 |
| `Entity.get_isSkillActivatable` | `0x21A4D8` | `bool` | ally 异常中技能控制 |
| `Entity.get_isSkillActivatableInAbnormal` | `0x21A57C` | `bool` | ally 异常中技能控制 |
| `BattleController.GetRemainingAvailableCharacterCnt` | `0x14EB44` | `int32_t(side)` | 剩余部署位 |
| `Deck.Card.get_playerSide` | `0x1EABF4` | `int32_t` | Card side helper |
| `Deck.Card.get_dontOccupyMaxDeployCnt` | `0x1F46B0` | `bool` | 不占最大部署限制 |
| `Deck.Card.get_respawnValid` | `0x1F32B0` | `bool` | 立即再部署候选 |
| `Deck.Card.get_respawnProgress` | `0x1F3358` | `Torappu.FP` | 立即再部署；32.32 定点/ABI |
| `Deck.Card.get_respawnRemainingTime` | `0x1F3458` | `Torappu.FP` | 立即再部署；32.32 定点/ABI |
| `Character.get_allowWithdrawGainCost` | `0x519F7C` | `bool` | 撤退允许返费 |
| `Token.get_allowWithdrawGainCost` | `0x5A34F8` | `bool` | Token 撤退允许返费 |
| `BasicSkill.get_owner` | `0x44A5E4` | `Character*` | BasicSkill side helper |
| `BasicSkill.get_spCostZero` | `0x450838` | `bool` | skill SP no-cost |
| `BasicSkill.get_canCastWithNoSp` | `0x450E3C` | `bool` | skill SP no-cost |
| `BasicSkill.get_spEnough` | `0x44E404` | `bool` | skill SP no-cost |
| `Ability.get_owner` | `0x1063AC` | `Entity*` | Ability side helper |
| `Ability.get_isReady/isCooledDown` | `0x106880` / `0x10693C` | `bool` | ability 冷却；高风险 |
| `Ability.get_canSelectCamouflageTarget` | `0x106CA8` | `bool` | ally 选中迷彩目标 |
| `AdvancedSelector.get_forceIgnoreCamouflage` | `0x4AB0D0` | `bool` | ally selector 忽略迷彩 |
| `TargetSelector.get_forceIgnoreCamouflage` | `0x4E6D90` | `bool` | ally selector 忽略迷彩 |
| `Projectile.get_source` | `0x3C7218` | `Entity*` | Projectile side helper |
| `Projectile.get_damageMissFlag` | `0x3D1D38` | `bool` | 必中候选；需核对更早判定 |
| `RandomSelector.OnPostFilter(List<Entity>)` | `0x4D9500` | `void(List*)` | 真群攻；不要选 Tile overload |
| `ParallelGroupSelector.OnPostFilter(List<Entity>)` | `0x4D7B18` | `void(List*)` | 真群攻；不要选 Tile overload |

**已纠正的分析结论：** `0x59AC3C` 实际是 `PropLikeStaticBlockToken.get_blockCnt`，不是 `Character.get_blockCnt`。通用单位候选应使用 `Entity.get_blockCnt @ 0x218968`；除非专门处理静态阻挡物，不得再引用 `0x59AC3C`。

### 11.4 TAS

| 方法 | RVA | 签名要点 |
|---|---:|---|
| `BattleController.ResetSeed(int)` | `0x158C74` | `void(int32_t)` |
| `BattleController.PlayerOp_Withdraw` | `0x15B220` | `bool(Character*)` |
| `BattleController.PlayerOp_Spawn` | `0x15B3FC` | `bool(uint32_t, direction, Tile*)` |
| `BattleController.PlayerOp_TrigSkill` | `0x15B5A4` | `bool(Character*, String*)` |
| `BasicSkill.IsTriggerable` | `0x44F288` | `bool(operationSide)` |
| `BasicSkill.IsAutoSkillTriggerable` | `0x44F424` | `bool(operationSide)` |

## 12. 每项功能的修改文件矩阵

| 文件 | 需要承担的职责 |
|---|---|
| `openbachelor_ios/profile_generator.py` | 增加 `MethodSpec` / layout 解析，是 RVA 和字段偏移的唯一来源 |
| `profiles/arknights-2.7.61-59.json` | 由 generator 重新生成；包含 RVA、prologue、layout，不手改 |
| `frida/direct-trainer.ts` | side-gated Direct hook、状态恢复、capability/partial/error 事件 |
| `frida/direct.ts` | 网络采集/重写、hook registry、运行时状态、Direct Extra/Trainer 编排 |
| `frida/extra-hooks.ts` | Legacy Extra 读取、生命周期和 bridge fallback |
| `frida/floating-overlay.ts` | 开关、风险标记、仪表盘、错误和恢复 UI |
| `openbachelor_ios/capture.py` | filter/redaction、计时关联、summary、压缩/派生文件和安全落盘 |
| `openbachelor_ios/capture_proxy.py` | 实时 viewer 桥接、错误/吞吐状态和隐私边界 |
| `openbachelor_ios/runner.py` | CLI 命令、安全 allowlist、全部关闭 |
| `openbachelor_ios/config.py` / `config.example.json` | 默认值、范围验证和旧配置迁移 |
| `launcher/*` | Launcher 可见配置与状态传递 |
| `README.md` | 用户用法、边界、风险和实机步骤 |
| `tests/*` | profile 生成、配置、命令路由、capability 和恢复回归 |
| `TODO.md` | 状态、实机证据和剩余风险 |

## 13. 统一验收清单

### 13.1 自动化

- [ ] `UV_CACHE_DIR=.uv-cache uv run --locked python -m pytest -q`。
- [ ] `UV_CACHE_DIR=.uv-cache uv run --locked ruff check openbachelor_ios tests`。
- [ ] `npm run typecheck`。
- [ ] `npm run build`，确认 Direct bundle 确实包含新增模块。
- [ ] 新增 profile generator 测试：正确 overload、RVA、prologue、layout、缺失符号 warning。
- [ ] 新增 Agent 行为测试：缺任一依赖时 unavailable，不能退化为未校验地址。
- [ ] 新增 CLI/overlay 测试：partial/high-risk 标签、`enable all` allowlist、全部关闭。
- [ ] 新增 Direct capture 测试：四种 transport 计数、request/response 关联、stream、截断、取消、异常和 state 清理。
- [ ] 新增隐私测试：敏感 header/body 在 JSONL、HAR、sidecar、日志和导出摘要中均不可回显。
- [ ] 新增 response layout 回归：BestHTTP/WebHttp code 使用不同 fixture offset 时仍分别读取正确字段。

### 13.2 实机最小矩阵

- [ ] 干净启动后只启用一个功能，记录 `trainer-ready` / `extra-ready`。
- [ ] ally、enemy、召唤物、陷阱、中立单位各验证一次 side 边界。
- [ ] 启用 → 禁用，确认值和行为立即恢复。
- [ ] 退出战斗 → 第二场战斗，确认没有 stale pointer 或遗留状态。
- [ ] 切后台/前台、暂停/继续、1x/2x/3x 切换。
- [ ] 连续开关 20 次，观察崩溃、卡死、耗电和日志洪泛。
- [ ] profile UUID/prologue 不匹配时功能必须 fail closed。
- [ ] 分别触发 UnityWebRequest、BestHTTP、ServerNet、LongService；记录实际命中，未出现的 transport 标记未验证而非通过。
- [ ] 启停 capture 但不 detach，确认网络行为不变、暂停期间不落盘、恢复后 request id 不冲突。
- [ ] capture 中断/Host 写盘失败/达到 body 上限时游戏继续运行，UI 明确显示丢失或截断。
- [ ] 记录设备型号、iOS、越狱/注入方式、Frida 版本、游戏 version/build。

### 13.3 每次实机记录模板

~~~text
日期：
commit / 工作树：
设备 / iOS：
注入模式 / Frida：
游戏 version(build)：
profile id / Mach-O UUID：
功能与输入：
观察到的事件/数值：
禁用恢复结果：
第二场战斗结果：
结论：通过 / partial / 失败
失败原因与下一步：
~~~

## 14. 明确不做或暂不建议

- 不做客户端强制奖励、物品、货币或账号进度。
- 不伪造服务器结算或把本地统计冒充服务器结果。
- 不提供泛化的“任意接口本地成功响应”；battle-finish 之外的合成响应必须逐 route 证明用途和失败语义。
- 不把账号 token、Cookie、设备标识或完整请求体默认写入可分享的诊断包。
- 不把 16x/32x 或其他高风险项默认启用，也不纳入安全 `enable all`。
- 不实现 Unity/IL2CPP 全堆内存快照式存档。
- 不安装未逐项校验 prologue 的全局 `Interceptor.replace`。
- 不因 hook 安装成功就把 partial/unavailable 标记改为 ready。

## 15. 决策记录

### 2026-08-22

- 当前 iOS build 的 IL2CPP exports 被裁剪，后续新增功能以 Direct RVA 为主，bridge 仅作可选 fallback。
- Extra Direct 当前基线是 `pause_deploy`、`3x_speed`、`battle_timeline`；Vision 尚无 Direct 等价实现。
- Trainer 当前基线是 20 个命令、18 个可控制、2 个 partial、2 个 Direct unavailable。
- 先完成安全恢复、仪表盘、统计和 profile 健康面板，再做高复杂度范围/重复角色。
- True AOE 的缺口已定位到两个 `List<Entity>` post-filter，不再重复搜索。
- TAS 检查点采用重开 + seed + 回放，不再评估全堆快照。
- `Entity.get_blockCnt @ 0x218968` 才是通用阻挡数候选；`0x59AC3C` 的旧归类已判定错误。
- Direct 后续优先补传输覆盖率、脱敏、关联计时和 state 生命周期，不先扩展任意响应伪造。
- `webHttpResponseStatus()` 当前误用 `bestHttpResponseCode` layout；两个字段在本 profile 恰好都是 `0x18`，必须用不同偏移 fixture 防止该错误继续被掩盖。
- Extra 新增候选以原生波次/首领统计、敌人 HP/SP、范围提示、镜头震动和路径 ETA 为主；需要实体生命周期的功能继续排在 Direct Vision 之后。
- Trainer 新增候选必须使用对象对应的 side 链：Card 直接读 playerSide，BasicSkill/Ability/selector 先取 owner，再读 BObject side。
- 敌方动作禁用、ally undead、Ability 冷却和 always-hit 虽有明确标量 getter/RVA，仍因状态机范围过宽列为 P2/P3。
- 当前工作树只有既有自动化基线，没有 iPhone 实机结果；本次新增候选仅完成静态证据核对，未验证项不得标记完成。
