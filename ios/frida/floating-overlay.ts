import ObjC from "frida-objc-bridge";

export interface FloatingOverlayOptions {
    captureEnabled: () => boolean;
    setCaptureEnabled: (enabled: boolean) => void;
    logConsoleVisible: boolean;
    trainerCommands: () => string[];
    trainerEnabled: (command: string) => boolean;
    setTrainerEnabled: (command: string, enabled: boolean) => void;
    trainerStepUnits: () => string[];
    requestTrainerStep: (unit: "tick" | "frame", count: number) => boolean;
    reportAction: (action: string, details?: Record<string, unknown>) => void;
}

export interface FloatingOverlay {
    record(payload: Record<string, any>): void;
    destroy(): void;
}

const UI_CONTROL_STATE_NORMAL = 0;
const UI_CONTROL_EVENT_TOUCH_DOWN = 1 << 0;
const UI_CONTROL_EVENT_TOUCH_UP_INSIDE = 1 << 6;
const UI_CONTROL_EVENT_EDITING_DID_BEGIN = 1 << 16;
const UI_CONTROL_EVENT_EDITING_DID_END = 1 << 18;
const UI_CONTROL_EVENT_EDITING_DID_END_ON_EXIT = 1 << 19;
const GESTURE_STATE_BEGAN = 1;
const GESTURE_STATE_CHANGED = 2;
const MAX_LINES = 160;
const MAX_TAS_STEP_COUNT = 10000;
const MAX_MOUNT_ATTEMPTS = 240;
const OVERLAY_WINDOW_LEVEL = 1001;

const TRAINER_LABELS: Record<string, string> = {
    unlock_fps: "解锁 120 FPS",
    battle_speed_16x: "16 倍战斗速度（高风险）",
    tas_pause: "TAS 暂停",
    tas_step: "TAS 步进",
    zero_cost: "零费用",
    zero_deploy_cnt: "不占部署位",
    deploy_everywhere: "全地形部署",
    zero_cooldown: "零再部署时间",
    unlimited_token: "无限召唤物",
    no_sp: "无限技力",
    withdraw_everything: "全部可撤退",
    heal_everyone: "治疗全部单位",
    unlimited_ammo: "无限弹药",
    eat_enemy: "敌人不扣生命",
    global_range: "全图范围",
    anti_air: "全目标类型",
    true_aoe: "真群攻",
    no_ban_card: "解除禁用干员",
    cloner_assist: "克隆助战",
    allow_dup_char: "允许重复干员",
};

const TRAINER_ACTIONS = new Set(["tas_step"]);
const TRAINER_CUSTOM_CONTROLS = new Set(["tas_step"]);
const TRAINER_GROUPS = [
    {
        title: "战斗节奏",
        commands: ["unlock_fps", "battle_speed_16x", "tas_pause", "tas_step"],
    },
    {
        title: "部署与资源",
        commands: [
            "zero_cost", "zero_deploy_cnt", "deploy_everywhere", "zero_cooldown",
            "unlimited_token", "no_sp", "withdraw_everything", "unlimited_ammo",
        ],
    },
    {
        title: "单位与目标",
        commands: ["heal_everyone", "eat_enemy", "global_range", "anti_air", "true_aoe"],
    },
    {
        title: "编队规则",
        commands: ["no_ban_card", "cloner_assist", "allow_dup_char"],
    },
];

function rgba(red: number, green: number, blue: number, alpha = 1): any {
    return ObjC.classes.UIColor.colorWithRed_green_blue_alpha_(red, green, blue, alpha);
}

function frame(x: number, y: number, width: number, height: number): any {
    return [[x, y], [width, height]];
}

function pointX(value: any): number {
    return Number(value?.[0] ?? value?.x ?? 0);
}

function pointY(value: any): number {
    return Number(value?.[1] ?? value?.y ?? 0);
}

function sizeWidth(value: any): number {
    return Number(value?.[1]?.[0] ?? value?.size?.width ?? 0);
}

function sizeHeight(value: any): number {
    return Number(value?.[1]?.[1] ?? value?.size?.height ?? 0);
}

function isNullObject(value: any): boolean {
    if (value === null || value === undefined) return true;
    try {
        return value.handle.isNull();
    } catch (_) {
        return false;
    }
}

function windowFromCollection(windows: any, excluded: any | null): any | null {
    const count = Number(windows.count());
    let fallback: any | null = null;
    for (let index = 0; index < count; index += 1) {
        const candidate = windows.objectAtIndex_(index);
        if (excluded !== null && candidate.equals(excluded)) continue;
        if (candidate.isHidden()) continue;
        const bounds = candidate.bounds();
        if (Number(candidate.alpha()) <= 0 || sizeWidth(bounds) <= 0 || sizeHeight(bounds) <= 0) continue;
        fallback = candidate;
        if (candidate.isKeyWindow()) return candidate;
    }
    return fallback;
}

function activeWindow(excluded: any | null = null): any | null {
    const application = ObjC.classes.UIApplication.sharedApplication();
    const windowSceneClass = ObjC.classes.UIWindowScene;
    if (windowSceneClass !== undefined && application.respondsToSelector_(ObjC.selector("connectedScenes"))) {
        const scenes = application.connectedScenes().objectEnumerator();
        while (true) {
            const scene = scenes.nextObject();
            if (isNullObject(scene)) break;
            if (!scene.isKindOfClass_(windowSceneClass)) continue;
            if (Number(scene.activationState()) > 1) continue;
            const candidate = windowFromCollection(scene.windows(), excluded);
            if (candidate !== null) return candidate;
        }
    }
    return windowFromCollection(application.windows(), excluded);
}

function button(title: string, x: number, y: number, width: number, height: number): any {
    const value = ObjC.classes.UIButton.buttonWithType_(0);
    value.setFrame_(frame(x, y, width, height));
    value.setTitle_forState_(title, UI_CONTROL_STATE_NORMAL);
    value.setTitleColor_forState_(rgba(0.91, 0.94, 0.96), UI_CONTROL_STATE_NORMAL);
    value.setBackgroundColor_(rgba(0.14, 0.17, 0.20, 0.96));
    value.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(12, 0.25));
    value.titleLabel().setAdjustsFontSizeToFitWidth_(true);
    value.titleLabel().setMinimumScaleFactor_(0.72);
    value.layer().setCornerRadius_(6);
    return value;
}

function shortUrl(value: unknown): string {
    if (typeof value !== "string" || value.length === 0) return "";
    const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(value);
    if (match === null) return "<url>";
    const path = match[3].length > 72 ? `${match[3].slice(0, 69)}...` : match[3];
    return `${match[1]}://${match[2]}${path}`;
}

function describeEvent(payload: Record<string, any>): string | null {
    const event = typeof payload.event === "string" ? payload.event : "event";
    if (event === "capture") {
        const parts = [payload.phase ?? "capture", payload.method ?? "", shortUrl(payload.url)];
        if (payload.status_code !== undefined) parts.push(String(payload.status_code));
        return parts.filter(Boolean).join(" ");
    }
    if (event === "direct-ready") {
        const hooks = Array.isArray(payload.hooks_installed) ? payload.hooks_installed.length : 0;
        const errors = Array.isArray(payload.hook_errors) ? payload.hook_errors.length : 0;
        return `direct-ready hooks=${hooks} errors=${errors}`;
    }
    if (event === "direct-module") return `module ${payload.module ?? "unknown"} ${payload.uuid ?? ""}`.trim();
    if (event === "direct-waiting-module") return `waiting ${payload.module ?? "UnityFramework"}`;
    if (event === "direct-profile-mismatch") return `profile mismatch ${payload.actual_uuid ?? "unknown"}`;
    if (event === "direct-error") return `error ${payload.error ?? "unknown"}`;
    if (event === "battle-finish-blocked") {
        return `battle upload blocked ${shortUrl(payload.url)}`.trim();
    }
    if (event === "battle-finish-block-error") {
        return `battle upload block error ${payload.error ?? "unknown"}`;
    }
    if (event === "battle-finish-block-unavailable") return "battle upload block unavailable";
    if (event === "extra-ready") {
        const hooks = Array.isArray(payload.hooks_installed) ? payload.hooks_installed.length : 0;
        return `extra ready hooks=${hooks}`;
    }
    if (event === "extra-capability") {
        const features = Array.isArray(payload.features) ? payload.features.join(",") : "none";
        return `extra ${payload.available ? "ready" : "unavailable"} ${features}`;
    }
    if (event === "extra-action") return `extra action ${payload.feature ?? "unknown"}`;
    if (event === "extra-bridge-unavailable") return "extra bridge unavailable";
    if (event === "extra-runtime-error") return `extra error ${payload.hook ?? "unknown"}`;
    if (event === "extra-unavailable") return `extra unavailable ${payload.error ?? "unknown"}`;
    if (event === "extra-disabled") return "extra disabled";
    if (event === "trainer-ready") {
        const commands = Array.isArray(payload.commands_supported) ? payload.commands_supported.length : 0;
        return `trainer ready commands=${commands}`;
    }
    if (event === "trainer-state") {
        return `trainer ${payload.command ?? "unknown"} ${payload.enabled ? "on" : "off"}`;
    }
    if (event === "trainer-step-requested") {
        return `trainer step ${payload.count ?? "?"} ${payload.unit ?? "frame"}(s) requested`;
    }
    if (event === "trainer-action-started" && payload.command === "tas_step") {
        return `trainer step started #${payload.start_tick ?? "?"}`;
    }
    if (event === "trainer-action-complete") {
        if (payload.command === "tas_step") {
            const advanced = payload.unit === "tick" ? payload.advanced_ticks : payload.advanced_frames;
            return `trainer step complete ${advanced ?? "?"} ${payload.unit ?? "frame"}(s) #${payload.end_tick ?? "?"}`;
        }
        return `trainer ${payload.command ?? "action"} complete #${payload.end_tick ?? "?"}`;
    }
    if (event === "trainer-command-error") {
        return `trainer command error ${payload.error ?? "unknown"}`;
    }
    if (event === "trainer-command-unavailable") {
        return `trainer unavailable ${payload.command ?? "unknown"}`;
    }
    if (event === "trainer-runtime-error" || event === "trainer-hook-error") {
        return `trainer error ${payload.command ?? payload.hook ?? "unknown"}`;
    }
    if (event === "trainer-disabled") return "trainer disabled";
    if (event === "capture-warning") return `capture warning ${payload.error ?? "unknown"}`;
    if (event === "overlay-action") {
        const action = payload.action ?? "unknown";
        if (action === "expand" || action === "collapse") return null;
        return `action ${action}`;
    }
    if (event.startsWith("direct-")) return event;
    return null;
}

export function createFloatingOverlay(options: FloatingOverlayOptions): FloatingOverlay | null {
    let panel: any | null = null;
    let bubbleButton: any | null = null;
    let titleLabel: any | null = null;
    let statusLabel: any | null = null;
    let collapseButton: any | null = null;
    let logView: any | null = null;
    let captureButton: any | null = null;
    let trainerButton: any | null = null;
    let logButton: any | null = null;
    let copyButton: any | null = null;
    let clearButton: any | null = null;
    let trainerScrollView: any | null = null;
    let trainerSummaryLabel: any | null = null;
    let trainerStepCountField: any | null = null;
    let trainerTickStepButton: any | null = null;
    let trainerFrameStepButton: any | null = null;
    let controller: any | null = null;
    let rootController: any | null = null;
    let hostWindow: any | null = null;
    let window: any | null = null;
    let expanded = true;
    let logConsoleVisible = options.logConsoleVisible;
    let trainerVisible = false;
    let destroyed = false;
    let renderPending = false;
    let visibilityTimer: ReturnType<typeof setInterval> | null = null;
    let expandedSize = [332, 294];
    let dragStart = [0, 0];
    let mountAttempts = 0;
    let mounted = false;
    let battleTimeline: { seconds: number; ticks: number; updatedAt: number } | null = null;
    const lines: string[] = [];
    const trainerCommandButtons = new Map<string, any>();
    let trainerButtonCommands: string[] = [];
    let renderedTrainerCommands = "";
    const reportedMountFailures = new Set<string>();

    const updateCaptureButton = (): void => {
        if (captureButton === null) return;
        const enabled = options.captureEnabled();
        captureButton.setTitle_forState_(enabled ? "抓包 开" : "抓包 关", UI_CONTROL_STATE_NORMAL);
        captureButton.setTitleColor_forState_(
            enabled ? rgba(0.25, 0.91, 0.74) : rgba(0.70, 0.74, 0.78),
            UI_CONTROL_STATE_NORMAL,
        );
    };

    const updateTrainerButton = (): void => {
        if (trainerButton === null) return;
        const commands = options.trainerCommands();
        const active = commands.filter(command => options.trainerEnabled(command)).length;
        trainerButton.setEnabled_(commands.length > 0);
        trainerButton.setTitle_forState_(
            commands.length === 0 ? "Trainer N/A" : trainerVisible ? "完成" : active > 0 ? `Trainer ${active}` : "Trainer",
            UI_CONTROL_STATE_NORMAL,
        );
        trainerButton.setTitleColor_forState_(
            trainerVisible || active > 0 ? rgba(0.25, 0.91, 0.74) : rgba(0.70, 0.74, 0.78),
            UI_CONTROL_STATE_NORMAL,
        );
    };

    const updateLogButton = (): void => {
        if (logButton === null) return;
        logButton.setTitle_forState_(trainerVisible ? "日志" : logConsoleVisible ? "日志 开" : "日志 关", UI_CONTROL_STATE_NORMAL);
        logButton.setTitleColor_forState_(
            logConsoleVisible && !trainerVisible ? rgba(0.25, 0.91, 0.74) : rgba(0.70, 0.74, 0.78),
            UI_CONTROL_STATE_NORMAL,
        );
        logButton.setAccessibilityLabel_(trainerVisible ? "Return to rolling log" : "Toggle rolling log visibility");
    };

    const updateBubbleButton = (): void => {
        if (bubbleButton === null) return;
        const timelineFresh = battleTimeline !== null && Date.now() - battleTimeline.updatedAt < 3000;
        const title = timelineFresh ? String(Math.max(0, Math.trunc(battleTimeline!.ticks))) : "OB";
        bubbleButton.setTitle_forState_(title, UI_CONTROL_STATE_NORMAL);
        bubbleButton.setAccessibilityLabel_(
            timelineFresh ? `Current battle tick ${title}; expand OpenBachelor controls` : "Expand OpenBachelor controls",
        );
    };

    const styleTrainerCommandButton = (command: string, commandButton: any): void => {
        const action = TRAINER_ACTIONS.has(command);
        const enabled = !action && options.trainerEnabled(command);
        const highRisk = command === "battle_speed_16x";
        const label = TRAINER_LABELS[command] ?? command;
        commandButton.setTitle_forState_(`${action ? "▶" : enabled ? "✓" : "○"} ${label}`, UI_CONTROL_STATE_NORMAL);
        commandButton.setBackgroundColor_(
            enabled
                ? highRisk ? rgba(0.95, 0.66, 0.22) : rgba(0.25, 0.91, 0.74)
                : action ? rgba(0.20, 0.43, 0.64, 0.82) : rgba(0.105, 0.13, 0.15, 0.98),
        );
        commandButton.setTitleColor_forState_(
            enabled ? rgba(0.035, 0.055, 0.065) : highRisk ? rgba(1.0, 0.71, 0.28) : rgba(0.86, 0.90, 0.93),
            UI_CONTROL_STATE_NORMAL,
        );
        commandButton.layer().setBorderColor_(
            (enabled
                ? highRisk ? rgba(1.0, 0.78, 0.38, 0.92) : rgba(0.38, 1.0, 0.86, 0.90)
                : highRisk ? rgba(0.95, 0.66, 0.22, 0.70) : rgba(1, 1, 1, 0.10)).CGColor(),
        );
        commandButton.setAccessibilityValue_(action ? "Action" : enabled ? "On" : "Off");
    };

    const updateTrainerStepControls = (): void => {
        const units = new Set(options.trainerStepUnits());
        for (const [unit, stepButton] of [
            ["tick", trainerTickStepButton],
            ["frame", trainerFrameStepButton],
        ] as const) {
            if (stepButton === null) continue;
            const available = units.has(unit);
            stepButton.setEnabled_(available);
            stepButton.setTitleColor_forState_(
                available ? rgba(0.86, 0.90, 0.93) : rgba(0.42, 0.46, 0.49),
                UI_CONTROL_STATE_NORMAL,
            );
            stepButton.setBackgroundColor_(
                available ? rgba(0.20, 0.43, 0.64, 0.82) : rgba(0.105, 0.13, 0.15, 0.62),
            );
            stepButton.setAccessibilityValue_(available ? "Available" : "Unavailable for this profile");
        }
    };

    const rebuildTrainerControls = (commands: string[]): void => {
        if (trainerScrollView === null || controller === null) return;
        const existing = trainerScrollView.subviews().objectEnumerator();
        while (true) {
            const view = existing.nextObject();
            if (isNullObject(view)) break;
            view.removeFromSuperview();
        }
        trainerCommandButtons.clear();
        trainerButtonCommands = [];
        trainerStepCountField = null;
        trainerTickStepButton = null;
        trainerFrameStepButton = null;

        const contentWidth = expandedSize[0] - 40;
        const columnGap = 8;
        const tileWidth = (contentWidth - columnGap) / 2;
        let y = 10;
        trainerSummaryLabel = ObjC.classes.UILabel.alloc().initWithFrame_(frame(8, y, contentWidth, 38));
        trainerSummaryLabel.setTextColor_(rgba(0.68, 0.74, 0.78));
        trainerSummaryLabel.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(10.5, 0.35));
        trainerSummaryLabel.setNumberOfLines_(2);
        trainerScrollView.addSubview_(trainerSummaryLabel);
        y += 44;

        const supported = new Set(commands);
        // Keep the step row discoverable whenever Trainer itself is
        // available.  The individual buttons are still fail-closed from the
        // runtime-reported step units, so an incomplete profile now shows a
        // disabled, diagnosable control instead of silently omitting the
        // entire Tick/frame feature.
        if (supported.has("tas_step") || commands.length > 0) {
            const section = ObjC.classes.UILabel.alloc().initWithFrame_(frame(8, y, contentWidth, 20));
            section.setText_("暂停步进");
            section.setTextColor_(rgba(0.25, 0.91, 0.74));
            section.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(10.5, 0.65));
            section.setAccessibilityTraits_(1 << 16);
            trainerScrollView.addSubview_(section);
            y += 24;

            const countWidth = 58;
            const stepGap = 7;
            const stepButtonWidth = (contentWidth - countWidth - stepGap * 2) / 2;
            trainerStepCountField = ObjC.classes.UITextField.alloc().initWithFrame_(
                frame(8, y, countWidth, 36),
            );
            trainerStepCountField.setText_("1");
            trainerStepCountField.setPlaceholder_("数量");
            trainerStepCountField.setKeyboardType_(4);
            trainerStepCountField.setTextAlignment_(1);
            trainerStepCountField.setTextColor_(rgba(0.91, 0.94, 0.96));
            trainerStepCountField.setBackgroundColor_(rgba(0.105, 0.13, 0.15, 0.98));
            trainerStepCountField.setFont_(ObjC.classes.UIFont.monospacedSystemFontOfSize_weight_(12, 0.55));
            trainerStepCountField.layer().setCornerRadius_(9);
            trainerStepCountField.layer().setBorderWidth_(1);
            trainerStepCountField.layer().setBorderColor_(rgba(1, 1, 1, 0.12).CGColor());
            trainerStepCountField.setAccessibilityLabel_("Step count from 1 to 10000");
            trainerStepCountField.addTarget_action_forControlEvents_(
                controller,
                ObjC.selector("beginStepCountEditing:"),
                UI_CONTROL_EVENT_TOUCH_DOWN | UI_CONTROL_EVENT_EDITING_DID_BEGIN,
            );
            trainerStepCountField.addTarget_action_forControlEvents_(
                controller,
                ObjC.selector("endStepCountEditing:"),
                UI_CONTROL_EVENT_EDITING_DID_END | UI_CONTROL_EVENT_EDITING_DID_END_ON_EXIT,
            );
            trainerScrollView.addSubview_(trainerStepCountField);

            trainerTickStepButton = button(
                "前进 Tick",
                8 + countWidth + stepGap,
                y,
                stepButtonWidth,
                36,
            );
            trainerFrameStepButton = button(
                "前进帧",
                8 + countWidth + stepGap * 2 + stepButtonWidth,
                y,
                stepButtonWidth,
                36,
            );
            trainerTickStepButton.setAccessibilityLabel_("Advance the specified number of battle ticks");
            trainerFrameStepButton.setAccessibilityLabel_("Advance the specified number of rendered frames");
            trainerTickStepButton.addTarget_action_forControlEvents_(
                controller,
                ObjC.selector("stepTicks:"),
                UI_CONTROL_EVENT_TOUCH_UP_INSIDE,
            );
            trainerFrameStepButton.addTarget_action_forControlEvents_(
                controller,
                ObjC.selector("stepFrames:"),
                UI_CONTROL_EVENT_TOUCH_UP_INSIDE,
            );
            trainerScrollView.addSubview_(trainerTickStepButton);
            trainerScrollView.addSubview_(trainerFrameStepButton);
            y += 44;

            const hint = ObjC.classes.UILabel.alloc().initWithFrame_(frame(8, y, contentWidth, 30));
            hint.setText_(options.trainerStepUnits().length > 0
                ? "输入 1–10000；Tick 按战斗定步，帧按 BattleController.Update 计数"
                : "当前 profile 的暂停步进不可用；请查看 Launcher 会话状态与事件日志");
            hint.setTextColor_(rgba(0.55, 0.61, 0.65));
            hint.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(9.5, 0.3));
            hint.setNumberOfLines_(2);
            trainerScrollView.addSubview_(hint);
            y += 36;
        }

        const groups = TRAINER_GROUPS.map(group => ({
            title: group.title,
            commands: group.commands.filter(command => (
                supported.has(command) && !TRAINER_CUSTOM_CONTROLS.has(command)
            )),
        })).filter(group => group.commands.length > 0);
        const remaining = commands.filter(command => (
            !TRAINER_CUSTOM_CONTROLS.has(command)
            && !TRAINER_GROUPS.some(group => group.commands.includes(command))
        ));
        if (remaining.length > 0) groups.push({ title: "其他", commands: remaining });

        for (const group of groups) {
            const section = ObjC.classes.UILabel.alloc().initWithFrame_(frame(8, y, contentWidth, 20));
            section.setText_(group.title.toUpperCase());
            section.setTextColor_(rgba(0.25, 0.91, 0.74));
            section.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(10.5, 0.65));
            section.setAccessibilityTraits_(1 << 16);
            trainerScrollView.addSubview_(section);
            y += 24;
            group.commands.forEach((command, index) => {
                const column = index % 2;
                const row = Math.floor(index / 2);
                const commandButton = button(
                    TRAINER_LABELS[command] ?? command,
                    8 + column * (tileWidth + columnGap),
                    y + row * 43,
                    tileWidth,
                    36,
                );
                const tag = trainerButtonCommands.push(command) - 1;
                commandButton.setTag_(tag);
                commandButton.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(11, 0.45));
                commandButton.titleLabel().setAdjustsFontSizeToFitWidth_(true);
                commandButton.titleLabel().setMinimumScaleFactor_(0.72);
                commandButton.layer().setCornerRadius_(9);
                commandButton.layer().setBorderWidth_(1);
                commandButton.setAccessibilityLabel_(TRAINER_LABELS[command] ?? command);
                commandButton.addTarget_action_forControlEvents_(
                    controller,
                    ObjC.selector("toggleTrainerCommand:"),
                    UI_CONTROL_EVENT_TOUCH_UP_INSIDE,
                );
                trainerScrollView.addSubview_(commandButton);
                trainerCommandButtons.set(command, commandButton);
            });
            y += Math.ceil(group.commands.length / 2) * 43 + 8;
        }
        renderedTrainerCommands = commands.join("\u0000");
        trainerScrollView.setContentSize_([expandedSize[0] - 24, y + 4]);
        updateTrainerStepControls();
    };

    const updateTrainerControls = (): void => {
        const commands = options.trainerCommands();
        if (trainerScrollView !== null && renderedTrainerCommands !== commands.join("\u0000")) {
            rebuildTrainerControls(commands);
        }
        let active = 0;
        let stateful = 0;
        for (const command of commands) {
            if (!TRAINER_ACTIONS.has(command)) {
                stateful += 1;
                if (options.trainerEnabled(command)) active += 1;
            }
            const commandButton = trainerCommandButtons.get(command);
            if (commandButton !== undefined) styleTrainerCommandButton(command, commandButton);
        }
        updateTrainerStepControls();
        if (trainerSummaryLabel !== null) {
            trainerSummaryLabel.setText_(`已启用 ${active} / ${stateful}  ·  步进会自动保持暂停\n可输入 Tick/帧数量；橙色项目需谨慎启用`);
        }
    };

    const updateStatusLabel = (): void => {
        if (statusLabel === null) return;
        const parts = [options.captureEnabled() ? "ONLINE  ·  CAPTURE ON" : "ONLINE  ·  CAPTURE OFF"];
        if (battleTimeline !== null && Date.now() - battleTimeline.updatedAt < 3000) {
            parts.push(`T ${battleTimeline.seconds.toFixed(3)}s  #${battleTimeline.ticks}`);
        }
        statusLabel.setText_(parts.join("  ·  "));
        updateBubbleButton();
    };

    const render = (): void => {
        renderPending = false;
        if (destroyed || logView === null) return;
        const text = lines.join("\n");
        logView.setText_(text);
        if (text.length !== 0) logView.scrollRangeToVisible_([text.length - 1, 1]);
        updateStatusLabel();
        updateCaptureButton();
        updateTrainerButton();
        updateLogButton();
        updateTrainerControls();
        if (rootController !== null && panel !== null) rootController.view().bringSubviewToFront_(panel);
        if (window !== null) window.setHidden_(false);
    };

    const scheduleRender = (): void => {
        // The init message may arrive while a spawned process is still
        // suspended and UIKit/Objective-C is not ready. Buffer events until
        // the overlay has mounted instead of scheduling on a null main queue.
        if (renderPending || destroyed || logView === null || !ObjC.available || ObjC.mainQueue === null) return;
        renderPending = true;
        setTimeout(() => {
            if (destroyed) return;
            ObjC.schedule(ObjC.mainQueue, () => {
                try {
                    render();
                } catch (error) {
                    destroyed = true;
                    options.reportAction("ui-error", { stage: "render", error: String(error) });
                }
            });
        }, 80);
    };

    const append = (message: string): void => {
        const stamp = new Date().toISOString().slice(11, 19);
        lines.push(`${stamp}  ${message}`);
        if (lines.length > MAX_LINES) lines.splice(0, lines.length - MAX_LINES);
        scheduleRender();
    };

    const applyLayout = (transitioning = false): void => {
        if (panel === null || bubbleButton === null || window === null || hostWindow === null) return;
        const current = window.frame();
        const originX = pointX(current[0] ?? current.origin);
        const originY = pointY(current[0] ?? current.origin);
        const bounds = hostWindow.bounds();
        if (expanded) {
            const expandedHeight = trainerVisible || logConsoleVisible ? expandedSize[1] : Math.min(112, expandedSize[1]);
            const maximumX = Math.max(6, sizeWidth(bounds) - expandedSize[0] - 6);
            const maximumY = Math.max(6, sizeHeight(bounds) - expandedHeight - 6);
            const candidateX = transitioning ? originX - expandedSize[0] + 52 : originX;
            const expandedX = Math.max(6, Math.min(maximumX, candidateX));
            const expandedY = Math.max(6, Math.min(maximumY, originY));
            window.setFrame_(frame(expandedX, expandedY, expandedSize[0], expandedHeight));
            panel.setFrame_(frame(0, 0, expandedSize[0], expandedHeight));
            bubbleButton.setHidden_(true);
            for (const view of [titleLabel, statusLabel, collapseButton, captureButton, trainerButton, logButton, copyButton, clearButton]) {
                if (view !== null) view.setHidden_(false);
            }
            logView?.setHidden_(!logConsoleVisible || trainerVisible);
            trainerScrollView?.setHidden_(!trainerVisible);
            const bodyHeight = Math.max(0, expandedHeight - 116);
            logView?.setFrame_(frame(12, 58, expandedSize[0] - 24, bodyHeight));
            trainerScrollView?.setFrame_(frame(12, 58, expandedSize[0] - 24, bodyHeight));
            const actionY = expandedHeight - 46;
            const actionWidth = (expandedSize[0] - 48) / 5;
            const actionViews = [captureButton, trainerButton, logButton, copyButton, clearButton];
            actionViews.forEach((action, index) => {
                action?.setFrame_(frame(12 + index * (actionWidth + 6), actionY, actionWidth, 34));
            });
        } else {
            const bubbleX = Math.max(6, Math.min(sizeWidth(bounds) - 58, originX + expandedSize[0] - 52));
            const bubbleY = Math.max(6, Math.min(sizeHeight(bounds) - 58, originY));
            window.setFrame_(frame(bubbleX, bubbleY, 52, 52));
            panel.setFrame_(frame(0, 0, 52, 52));
            for (const view of [titleLabel, statusLabel, collapseButton, logView, trainerScrollView, captureButton, trainerButton, logButton, copyButton, clearButton]) {
                if (view !== null) view.setHidden_(true);
            }
            bubbleButton.setHidden_(false);
        }
        updateLogButton();
        updateTrainerButton();
    };

    const togglePanel = (): void => {
        if (expanded && trainerStepCountField !== null) endStepCountEditing();
        expanded = !expanded;
        applyLayout(true);
    };

    const copyLogs = (): void => {
        ObjC.classes.UIPasteboard.generalPasteboard().setString_(lines.join("\n"));
        append("visible log copied");
        options.reportAction("copy", { lines: lines.length });
    };

    const clearVisibleLogs = (): void => {
        lines.splice(0, lines.length);
        append("view cleared; saved logs kept on disk");
        options.reportAction("clear-view");
    };

    const toggleCapture = (): void => {
        const enabled = !options.captureEnabled();
        options.setCaptureEnabled(enabled);
        append(enabled ? "capture enabled" : "capture disabled");
        updateCaptureButton();
    };

    const toggleLogConsole = (): void => {
        if (trainerVisible) {
            endStepCountEditing();
            trainerVisible = false;
            logConsoleVisible = true;
        } else {
            logConsoleVisible = !logConsoleVisible;
        }
        applyLayout();
    };

    const beginStepCountEditing = (): void => {
        if (window === null) return;
        window.makeKeyWindow();
    };

    const endStepCountEditing = (): void => {
        trainerStepCountField?.resignFirstResponder();
        if (hostWindow !== null && !hostWindow.isHidden()) hostWindow.makeKeyWindow();
    };

    const requestedStepCount = (): number | null => {
        if (trainerStepCountField === null) return null;
        const text = String(trainerStepCountField.text() ?? "").trim();
        if (!/^[0-9]+$/.test(text)) return null;
        const count = Number(text);
        if (!Number.isSafeInteger(count) || count < 1 || count > MAX_TAS_STEP_COUNT) return null;
        return count;
    };

    const requestTrainerStep = (unit: "tick" | "frame"): void => {
        const count = requestedStepCount();
        if (count === null) {
            append(`step count must be an integer from 1 to ${MAX_TAS_STEP_COUNT}`);
            options.reportAction("trainer-step-invalid", { unit, maximum: MAX_TAS_STEP_COUNT });
            return;
        }
        endStepCountEditing();
        const accepted = options.requestTrainerStep(unit, count);
        append(accepted
            ? `trainer advance ${count} ${unit}(s) requested`
            : `trainer advance ${unit} rejected`);
        options.reportAction("trainer-step", { unit, count, accepted });
        updateTrainerControls();
        updateTrainerButton();
    };

    const toggleTrainerCommand = (sender: any): void => {
        const tag = Number(sender.tag());
        const command = trainerButtonCommands[tag];
        if (command === undefined) return;
        const action = TRAINER_ACTIONS.has(command);
        const enabled = action || !options.trainerEnabled(command);
        options.setTrainerEnabled(command, enabled);
        append(action
            ? `trainer ${command} requested`
            : `trainer ${command} ${enabled ? "enabled" : "disabled"}`);
        options.reportAction("trainer", { command, enabled, action });
        updateTrainerControls();
        updateTrainerButton();
    };

    const showTrainer = (): void => {
        const commands = options.trainerCommands();
        if (commands.length === 0) {
            append("trainer unavailable for this profile");
            return;
        }
        if (trainerVisible) endStepCountEditing();
        trainerVisible = !trainerVisible;
        updateTrainerControls();
        applyLayout();
    };

    const movePanel = (gesture: any): void => {
        if (panel === null || window === null || hostWindow === null) return;
        const state = Number(gesture.state());
        if (state === GESTURE_STATE_BEGAN) {
            const center = window.center();
            dragStart = [pointX(center), pointY(center)];
            return;
        }
        if (state !== GESTURE_STATE_CHANGED) return;
        const translation = gesture.translationInView_(hostWindow);
        const bounds = hostWindow.bounds();
        const width = sizeWidth(bounds);
        const height = sizeHeight(bounds);
        const overlayFrame = window.frame();
        const panelWidth = sizeWidth(overlayFrame);
        const panelHeight = sizeHeight(overlayFrame);
        const halfWidth = panelWidth / 2;
        const halfHeight = panelHeight / 2;
        const x = Math.max(halfWidth + 6, Math.min(width - halfWidth - 6, dragStart[0] + pointX(translation)));
        const y = Math.max(halfHeight + 6, Math.min(height - halfHeight - 6, dragStart[1] + pointY(translation)));
        window.setCenter_([x, y]);
    };

    const mountUnsafe = (): void => {
        if (destroyed || mounted) return;
        if (ObjC.classes.UIApplication === undefined || ObjC.classes.UIWindow === undefined
            || ObjC.classes.UIViewController === undefined) {
            retryMount("ui-application-not-loaded");
            return;
        }
        hostWindow = activeWindow(window);
        if (hostWindow === null) {
            retryMount("no-active-window");
            return;
        }
        const bounds = hostWindow.bounds();
        const screenWidth = sizeWidth(bounds);
        const screenHeight = sizeHeight(bounds);
        expandedSize = [Math.min(332, Math.max(260, screenWidth - 24)), Math.min(294, Math.max(220, screenHeight - 24))];
        const originX = Math.max(12, screenWidth - expandedSize[0] - 12);
        const originY = Math.min(72, Math.max(12, screenHeight - expandedSize[1] - 12));

        const className = `OBFloatingOverlay_${Process.id}_${Date.now()}`;
        const Controller = ObjC.registerClass({
            name: className,
            methods: {
                "- togglePanel:": { types: "v@:@", implementation() { togglePanel(); } },
                "- toggleCapture:": { types: "v@:@", implementation() { toggleCapture(); } },
                "- toggleLogConsole:": { types: "v@:@", implementation() { toggleLogConsole(); } },
                "- showTrainer:": { types: "v@:@", implementation() { showTrainer(); } },
                "- toggleTrainerCommand:": { types: "v@:@", implementation(sender: any) { toggleTrainerCommand(sender); } },
                "- beginStepCountEditing:": { types: "v@:@", implementation() { beginStepCountEditing(); } },
                "- endStepCountEditing:": { types: "v@:@", implementation() { endStepCountEditing(); } },
                "- stepTicks:": { types: "v@:@", implementation() { requestTrainerStep("tick"); } },
                "- stepFrames:": { types: "v@:@", implementation() { requestTrainerStep("frame"); } },
                "- copyLogs:": { types: "v@:@", implementation() { copyLogs(); } },
                "- clearLogs:": { types: "v@:@", implementation() { clearVisibleLogs(); } },
                "- movePanel:": { types: "v@:@", implementation(gesture: any) { movePanel(gesture); } },
            },
        });
        controller = Controller.alloc().init();

        const scene = hostWindow.windowScene();
        if (!isNullObject(scene)) {
            window = ObjC.classes.UIWindow.alloc().initWithWindowScene_(scene);
        } else {
            window = ObjC.classes.UIWindow.alloc().initWithFrame_(frame(originX, originY, expandedSize[0], expandedSize[1]));
        }
        window.setFrame_(frame(originX, originY, expandedSize[0], expandedSize[1]));
        window.setWindowLevel_(Math.max(OVERLAY_WINDOW_LEVEL, Number(hostWindow.windowLevel()) + 1));
        window.setBackgroundColor_(ObjC.classes.UIColor.clearColor());
        rootController = ObjC.classes.UIViewController.alloc().init();
        rootController.view().setBackgroundColor_(ObjC.classes.UIColor.clearColor());
        window.setRootViewController_(rootController);

        panel = ObjC.classes.UIView.alloc().initWithFrame_(frame(0, 0, expandedSize[0], expandedSize[1]));
        panel.setBackgroundColor_(rgba(0.055, 0.067, 0.078, 0.97));
        panel.layer().setCornerRadius_(14);
        panel.layer().setBorderWidth_(1);
        panel.layer().setBorderColor_(rgba(0.25, 0.91, 0.74, 0.52).CGColor());
        panel.layer().setShadowOpacity_(0.35);
        panel.layer().setShadowRadius_(10);
        panel.layer().setShadowOffset_([0, 4]);
        panel.setAccessibilityLabel_("OpenBachelor floating console");

        titleLabel = ObjC.classes.UILabel.alloc().initWithFrame_(frame(14, 9, expandedSize[0] - 64, 22));
        titleLabel.setText_("OPENBACHELOR  /  LIVE CONTROL");
        titleLabel.setTextColor_(rgba(0.94, 0.96, 0.98));
        titleLabel.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(12.5, 0.65));
        titleLabel.setUserInteractionEnabled_(true);
        panel.addSubview_(titleLabel);

        statusLabel = ObjC.classes.UILabel.alloc().initWithFrame_(frame(14, 33, expandedSize[0] - 64, 18));
        statusLabel.setTextColor_(rgba(0.25, 0.91, 0.74));
        statusLabel.setFont_(ObjC.classes.UIFont.monospacedSystemFontOfSize_weight_(10, 0.4));
        panel.addSubview_(statusLabel);

        collapseButton = button("−", expandedSize[0] - 46, 8, 36, 36);
        collapseButton.setAccessibilityLabel_("Collapse OpenBachelor console");
        collapseButton.addTarget_action_forControlEvents_(controller, ObjC.selector("togglePanel:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        panel.addSubview_(collapseButton);

        logView = ObjC.classes.UITextView.alloc().initWithFrame_(frame(12, 58, expandedSize[0] - 24, expandedSize[1] - 116));
        logView.setEditable_(false);
        logView.setSelectable_(true);
        logView.setTextColor_(rgba(0.83, 0.87, 0.90));
        logView.setBackgroundColor_(rgba(0.025, 0.030, 0.035, 0.90));
        logView.setFont_(ObjC.classes.UIFont.monospacedSystemFontOfSize_weight_(10.5, 0));
        logView.setTextContainerInset_([8, 8, 8, 8]);
        logView.layer().setCornerRadius_(6);
        panel.addSubview_(logView);

        trainerScrollView = ObjC.classes.UIScrollView.alloc().initWithFrame_(frame(12, 58, expandedSize[0] - 24, expandedSize[1] - 116));
        trainerScrollView.setBackgroundColor_(rgba(0.025, 0.030, 0.035, 0.90));
        trainerScrollView.setAlwaysBounceVertical_(true);
        trainerScrollView.setShowsHorizontalScrollIndicator_(false);
        trainerScrollView.layer().setCornerRadius_(8);
        trainerScrollView.setHidden_(true);
        trainerScrollView.setAccessibilityLabel_("Trainer command grid");
        panel.addSubview_(trainerScrollView);

        const actionY = expandedSize[1] - 46;
        const actionWidth = (expandedSize[0] - 48) / 5;
        captureButton = button("抓包 开", 12, actionY, actionWidth, 34);
        trainerButton = button("Trainer", 18 + actionWidth, actionY, actionWidth, 34);
        logButton = button("日志 开", 24 + actionWidth * 2, actionY, actionWidth, 34);
        copyButton = button("复制", 30 + actionWidth * 3, actionY, actionWidth, 34);
        clearButton = button("清空", 36 + actionWidth * 4, actionY, actionWidth, 34);
        captureButton.setAccessibilityLabel_("Toggle capture");
        trainerButton.setAccessibilityLabel_("Open Trainer controls");
        logButton.setAccessibilityLabel_("Toggle rolling log visibility");
        copyButton.setAccessibilityLabel_("Copy visible log");
        clearButton.setAccessibilityLabel_("Clear visible log");
        for (const action of [captureButton, trainerButton, logButton, copyButton, clearButton]) {
            panel.addSubview_(action);
        }
        captureButton.addTarget_action_forControlEvents_(controller, ObjC.selector("toggleCapture:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        trainerButton.addTarget_action_forControlEvents_(controller, ObjC.selector("showTrainer:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        logButton.addTarget_action_forControlEvents_(controller, ObjC.selector("toggleLogConsole:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        copyButton.addTarget_action_forControlEvents_(controller, ObjC.selector("copyLogs:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        clearButton.addTarget_action_forControlEvents_(controller, ObjC.selector("clearLogs:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);

        bubbleButton = button("OB", 0, 0, 52, 52);
        bubbleButton.setHidden_(true);
        bubbleButton.setAccessibilityLabel_("Expand OpenBachelor console");
        bubbleButton.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(15, 0.7));
        bubbleButton.titleLabel().setAdjustsFontSizeToFitWidth_(true);
        bubbleButton.titleLabel().setMinimumScaleFactor_(0.58);
        bubbleButton.setTitleColor_forState_(rgba(0.25, 0.91, 0.74), UI_CONTROL_STATE_NORMAL);
        bubbleButton.addTarget_action_forControlEvents_(controller, ObjC.selector("togglePanel:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        panel.addSubview_(bubbleButton);

        const headerPan = ObjC.classes.UIPanGestureRecognizer.alloc().initWithTarget_action_(controller, ObjC.selector("movePanel:"));
        const bubblePan = ObjC.classes.UIPanGestureRecognizer.alloc().initWithTarget_action_(controller, ObjC.selector("movePanel:"));
        headerPan.setCancelsTouchesInView_(false);
        bubblePan.setCancelsTouchesInView_(false);
        titleLabel.addGestureRecognizer_(headerPan);
        bubbleButton.addGestureRecognizer_(bubblePan);

        rootController.view().addSubview_(panel);
        rootController.view().bringSubviewToFront_(panel);
        // A dedicated scene window prevents Unity from covering or replacing
        // the overlay. Keep it non-key during normal control; the numeric step
        // field temporarily makes it key and restores the game window when
        // editing ends.
        window.setHidden_(false);
        mounted = true;
        applyLayout();
        visibilityTimer = setInterval(() => {
            if (destroyed || panel === null || window === null || !ObjC.available || ObjC.mainQueue === null) return;
            ObjC.schedule(ObjC.mainQueue, () => {
                try {
                    const currentHostWindow = activeWindow(window);
                    if (currentHostWindow === null || panel === null || window === null) return;
                    hostWindow = currentHostWindow;
                    const currentScene = currentHostWindow.windowScene();
                    if (!isNullObject(currentScene)) {
                        const overlayScene = window.windowScene();
                        if (isNullObject(overlayScene) || !overlayScene.equals(currentScene)) {
                            window.setWindowScene_(currentScene);
                        }
                    }
                    window.setWindowLevel_(Math.max(OVERLAY_WINDOW_LEVEL, Number(currentHostWindow.windowLevel()) + 1));
                    window.setHidden_(false);
                    updateStatusLabel();
                    rootController?.view().bringSubviewToFront_(panel);
                } catch (error) {
                    options.reportAction("ui-error", { stage: "visibility", error: String(error) });
                }
            });
        }, 2000);
        updateCaptureButton();
        updateTrainerButton();
        updateLogButton();
        updateTrainerControls();
        append("floating console attached");
        options.reportAction("ready", {
            window_level: Number(window.windowLevel()),
            scene: !isNullObject(window.windowScene()),
        });
    };

    function retryMount(reason: string, error?: unknown): void {
        if (destroyed || mounted) return;
        mountAttempts += 1;
        if (!reportedMountFailures.has(reason)) {
            reportedMountFailures.add(reason);
            options.reportAction("waiting", {
                reason,
                ...(error === undefined ? {} : { error: String(error) }),
            });
        }
        if (mountAttempts >= MAX_MOUNT_ATTEMPTS) {
            destroyed = true;
            options.reportAction("unavailable", {
                reason,
                attempts: mountAttempts,
                ...(error === undefined ? {} : { error: String(error) }),
            });
            return;
        }
        setTimeout(scheduleMount, 250);
    }

    const mount = (): void => {
        try {
            mountUnsafe();
        } catch (error) {
            options.reportAction("ui-error", { stage: "mount", error: String(error) });
            if (window !== null) {
                try { window.setHidden_(true); } catch (_) { /* best effort */ }
            }
            panel = null;
            rootController = null;
            hostWindow = null;
            window = null;
            retryMount("mount-error", error);
        }
    };

    function scheduleMount(): void {
        if (destroyed || mounted) return;
        if (!ObjC.available || ObjC.mainQueue === null) {
            retryMount("objc-runtime-not-loaded");
            return;
        }
        ObjC.schedule(ObjC.mainQueue, mount);
    }

    scheduleMount();

    return {
        record(payload: Record<string, any>): void {
            if (payload.event === "battle-timeline") {
                const seconds = Number(payload.seconds);
                const ticks = Number(payload.ticks);
                if (Number.isFinite(seconds) && Number.isFinite(ticks)) {
                    battleTimeline = { seconds, ticks, updatedAt: Date.now() };
                    scheduleRender();
                }
                return;
            }
            const description = describeEvent(payload);
            if (description !== null) append(description);
        },
        destroy(): void {
            if (destroyed) return;
            destroyed = true;
            if (visibilityTimer !== null) clearInterval(visibilityTimer);
            visibilityTimer = null;
            const mountedPanel = panel;
            const mountedWindow = window;
            const mountedHostWindow = hostWindow;
            if (ObjC.available && ObjC.mainQueue !== null && (mountedPanel !== null || mountedWindow !== null)) {
                ObjC.schedule(ObjC.mainQueue, () => {
                    trainerStepCountField?.resignFirstResponder();
                    mountedPanel?.removeFromSuperview();
                    mountedWindow?.setHidden_(true);
                    if (mountedHostWindow !== null && !mountedHostWindow.isHidden()) {
                        mountedHostWindow.makeKeyWindow();
                    }
                });
            }
            panel = null;
            trainerCommandButtons.clear();
            trainerButtonCommands = [];
            controller = null;
            rootController = null;
            hostWindow = null;
            window = null;
        },
    };
}
