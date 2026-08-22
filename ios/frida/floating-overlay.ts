import ObjC from "frida-objc-bridge";

export interface FloatingOverlayOptions {
    captureEnabled: () => boolean;
    setCaptureEnabled: (enabled: boolean) => void;
    reportAction: (action: string, details?: Record<string, unknown>) => void;
}

export interface FloatingOverlay {
    record(payload: Record<string, any>): void;
    destroy(): void;
}

const UI_CONTROL_STATE_NORMAL = 0;
const UI_CONTROL_EVENT_TOUCH_UP_INSIDE = 1 << 6;
const GESTURE_STATE_BEGAN = 1;
const GESTURE_STATE_CHANGED = 2;
const MAX_LINES = 160;

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

function activeWindow(): any | null {
    const application = ObjC.classes.UIApplication.sharedApplication();
    const windows = application.windows();
    const count = Number(windows.count());
    let fallback: any | null = null;
    for (let index = 0; index < count; index += 1) {
        const candidate = windows.objectAtIndex_(index);
        if (candidate.isHidden()) continue;
        fallback = candidate;
        if (candidate.isKeyWindow()) return candidate;
    }
    return fallback;
}

function button(title: string, x: number, y: number, width: number, height: number): any {
    const value = ObjC.classes.UIButton.buttonWithType_(0);
    value.setFrame_(frame(x, y, width, height));
    value.setTitle_forState_(title, UI_CONTROL_STATE_NORMAL);
    value.setTitleColor_forState_(rgba(0.91, 0.94, 0.96), UI_CONTROL_STATE_NORMAL);
    value.setBackgroundColor_(rgba(0.14, 0.17, 0.20, 0.96));
    value.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(12, 0.25));
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
    if (event === "capture-warning") return `capture warning ${payload.error ?? "unknown"}`;
    if (event === "overlay-action") return `action ${payload.action ?? "unknown"}`;
    if (event.startsWith("direct-")) return event;
    return null;
}

export function createFloatingOverlay(options: FloatingOverlayOptions): FloatingOverlay | null {
    if (!ObjC.available) return null;

    let panel: any | null = null;
    let bubbleButton: any | null = null;
    let titleLabel: any | null = null;
    let statusLabel: any | null = null;
    let collapseButton: any | null = null;
    let logView: any | null = null;
    let captureButton: any | null = null;
    let copyButton: any | null = null;
    let clearButton: any | null = null;
    let controller: any | null = null;
    let window: any | null = null;
    let expanded = true;
    let destroyed = false;
    let renderPending = false;
    let visibilityTimer: ReturnType<typeof setInterval> | null = null;
    let expandedSize = [332, 294];
    let dragStart = [0, 0];
    let mountAttempts = 0;
    const lines: string[] = [];

    const updateCaptureButton = (): void => {
        if (captureButton === null) return;
        const enabled = options.captureEnabled();
        captureButton.setTitle_forState_(enabled ? "抓包 开" : "抓包 关", UI_CONTROL_STATE_NORMAL);
        captureButton.setTitleColor_forState_(
            enabled ? rgba(0.25, 0.91, 0.74) : rgba(0.70, 0.74, 0.78),
            UI_CONTROL_STATE_NORMAL,
        );
    };

    const render = (): void => {
        renderPending = false;
        if (destroyed || logView === null) return;
        const text = lines.join("\n");
        logView.setText_(text);
        if (text.length !== 0) logView.scrollRangeToVisible_([text.length - 1, 1]);
        if (statusLabel !== null) {
            statusLabel.setText_(options.captureEnabled() ? "ONLINE  ·  CAPTURE ON" : "ONLINE  ·  CAPTURE OFF");
        }
        updateCaptureButton();
        if (window !== null && panel !== null) window.bringSubviewToFront_(panel);
    };

    const scheduleRender = (): void => {
        if (renderPending || destroyed) return;
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

    const applyLayout = (): void => {
        if (panel === null || bubbleButton === null) return;
        const current = panel.frame();
        const originX = pointX(current[0] ?? current.origin);
        const originY = pointY(current[0] ?? current.origin);
        if (expanded) {
            const bounds = window?.bounds();
            const maximumX = Math.max(6, sizeWidth(bounds) - expandedSize[0] - 6);
            const maximumY = Math.max(6, sizeHeight(bounds) - expandedSize[1] - 6);
            const expandedX = Math.max(6, Math.min(maximumX, originX - expandedSize[0] + 52));
            const expandedY = Math.max(6, Math.min(maximumY, originY));
            panel.setFrame_(frame(expandedX, expandedY, expandedSize[0], expandedSize[1]));
            bubbleButton.setHidden_(true);
            for (const view of [titleLabel, statusLabel, collapseButton, logView, captureButton, copyButton, clearButton]) {
                if (view !== null) view.setHidden_(false);
            }
        } else {
            panel.setFrame_(frame(originX + expandedSize[0] - 52, originY, 52, 52));
            for (const view of [titleLabel, statusLabel, collapseButton, logView, captureButton, copyButton, clearButton]) {
                if (view !== null) view.setHidden_(true);
            }
            bubbleButton.setHidden_(false);
        }
    };

    const togglePanel = (): void => {
        expanded = !expanded;
        applyLayout();
        options.reportAction(expanded ? "expand" : "collapse");
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

    const movePanel = (gesture: any): void => {
        if (panel === null || window === null) return;
        const state = Number(gesture.state());
        if (state === GESTURE_STATE_BEGAN) {
            const center = panel.center();
            dragStart = [pointX(center), pointY(center)];
            return;
        }
        if (state !== GESTURE_STATE_CHANGED) return;
        const translation = gesture.translationInView_(window);
        const bounds = window.bounds();
        const width = sizeWidth(bounds);
        const height = sizeHeight(bounds);
        const panelFrame = panel.frame();
        const panelWidth = sizeWidth(panelFrame);
        const panelHeight = sizeHeight(panelFrame);
        const halfWidth = panelWidth / 2;
        const halfHeight = panelHeight / 2;
        const x = Math.max(halfWidth + 6, Math.min(width - halfWidth - 6, dragStart[0] + pointX(translation)));
        const y = Math.max(halfHeight + 6, Math.min(height - halfHeight - 6, dragStart[1] + pointY(translation)));
        panel.setCenter_([x, y]);
    };

    const mountUnsafe = (): void => {
        if (destroyed) return;
        if (ObjC.classes.UIApplication === undefined) {
            mountAttempts += 1;
            if (mountAttempts < 240) setTimeout(() => ObjC.schedule(ObjC.mainQueue, mount), 250);
            else options.reportAction("unavailable", { reason: "ui-application-not-loaded" });
            return;
        }
        window = activeWindow();
        if (window === null) {
            mountAttempts += 1;
            if (mountAttempts < 240) setTimeout(() => ObjC.schedule(ObjC.mainQueue, mount), 250);
            else options.reportAction("unavailable", { reason: "no-active-window" });
            return;
        }
        const bounds = window.bounds();
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
                "- copyLogs:": { types: "v@:@", implementation() { copyLogs(); } },
                "- clearLogs:": { types: "v@:@", implementation() { clearVisibleLogs(); } },
                "- movePanel:": { types: "v@:@", implementation(gesture: any) { movePanel(gesture); } },
            },
        });
        controller = Controller.alloc().init();

        panel = ObjC.classes.UIView.alloc().initWithFrame_(frame(originX, originY, expandedSize[0], expandedSize[1]));
        panel.setBackgroundColor_(rgba(0.055, 0.067, 0.078, 0.97));
        panel.layer().setCornerRadius_(8);
        panel.layer().setBorderWidth_(1);
        panel.layer().setBorderColor_(rgba(0.25, 0.91, 0.74, 0.52).CGColor());
        panel.layer().setShadowOpacity_(0.35);
        panel.layer().setShadowRadius_(10);
        panel.layer().setShadowOffset_([0, 4]);
        panel.setAccessibilityLabel_("OpenBachelor floating console");

        titleLabel = ObjC.classes.UILabel.alloc().initWithFrame_(frame(14, 10, expandedSize[0] - 64, 22));
        titleLabel.setText_("OpenBachelor Console");
        titleLabel.setTextColor_(rgba(0.94, 0.96, 0.98));
        titleLabel.setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(15, 0.6));
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

        const actionY = expandedSize[1] - 46;
        const actionWidth = (expandedSize[0] - 36) / 3;
        captureButton = button("抓包 开", 12, actionY, actionWidth, 34);
        copyButton = button("复制", 18 + actionWidth, actionY, actionWidth, 34);
        clearButton = button("清空", 24 + actionWidth * 2, actionY, actionWidth, 34);
        captureButton.setAccessibilityLabel_("Toggle capture");
        copyButton.setAccessibilityLabel_("Copy visible log");
        clearButton.setAccessibilityLabel_("Clear visible log");
        for (const action of [captureButton, copyButton, clearButton]) {
            panel.addSubview_(action);
        }
        captureButton.addTarget_action_forControlEvents_(controller, ObjC.selector("toggleCapture:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        copyButton.addTarget_action_forControlEvents_(controller, ObjC.selector("copyLogs:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        clearButton.addTarget_action_forControlEvents_(controller, ObjC.selector("clearLogs:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);

        bubbleButton = button("OB", 0, 0, 52, 52);
        bubbleButton.setHidden_(true);
        bubbleButton.setAccessibilityLabel_("Expand OpenBachelor console");
        bubbleButton.titleLabel().setFont_(ObjC.classes.UIFont.systemFontOfSize_weight_(15, 0.7));
        bubbleButton.setTitleColor_forState_(rgba(0.25, 0.91, 0.74), UI_CONTROL_STATE_NORMAL);
        bubbleButton.addTarget_action_forControlEvents_(controller, ObjC.selector("togglePanel:"), UI_CONTROL_EVENT_TOUCH_UP_INSIDE);
        panel.addSubview_(bubbleButton);

        const headerPan = ObjC.classes.UIPanGestureRecognizer.alloc().initWithTarget_action_(controller, ObjC.selector("movePanel:"));
        const bubblePan = ObjC.classes.UIPanGestureRecognizer.alloc().initWithTarget_action_(controller, ObjC.selector("movePanel:"));
        headerPan.setCancelsTouchesInView_(false);
        bubblePan.setCancelsTouchesInView_(false);
        titleLabel.addGestureRecognizer_(headerPan);
        bubbleButton.addGestureRecognizer_(bubblePan);

        window.addSubview_(panel);
        window.bringSubviewToFront_(panel);
        visibilityTimer = setInterval(() => {
            if (destroyed || panel === null) return;
            ObjC.schedule(ObjC.mainQueue, () => {
                const currentWindow = activeWindow();
                if (currentWindow === null || panel === null) return;
                if (window === null || !currentWindow.equals(window)) {
                    panel.removeFromSuperview();
                    window = currentWindow;
                    window.addSubview_(panel);
                }
                window.bringSubviewToFront_(panel);
            });
        }, 2000);
        updateCaptureButton();
        append("floating console attached");
        options.reportAction("ready");
    };
    const mount = (): void => {
        try {
            mountUnsafe();
        } catch (error) {
            destroyed = true;
            options.reportAction("ui-error", { stage: "mount", error: String(error) });
        }
    };
    ObjC.schedule(ObjC.mainQueue, mount);

    return {
        record(payload: Record<string, any>): void {
            const description = describeEvent(payload);
            if (description !== null) append(description);
        },
        destroy(): void {
            if (destroyed) return;
            destroyed = true;
            if (visibilityTimer !== null) clearInterval(visibilityTimer);
            visibilityTimer = null;
            if (panel !== null) {
                ObjC.schedule(ObjC.mainQueue, () => panel?.removeFromSuperview());
            }
            panel = null;
            controller = null;
            window = null;
        },
    };
}
