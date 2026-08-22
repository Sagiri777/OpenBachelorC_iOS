// Shared iOS extra hooks. The legacy extra agent and the direct profile
// agent both use this installer. Direct mode may not have a usable IL2CPP
// export table; callers must treat a failed Il2Cpp.perform() as a capability
// miss rather than as a fatal agent error.

import "frida-il2cpp-bridge";
import { ScriptConfig, safe } from "./util";

declare const Il2Cpp: any;

export interface ExtraEmitter {
    (payload: Record<string, any>): void;
}

export interface ExtraInstallResult {
    supported: boolean;
    hooksInstalled: string[];
    hookErrors: string[];
}

export interface ExtraInstallOptions {
    pauseDeploy?: boolean;
    speed?: boolean;
    vision?: boolean;
}

function vector2(x: number, y: number) {
    const Vector2 = Il2Cpp.domain
        .assembly("UnityEngine.CoreModule")
        .image.class("UnityEngine.Vector2");
    const value = Vector2.alloc().unbox();
    value.field("x").value = x;
    value.field("y").value = y;
    return value;
}

function invScale(value: number) {
    return value > 0.01 ? 1 / value : 1;
}

export async function installExtraHooks(
    conf: ScriptConfig,
    emit: ExtraEmitter,
    options: ExtraInstallOptions = {},
): Promise<ExtraInstallResult> {
    const hooksInstalled: string[] = [];
    const hookErrors: string[] = [];
    let supported = false;

    try {
        await Il2Cpp.perform(() => {
            supported = true;
            const hook = (name: string, installer: () => void) => {
                if (safe(name, installer)) hooksInstalled.push(name);
                else hookErrors.push(name);
            };

            if (options.pauseDeploy !== false) {
                hook("UISwitchToggle.SetInteractable", () => {
                    const method = Il2Cpp.domain
                        .assembly("Assembly-CSharp")
                        .image.class("Torappu.UI.UISwitchToggle")
                        .method("SetInteractable")
                        .overload("System.Boolean", "System.Boolean");
                    method.implementation = function (interactable: boolean, animated: boolean) {
                        if (conf.bool("pause_deploy")) interactable = true;
                        return this.method("SetInteractable").invoke(interactable, animated);
                    };
                });

                hook("UIController.OnBottomMaskClicked", () => {
                    const method = Il2Cpp.domain
                        .assembly("Assembly-CSharp")
                        .image.class("Torappu.Battle.UI.UIController")
                        .method("OnBottomMaskClicked")
                        .overload("System.Object");
                    method.implementation = function (argument: any) {
                        const wasPaused = conf.bool("pause_deploy")
                            && this.method("get_isPaused").invoke() === true;
                        if (wasPaused) this.method("SetPaused").invoke(false, false, false);
                        try {
                            this.method("OnBottomMaskClicked").invoke(argument);
                        } finally {
                            if (wasPaused) this.method("SetPaused").invoke(true, false, false);
                        }
                    };
                });

                hook("UIController.OnCardBeginDrag", () => {
                    const method = Il2Cpp.domain
                        .assembly("Assembly-CSharp")
                        .image.class("Torappu.Battle.UI.UIController")
                        .method("OnCardBeginDrag")
                        .overload("Torappu.Battle.UI.UICard");
                    method.implementation = function (card: any) {
                        const wasPaused = conf.bool("pause_deploy")
                            && this.method("get_isPaused").invoke() === true;
                        if (wasPaused) this.method("SetPaused").invoke(false, false, false);
                        try {
                            this.method("OnCardBeginDrag").invoke(card);
                        } finally {
                            if (wasPaused) this.method("SetPaused").invoke(true, false, false);
                        }
                    };
                });
            }

            if (options.speed !== false) {
                hook("UITopBar.OnSpeedSwitcherClicked", () => {
                    const method = Il2Cpp.domain
                        .assembly("Assembly-CSharp")
                        .image.class("Torappu.Battle.UI.UITopBar")
                        .method("OnSpeedSwitcherClicked")
                        .overload();
                    method.implementation = function () {
                        if (!conf.bool("3x_speed")) {
                            return this.method("OnSpeedSwitcherClicked").invoke();
                        }
                        const level = this.method("get_speedLevel").invoke();
                        let raw = level.field("value__").value + 1;
                        if (raw > 3) raw = 1;
                        level.field("value__").value = raw;
                        this.method("set_speedLevel").invoke(level);
                    };
                });
            }

            if (options.vision !== false) hook("vision overlay", () => {
                const TextModeSlash = Il2Cpp.domain
                    .assembly("Assembly-CSharp")
                    .image.class("Torappu.UI.UITextSlider")
                    .nested("TextMode")
                    .field("A_SLASH_B").value;
                const TextAnchorMiddleCenter = Il2Cpp.domain
                    .assembly("UnityEngine.TextRenderingModule")
                    .image.class("UnityEngine.TextAnchor")
                    .field("MiddleCenter").value;
                const GameObject = Il2Cpp.domain
                    .assembly("UnityEngine.CoreModule")
                    .image.class("UnityEngine.GameObject");
                const Text = Il2Cpp.domain
                    .assembly("UnityEngine.UI")
                    .image.class("UnityEngine.UI.Text");
                const RectTransform = Il2Cpp.domain
                    .assembly("UnityEngine.CoreModule")
                    .image.class("UnityEngine.RectTransform");
                const Vector3 = Il2Cpp.domain
                    .assembly("UnityEngine.CoreModule")
                    .image.class("UnityEngine.Vector3");
                const Character = Il2Cpp.domain
                    .assembly("Assembly-CSharp")
                    .image.class("Torappu.Battle.Character");
                const overlayName = "obc-vision";

                function findFont() {
                    const Resources = Il2Cpp.domain
                        .assembly("UnityEngine.CoreModule")
                        .image.class("UnityEngine.Resources");
                    const Font = Il2Cpp.domain
                        .assembly("UnityEngine.TextRenderingModule")
                        .image.class("UnityEngine.Font");
                    const fonts = Resources
                        .method("FindObjectsOfTypeAll")
                        .overload("System.Type")
                        .invoke(Font.type.object);
                    for (let index = 0; index < fonts.length; index++) {
                        const font = fonts.get(index);
                        if (font.method("get_name").invoke().content === "Novecentowide-Normal") {
                            return font;
                        }
                    }
                    return null;
                }

                function attachOverlay(slider: any, unit: any, giant = false) {
                    if (slider.isNull()) return;
                    const font = findFont();
                    if (font === null) return;

                    let gameObject: any = null;
                    const currentText = slider.field("_text").value;
                    if (!currentText.isNull()) {
                        const current = currentText.method("get_gameObject").invoke();
                        if (current.method("get_name").invoke().content === overlayName) {
                            gameObject = current;
                        }
                    }

                    if (gameObject === null) {
                        gameObject = GameObject.alloc();
                        gameObject.method(".ctor").invoke(Il2Cpp.string(overlayName));
                        const text = gameObject.method("AddComponent").invoke(Text.type.object);
                        text.method("set_alignment").invoke(TextAnchorMiddleCenter);
                        text.method("set_font").invoke(font);
                        const baseSize = conf.number("vision_font_size", 22);
                        text.method("set_fontSize").invoke(giant ? baseSize * 2 : baseSize);
                        slider.field("_text").value = text;
                        slider.field("_textMode").value = TextModeSlash;

                        const parent = slider.method("get_transform").invoke();
                        parent.method("SetAsLastSibling").invoke();
                        const transform = gameObject.method("get_transform").invoke();
                        transform.method("SetParent").invoke(parent);
                        const rect = gameObject
                            .method("GetComponent")
                            .overload("System.Type")
                            .invoke(RectTransform.type.object);

                        if (giant) {
                            const scale = unit.method("get_bossHudScale").invoke();
                            scale.field("x").value = invScale(scale.field("x").value);
                            scale.field("y").value = invScale(scale.field("y").value);
                            scale.field("z").value = invScale(scale.field("z").value);
                            rect.method("set_localScale").invoke(scale);
                        } else {
                            rect.method("set_localScale").invoke(Vector3.method("get_one").invoke());
                        }

                        rect.method("set_anchoredPosition3D").invoke(
                            Vector3.method("get_zero").invoke(),
                        );
                        const center = vector2(0.5, 0.5);
                        rect.method("set_anchorMax").invoke(center);
                        rect.method("set_anchorMin").invoke(center);
                        rect.method("set_pivot").invoke(center);
                        rect.method("set_sizeDelta").invoke(vector2(10000, 10000));
                    }

                    const hidden = unit.isNull() || unit.class.isSubclassOf(Character, false);
                    gameObject.method("SetActive").invoke(!hidden);
                }

                const unitHud = Il2Cpp.domain
                    .assembly("Assembly-CSharp")
                    .image.class("Torappu.Battle.UI.UIUnitHUD")
                    .method("Attach")
                    .overload("Torappu.Battle.Unit");
                unitHud.implementation = function (unit: any) {
                    this.method("Attach").invoke(unit);
                    if (conf.bool("vision")) attachOverlay(this.field("_hpSlider").value, unit);
                };

                const enemySlider = Il2Cpp.domain
                    .assembly("Assembly-CSharp")
                    .image.class("Torappu.Battle.UI.UIHudEnemyHpSlider")
                    .method("OnAttach")
                    .overload("Torappu.Battle.Unit");
                enemySlider.implementation = function (unit: any) {
                    this.method("OnAttach").invoke(unit);
                    if (conf.bool("vision")) attachOverlay(this, unit);
                };

                const bossPanel = Il2Cpp.domain
                    .assembly("Assembly-CSharp")
                    .image.class("Torappu.Battle.UI.UIEnemyGiantBossInfoPanel")
                    .method("Attach")
                    .overload("Torappu.Battle.IUseGiantBossInfoPanel");
                bossPanel.implementation = function (boss: any) {
                    this.method("Attach").invoke(boss);
                    if (conf.bool("vision")) {
                        attachOverlay(this.field("_hpSlider").value, boss, true);
                    }
                };
            });

            supported = hooksInstalled.length > 0;
            emit({
                event: "extra-ready",
                platform: Process.platform,
                hooks_installed: hooksInstalled,
                hook_errors: hookErrors,
                supported,
            });
        });
    } catch (error) {
        supported = false;
        hookErrors.push(String(error));
        emit({
            event: "extra-unavailable",
            platform: Process.platform,
            hooks_installed: hooksInstalled,
            hook_errors: hookErrors,
            error: String(error),
        });
    }

    return { supported, hooksInstalled, hookErrors };
}
