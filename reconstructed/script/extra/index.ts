// Functional reconstruction of rel/extra.js.
// Extra battle UX hooks: pause deployment, 3x speed, and HP / vision overlay.

import "frida-il2cpp-bridge";
import { ScriptConfig, il2cppModuleName, safe, waitForModule } from "../util";

declare const Il2Cpp: any;
declare const rpc: any;
declare const console: any;
declare const setTimeout: any;

const conf = new ScriptConfig();
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

function vector2(x: number, y: number) {
    const Vector2 = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image.class("UnityEngine.Vector2");
    const v = Vector2.alloc().unbox();
    v.field("x").value = x;
    v.field("y").value = y;
    return v;
}

function invScale(v: number) {
    return v > 0.01 ? 1 / v : 1;
}

async function main() {
    const ok = await waitForModule(il2cppModuleName(), 10000, 100);
    if (!ok) {
        console.log("err: il2cpp not found");
        return;
    }
    await new Promise(resolve => setTimeout(resolve, 10000));

    Il2Cpp.perform(() => {
        safe("UISwitchToggle.SetInteractable", () => {
            const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.UI.UISwitchToggle")
                .method("SetInteractable").overload("System.Boolean", "System.Boolean");
            m.implementation = function (interactable: boolean, animated: boolean) {
                if (conf.bool("pause_deploy")) interactable = true;
                return this.method("SetInteractable").invoke(interactable, animated);
            };
        });

        safe("UIController.OnBottomMaskClicked", () => {
            const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UIController")
                .method("OnBottomMaskClicked").overload("System.Object");
            m.implementation = function (arg: any) {
                let wasPaused = false;
                if (conf.bool("pause_deploy")) wasPaused = this.method("get_isPaused").invoke() === true;
                if (wasPaused) this.method("SetPaused").invoke(false, false, false);
                try { this.method("OnBottomMaskClicked").invoke(arg); } catch (_) { }
                if (wasPaused) this.method("SetPaused").invoke(true, false, false);
            };
        });

        safe("UIController.OnCardBeginDrag", () => {
            const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UIController")
                .method("OnCardBeginDrag").overload("Torappu.Battle.UI.UICard");
            m.implementation = function (card: any) {
                let wasPaused = false;
                if (conf.bool("pause_deploy")) wasPaused = this.method("get_isPaused").invoke() === true;
                if (wasPaused) this.method("SetPaused").invoke(false, false, false);
                this.method("OnCardBeginDrag").invoke(card);
                if (wasPaused) this.method("SetPaused").invoke(true, false, false);
            };
        });

        safe("UITopBar.OnSpeedSwitcherClicked", () => {
            const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UITopBar")
                .method("OnSpeedSwitcherClicked").overload();
            m.implementation = function () {
                if (!conf.bool("3x_speed")) return this.method("OnSpeedSwitcherClicked").invoke();
                const level = this.method("get_speedLevel").invoke();
                let raw = level.field("value__").value + 1;
                if (raw > 3) raw = 1;
                level.field("value__").value = raw;
                this.method("set_speedLevel").invoke(level);
            };
        });

        safe("vision overlay", () => {
            const TextModeSlash = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.UI.UITextSlider").nested("TextMode").field("A_SLASH_B").value;
            const TextAnchorMiddleCenter = Il2Cpp.domain.assembly("UnityEngine.TextRenderingModule").image.class("UnityEngine.TextAnchor").field("MiddleCenter").value;
            const GameObject = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image.class("UnityEngine.GameObject");
            const Text = Il2Cpp.domain.assembly("UnityEngine.UI").image.class("UnityEngine.UI.Text");
            const RectTransform = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image.class("UnityEngine.RectTransform");
            const Vector3 = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image.class("UnityEngine.Vector3");
            const Character = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.Character");
            const overlayName = "obc-vision";

            function findFont() {
                const Resources = Il2Cpp.domain.assembly("UnityEngine.CoreModule").image.class("UnityEngine.Resources");
                const Font = Il2Cpp.domain.assembly("UnityEngine.TextRenderingModule").image.class("UnityEngine.Font");
                const fonts = Resources.method("FindObjectsOfTypeAll").overload("System.Type").invoke(Font.type.object);
                for (let i = 0; i < fonts.length; i++) {
                    const font = fonts.get(i);
                    if (font.method("get_name").invoke().content === "Novecentowide-Normal") return font;
                }
                return null;
            }

            function attachOverlay(slider: any, unit: any, giant = false) {
                if (slider.isNull()) return;
                const font = findFont();
                if (font === null) return;

                let go: any = null;
                const currentText = slider.field("_text").value;
                if (!currentText.isNull()) {
                    const currentGo = currentText.method("get_gameObject").invoke();
                    if (currentGo.method("get_name").invoke().content === overlayName) go = currentGo;
                }

                if (go === null) {
                    go = GameObject.alloc();
                    go.method(".ctor").invoke(Il2Cpp.string(overlayName));
                    const text = go.method("AddComponent").invoke(Text.type.object);
                    text.method("set_alignment").invoke(TextAnchorMiddleCenter);
                    text.method("set_font").invoke(font);
                    let fontSize = conf.number("vision_font_size", 22);
                    if (giant) fontSize *= 2;
                    text.method("set_fontSize").invoke(fontSize);
                    slider.field("_text").value = text;
                    slider.field("_textMode").value = TextModeSlash;

                    const parent = slider.method("get_transform").invoke();
                    parent.method("SetAsLastSibling").invoke();
                    const transform = go.method("get_transform").invoke();
                    transform.method("SetParent").invoke(parent);
                    const rect = go.method("GetComponent").overload("System.Type").invoke(RectTransform.type.object);

                    if (giant) {
                        const scale = unit.method("get_bossHudScale").invoke();
                        scale.field("x").value = invScale(scale.field("x").value);
                        scale.field("y").value = invScale(scale.field("y").value);
                        scale.field("z").value = invScale(scale.field("z").value);
                        rect.method("set_localScale").invoke(scale);
                    } else {
                        rect.method("set_localScale").invoke(Vector3.method("get_one").invoke());
                    }

                    rect.method("set_anchoredPosition3D").invoke(Vector3.method("get_zero").invoke());
                    const center = vector2(0.5, 0.5);
                    rect.method("set_anchorMax").invoke(center);
                    rect.method("set_anchorMin").invoke(center);
                    rect.method("set_pivot").invoke(center);
                    rect.method("set_sizeDelta").invoke(vector2(10000, 10000));
                }

                if (unit.isNull() || unit.class.isSubclassOf(Character, false)) go.method("SetActive").invoke(false);
                else go.method("SetActive").invoke(true);
            }

            safe("UIUnitHUD.Attach", () => {
                const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UIUnitHUD")
                .method("Attach").overload("Torappu.Battle.Unit");
            m.implementation = function (unit: any) {
                    this.method("Attach").invoke(unit);
                    if (conf.bool("vision")) attachOverlay(this.field("_hpSlider").value, unit);
                };
            });

            safe("UIHudEnemyHpSlider.OnAttach", () => {
                const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UIHudEnemyHpSlider")
                .method("OnAttach").overload("Torappu.Battle.Unit");
            m.implementation = function (unit: any) {
                    this.method("OnAttach").invoke(unit);
                    if (conf.bool("vision")) attachOverlay(this, unit);
                };
            });

            const m = Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.Battle.UI.UIEnemyGiantBossInfoPanel")
                .method("Attach").overload("Torappu.Battle.IUseGiantBossInfoPanel");
            m.implementation = function (boss: any) {
                this.method("Attach").invoke(boss);
                if (conf.bool("vision")) attachOverlay(this.field("_hpSlider").value, boss, true);
            };
        });
    });
}

main();
