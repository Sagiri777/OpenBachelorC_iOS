import { ScriptConfig } from "./util";

export const DIRECT_TRAINER_COMMANDS = [
    "unlock_fps",
    "battle_speed_16x",
    "tas_pause",
    "tas_step",
    "zero_cost",
    "zero_deploy_cnt",
    "deploy_everywhere",
    "zero_cooldown",
    "unlimited_token",
    "no_sp",
    "withdraw_everything",
    "heal_everyone",
    "unlimited_ammo",
    "eat_enemy",
    "global_range",
    "anti_air",
    "true_aoe",
    "no_ban_card",
    "cloner_assist",
    "allow_dup_char",
] as const;

export type DirectTrainerCommand = typeof DIRECT_TRAINER_COMMANDS[number];

export interface DirectTrainerRuntime {
    conf: ScriptConfig;
    hasOffset(name: string): boolean;
    address(name: string): NativePointer;
    emit(payload: Record<string, any>): void;
    hooks: string[];
    errors: string[];
}

export interface DirectTrainerControl {
    supportedCommands(): string[];
    enabledCommands(): string[];
    supportedStepUnits(): DirectTrainerStepUnit[];
    requestStep(unit: DirectTrainerStepUnit, count: number): boolean;
    invoke(command: string): boolean;
}

export type DirectTrainerStepUnit = "tick" | "frame";

type HookContext = InvocationContext & { trainerApply?: boolean };

interface ReturnHook {
    key: string;
    value: number | string;
    applies?: (self: NativePointer) => boolean;
}

const PARTIAL_COMMANDS = ["unlimited_token", "true_aoe"];
const MAX_TAS_STEP_COUNT = 10000;

function replacementValue(value: number | string): NativePointer {
    return typeof value === "number" ? ptr(value) : ptr(value);
}

export function installDirectTrainerHooks(
    runtime: DirectTrainerRuntime,
): DirectTrainerControl {
    const { conf, emit, hooks, errors } = runtime;
    const supported = new Set<string>();
    const enabled = new Set<string>();
    const stepUnits = new Set<DirectTrainerStepUnit>();
    const retainedFunctions: any[] = [];
    const actionHandlers = new Map<string, (action: "enable" | "disable") => boolean>();
    const stateHandlers = new Map<string, (enabled: boolean) => void>();
    let requestStep = (unit: DirectTrainerStepUnit, count: number): boolean => {
        emit({
            event: "trainer-command-unavailable",
            command: "tas_step",
            unit,
            count,
            reason: "profile",
        });
        return false;
    };

    const nativeFunction = (
        key: string,
        returnType: NativeFunctionReturnType,
        argumentTypes: NativeFunctionArgumentType[],
    ): any => {
        const value = new NativeFunction(runtime.address(key), returnType, argumentTypes);
        retainedFunctions.push(value);
        return value;
    };

    let targetSelectorGetOwner: any = null;
    let bObjectGetSide: any = null;
    const ensureAllyHelpers = (): boolean => {
        if (targetSelectorGetOwner !== null && bObjectGetSide !== null) return true;
        if (!runtime.hasOffset("trainerTargetSelectorGetOwner")
            || !runtime.hasOffset("trainerBObjectGetSide")) return false;
        try {
            targetSelectorGetOwner = nativeFunction(
                "trainerTargetSelectorGetOwner",
                "pointer",
                ["pointer", "pointer"],
            );
            bObjectGetSide = nativeFunction(
                "trainerBObjectGetSide",
                "int32",
                ["pointer", "pointer"],
            );
            return true;
        } catch (error) {
            errors.push(`trainer ally helpers: ${String(error)}`);
            targetSelectorGetOwner = null;
            bObjectGetSide = null;
            return false;
        }
    };

    const isAllyEntity = (entity: NativePointer): boolean => {
        if (entity.isNull() || bObjectGetSide === null) return false;
        return Number(bObjectGetSide(entity, NULL)) === 1;
    };

    const isAllySelector = (selector: NativePointer): boolean => {
        if (selector.isNull() || targetSelectorGetOwner === null) return false;
        const owner = targetSelectorGetOwner(selector, NULL) as NativePointer;
        return isAllyEntity(owner);
    };

    const attachReturnHook = (command: string, hook: ReturnHook): boolean => {
        if (!runtime.hasOffset(hook.key)) return false;
        try {
            Interceptor.attach(runtime.address(hook.key), {
                onEnter(this: HookContext, args) {
                    if (!enabled.has(command)) return;
                    try {
                        this.trainerApply = hook.applies?.(args[0]) ?? true;
                    } catch (error) {
                        this.trainerApply = false;
                        emit({
                            event: "trainer-runtime-error",
                            command,
                            hook: hook.key,
                            error: String(error),
                        });
                    }
                },
                onLeave(this: HookContext, retval) {
                    if (this.trainerApply) retval.replace(replacementValue(hook.value));
                },
            });
            hooks.push(hook.key);
            return true;
        } catch (error) {
            errors.push(`${hook.key}: ${String(error)}`);
            emit({
                event: "trainer-hook-error",
                command,
                hook: hook.key,
                error: String(error),
            });
            return false;
        }
    };

    const installCommand = (command: string, commandHooks: ReturnHook[]): void => {
        const results = commandHooks.map(hook => attachReturnHook(command, hook));
        if (results.length > 0 && results.every(Boolean)) supported.add(command);
    };

    const invoke = (rawCommand: string): boolean => {
        const match = /^(enable|disable):(.+)$/.exec(rawCommand);
        if (match === null) {
            emit({ event: "trainer-command-error", command: rawCommand, error: "invalid-command" });
            return false;
        }
        const action = match[1];
        const command = match[2];
        if (!conf.bool("trainer_enabled", false)) {
            emit({ event: "trainer-command-unavailable", command, reason: "configuration" });
            return false;
        }
        if (!supported.has(command)) {
            emit({ event: "trainer-command-unavailable", command, reason: "profile" });
            return false;
        }
        const actionHandler = actionHandlers.get(command);
        if (actionHandler !== undefined) {
            let accepted = false;
            try {
                accepted = actionHandler(action as "enable" | "disable");
            } catch (error) {
                emit({ event: "trainer-runtime-error", command, error: String(error) });
                return false;
            }
            emit({
                event: "trainer-action",
                command,
                action,
                accepted,
                enabled_commands: Array.from(enabled),
            });
            return accepted;
        }
        if (action === "enable") enabled.add(command);
        else enabled.delete(command);
        try {
            stateHandlers.get(command)?.(action === "enable");
        } catch (error) {
            emit({ event: "trainer-runtime-error", command, error: String(error) });
        }
        emit({
            event: "trainer-state",
            command,
            enabled: action === "enable",
            enabled_commands: Array.from(enabled),
        });
        return true;
    };

    for (const command of DIRECT_TRAINER_COMMANDS) {
        conf.command(`enable:${command}`, () => invoke(`enable:${command}`));
        conf.command(`disable:${command}`, () => invoke(`disable:${command}`));
    }
    conf.command("dump", () => {
        emit({ event: "trainer-command-unavailable", command: "dump", reason: "direct-rva" });
    });

    if (!conf.bool("trainer_enabled", false)) {
        emit({ event: "trainer-disabled", reason: "configuration" });
        return {
            supportedCommands: () => [],
            enabledCommands: () => [],
            supportedStepUnits: () => [],
            requestStep,
            invoke,
        };
    }

    const attachRuntimeHook = (
        command: string,
        hookName: string,
        offsetKey: string,
        callbacks: any,
    ): boolean => {
        if (!runtime.hasOffset(offsetKey)) return false;
        try {
            Interceptor.attach(runtime.address(offsetKey), callbacks);
            hooks.push(hookName);
            return true;
        } catch (error) {
            errors.push(`${hookName}: ${String(error)}`);
            emit({ event: "trainer-hook-error", command, hook: hookName, error: String(error) });
            return false;
        }
    };

    const configuredTargetFps = (): number => Math.round(
        Math.max(30, Math.min(conf.number("trainer_target_fps", 120), 240)),
    );
    const configuredBattleSpeed = (): number => Math.max(
        4,
        Math.min(conf.number("trainer_battle_speed", 16), 32),
    );

    let setTargetFrameRate: any = null;
    let fpsNeedsApply = false;
    if (runtime.hasOffset("trainerApplicationSetTargetFrameRate")) {
        try {
            setTargetFrameRate = nativeFunction(
                "trainerApplicationSetTargetFrameRate",
                "void",
                ["int32", "pointer"],
            );
        } catch (error) {
            errors.push(`trainerApplicationSetTargetFrameRate: ${String(error)}`);
        }
    }
    if (setTargetFrameRate !== null) {
        const fpsHook = attachRuntimeHook(
            "unlock_fps",
            "trainerApplicationSetTargetFrameRate",
            "trainerApplicationSetTargetFrameRate",
            {
                onEnter(args: InvocationArguments) {
                    if (enabled.has("unlock_fps")) args[0] = ptr(configuredTargetFps());
                },
            },
        );
        if (fpsHook) {
            supported.add("unlock_fps");
            stateHandlers.set("unlock_fps", value => { fpsNeedsApply = value; });
        }
    }

    let getSpeedLevel: any = null;
    let setTimeScale: any = null;
    try {
        if (runtime.hasOffset("trainerBattleControllerGetSpeedLevel")) {
            getSpeedLevel = nativeFunction(
                "trainerBattleControllerGetSpeedLevel",
                "int32",
                ["pointer", "pointer"],
            );
        }
        if (runtime.hasOffset("trainerBattleControllerSetTimeScale")) {
            setTimeScale = nativeFunction(
                "trainerBattleControllerSetTimeScale",
                "void",
                ["pointer", "float", "pointer"],
            );
        }
    } catch (error) {
        errors.push(`trainer battle speed functions: ${String(error)}`);
        getSpeedLevel = null;
        setTimeScale = null;
    }

    let speedNeedsApply = false;
    let speedNeedsRestore = false;
    let speedHookInstalled = false;
    if (getSpeedLevel !== null && setTimeScale !== null) {
        speedHookInstalled = attachRuntimeHook(
            "battle_speed_16x",
            "trainerBattleControllerOnSpeedLevelChanged",
            "trainerBattleControllerOnSpeedLevelChanged",
            {
                onEnter(this: HookContext, args: InvocationArguments) {
                    if (enabled.has("battle_speed_16x")) this.trainerApply = true;
                    (this as HookContext & { trainerController?: NativePointer }).trainerController = args[0];
                },
                onLeave(this: HookContext & { trainerController?: NativePointer }) {
                    if (!this.trainerApply || this.trainerController === undefined) return;
                    try {
                        setTimeScale(this.trainerController, configuredBattleSpeed(), NULL);
                    } catch (error) {
                        emit({
                            event: "trainer-runtime-error",
                            command: "battle_speed_16x",
                            hook: "trainerBattleControllerOnSpeedLevelChanged",
                            error: String(error),
                        });
                    }
                },
            },
        );
        if (speedHookInstalled) {
            supported.add("battle_speed_16x");
            stateHandlers.set("battle_speed_16x", value => {
                speedNeedsApply = value;
                speedNeedsRestore = !value;
            });
        }
    }

    let getFixedFrameCnt: any = null;
    let getUiPaused: any = null;
    let setUiPaused: any = null;
    let uiController: NativePointer | null = null;
    let tasOwnsPause = false;
    let tasStepPending: { unit: DirectTrainerStepUnit; count: number } | null = null;
    let tasStepState: {
        unit: DirectTrainerStepUnit;
        count: number;
        startTick: number;
        framesAdvanced: number;
    } | null = null;
    try {
        if (runtime.hasOffset("extraBattleControllerGetFixedFrameCnt")) {
            getFixedFrameCnt = nativeFunction(
                "extraBattleControllerGetFixedFrameCnt",
                "uint32",
                ["pointer"],
            );
        }
        if (runtime.hasOffset("extraUiControllerGetIsPaused")) {
            getUiPaused = nativeFunction(
                "extraUiControllerGetIsPaused",
                "uint8",
                ["pointer", "pointer"],
            );
        }
        if (runtime.hasOffset("extraUiControllerSetPaused")) {
            setUiPaused = nativeFunction(
                "extraUiControllerSetPaused",
                "uint8",
                ["pointer", "uint8", "uint8", "uint8", "pointer"],
            );
        }
    } catch (error) {
        errors.push(`trainer TAS functions: ${String(error)}`);
        getFixedFrameCnt = null;
        getUiPaused = null;
        setUiPaused = null;
    }

    const captureUiController = (args: InvocationArguments): void => {
        if (!args[0].isNull()) uiController = args[0];
    };
    const uiAwakeHook = attachRuntimeHook(
        "tas_pause",
        "trainerUiControllerAwake",
        "trainerUiControllerAwake",
        { onEnter: captureUiController },
    );
    const uiUpdateHook = attachRuntimeHook(
        "tas_pause",
        "trainerUiControllerUpdate",
        "trainerUiControllerUpdate",
        { onEnter: captureUiController },
    );
    const uiDestroyHook = attachRuntimeHook(
        "tas_pause",
        "trainerUiControllerOnDestroy",
        "trainerUiControllerOnDestroy",
        {
            onEnter(args: InvocationArguments) {
                if (uiController !== null && args[0].equals(uiController)) uiController = null;
                tasOwnsPause = false;
                tasStepPending = null;
                tasStepState = null;
            },
        },
    );

    const tickDelta = (start: number, end: number): number => (
        end >= start ? end - start : 0x100000000 - start + end
    );

    const finishTasStep = (endTick: number): void => {
        const state = tasStepState;
        if (state === null || uiController === null || uiController.isNull()
            || setUiPaused === null) return;
        setUiPaused(uiController, 1, 0, 0, NULL);
        tasStepState = null;
        tasOwnsPause = true;
        emit({
            event: "trainer-action-complete",
            command: "tas_step",
            unit: state.unit,
            requested_count: state.count,
            advanced_frames: state.framesAdvanced,
            advanced_ticks: tickDelta(state.startTick, endTick),
            start_tick: state.startTick,
            end_tick: endTick,
        });
    };

    const fixedUpdateHook = attachRuntimeHook(
        "tas_step",
        "trainerBattleControllerFixedUpdate",
        "trainerBattleControllerFixedUpdate",
        {
            onLeave() {
                const state = tasStepState;
                if (state === null || state.unit !== "tick" || getFixedFrameCnt === null) return;
                try {
                    const ticks = Number(getFixedFrameCnt(NULL));
                    if (tickDelta(state.startTick, ticks) >= state.count) finishTasStep(ticks);
                } catch (error) {
                    tasStepState = null;
                    emit({
                        event: "trainer-runtime-error",
                        command: "tas_step",
                        unit: "tick",
                        hook: "trainerBattleControllerFixedUpdate",
                        error: String(error),
                    });
                }
            },
        },
    );

    const battleUpdateHook = attachRuntimeHook(
        "runtime_controls",
        "trainerBattleControllerUpdate",
        "extraBattleControllerUpdate",
        {
            onEnter(args: InvocationArguments) {
                const battleController = args[0];
                if (battleController.isNull()) return;
                try {
                    if (enabled.has("unlock_fps") && fpsNeedsApply && setTargetFrameRate !== null) {
                        setTargetFrameRate(configuredTargetFps(), NULL);
                        fpsNeedsApply = false;
                    }
                    if (enabled.has("battle_speed_16x") && speedNeedsApply && setTimeScale !== null) {
                        setTimeScale(battleController, configuredBattleSpeed(), NULL);
                        speedNeedsApply = false;
                        speedNeedsRestore = false;
                    } else if (!enabled.has("battle_speed_16x") && speedNeedsRestore
                        && setTimeScale !== null && getSpeedLevel !== null) {
                        const level = Number(getSpeedLevel(battleController, NULL));
                        const normalScale = level <= 0 ? 0.1 : Math.min(level, 3);
                        setTimeScale(battleController, normalScale, NULL);
                        speedNeedsRestore = false;
                    }

                    if (uiController === null || uiController.isNull()
                        || getUiPaused === null || setUiPaused === null) return;
                    if (tasStepState !== null) {
                        if (tasStepState.unit === "frame"
                            && tasStepState.framesAdvanced >= tasStepState.count) {
                            finishTasStep(Number(getFixedFrameCnt(NULL)));
                            return;
                        }
                        tasStepState.framesAdvanced += 1;
                        return;
                    }
                    if (tasStepPending !== null && tasStepState === null
                        && getFixedFrameCnt !== null) {
                        const pending = tasStepPending;
                        tasStepPending = null;
                        tasStepState = {
                            unit: pending.unit,
                            count: pending.count,
                            startTick: Number(getFixedFrameCnt(NULL)),
                            framesAdvanced: 1,
                        };
                        if (Number(getUiPaused(uiController, NULL)) !== 0) {
                            setUiPaused(uiController, 0, 0, 0, NULL);
                        }
                        tasOwnsPause = true;
                        emit({
                            event: "trainer-action-started",
                            command: "tas_step",
                            unit: pending.unit,
                            requested_count: pending.count,
                            start_tick: tasStepState.startTick,
                        });
                    }
                    if (tasStepState !== null) {
                        return;
                    }
                    const paused = Number(getUiPaused(uiController, NULL)) !== 0;
                    if (enabled.has("tas_pause")) {
                        if (!paused) {
                            setUiPaused(uiController, 1, 0, 0, NULL);
                            tasOwnsPause = true;
                        }
                    } else if (tasOwnsPause) {
                        if (paused) setUiPaused(uiController, 0, 0, 0, NULL);
                        tasOwnsPause = false;
                    }
                } catch (error) {
                    emit({
                        event: "trainer-runtime-error",
                        command: "runtime_controls",
                        hook: "trainerBattleControllerUpdate",
                        error: String(error),
                    });
                }
            },
        },
    );

    // Awake and Update are two independent ways to discover the live
    // UIController.  OnDestroy is useful for eagerly clearing the pointer,
    // but it is not required to pause or step: Awake replaces the pointer at
    // the start of the next battle and Update continuously refreshes it while
    // a battle is active.  Requiring both Update and OnDestroy used to hide
    // all Tick/frame controls when either non-essential lifecycle hook could
    // not be attached, even though the stepping primitives were available.
    const controllerCaptureReady = uiAwakeHook || uiUpdateHook;
    const tasHooksReady = getFixedFrameCnt !== null
        && getUiPaused !== null
        && setUiPaused !== null
        && controllerCaptureReady
        && battleUpdateHook;
    if (tasHooksReady) {
        supported.add("tas_pause");
        supported.add("tas_step");
        stepUnits.add("frame");
        if (fixedUpdateHook) stepUnits.add("tick");
        requestStep = (unit, count) => {
            const normalizedCount = Math.trunc(count);
            if (!stepUnits.has(unit)) {
                emit({ event: "trainer-command-unavailable", command: "tas_step", unit, reason: "profile" });
                return false;
            }
            if (!Number.isFinite(count) || normalizedCount < 1 || normalizedCount > MAX_TAS_STEP_COUNT) {
                emit({
                    event: "trainer-command-error",
                    command: "tas_step",
                    unit,
                    count,
                    error: `count-must-be-1-${MAX_TAS_STEP_COUNT}`,
                });
                return false;
            }
            if (tasStepPending !== null || tasStepState !== null) {
                emit({ event: "trainer-command-error", command: "tas_step", unit, count: normalizedCount, error: "busy" });
                return false;
            }
            enabled.add("tas_pause");
            tasStepPending = { unit, count: normalizedCount };
            emit({
                event: "trainer-step-requested",
                command: "tas_step",
                unit,
                count: normalizedCount,
            });
            return true;
        };
        stateHandlers.set("tas_pause", value => {
            if (!value) {
                tasStepPending = null;
                tasStepState = null;
            }
        });
        actionHandlers.set("tas_step", action => {
            if (action === "disable") {
                tasStepPending = null;
                tasStepState = null;
                return true;
            }
            return requestStep("frame", 1);
        });
    }

    installCommand("zero_cost", [
        { key: "trainerDeckCardGetCost", value: 0 },
        { key: "trainerDeckTokenCardGetCost", value: 0 },
    ]);
    installCommand("zero_deploy_cnt", [
        { key: "trainerDeckCardGetDontOccupyDeployCnt", value: 1 },
    ]);
    installCommand("deploy_everywhere", [
        { key: "trainerTileGetBuildableType", value: 3 },
    ]);
    installCommand("zero_cooldown", [
        { key: "trainerDeckCardGetState", value: 1 },
    ]);
    // Direct mode covers the scalar token checks. The ObscuredInt struct
    // returned by get_maxDeployCnt is intentionally left untouched because
    // replacing a multi-register value is ABI-sensitive on arm64/arm64e.
    installCommand("unlimited_token", [
        { key: "trainerDeckCardGetRemainingCnt", value: 999 },
        { key: "trainerDeckTokenCardGetIsMaxDeployed", value: 0 },
        { key: "trainerDeckTokenCardGetReadyToSpawn", value: 1 },
        { key: "trainerDeckTokenCardGetCardPolicy", value: 2 },
    ]);

    if (runtime.hasOffset("trainerBObjectGetSide")) {
        try {
            bObjectGetSide = nativeFunction(
                "trainerBObjectGetSide",
                "int32",
                ["pointer", "pointer"],
            );
        } catch (error) {
            errors.push(`trainerBObjectGetSide: ${String(error)}`);
            bObjectGetSide = null;
        }
    }
    if (bObjectGetSide !== null) {
        installCommand("no_sp", [
            {
                key: "trainerEntityGetSp",
                value: "0x1869f00000000",
                applies: isAllyEntity,
            },
            { key: "trainerBasicSkillGetAvailableCnt", value: 9 },
            { key: "trainerBasicSkillGetIsUsedUp", value: 0 },
        ]);
    }

    installCommand("withdraw_everything", [
        { key: "trainerCharacterGetWithdrawable", value: 1 },
        { key: "trainerCharacterGetManuallyWithdrawable", value: 1 },
        { key: "trainerTrapGetWithdrawable", value: 1 },
    ]);
    installCommand("heal_everyone", [
        { key: "trainerEntityGetIsHealFree", value: 0 },
    ]);
    installCommand("unlimited_ammo", [
        { key: "trainerAbilityEventCounterGetMaxCount", value: 99999 },
    ]);
    installCommand("eat_enemy", [
        { key: "trainerEnemyGetLifePointReduce", value: 0 },
        { key: "trainerBattleControllerModifyLifePoint", value: 0 },
    ]);

    if (ensureAllyHelpers()) {
        installCommand("anti_air", [
            { key: "trainerAdvancedSelectorGetTargetMotion", value: 3, applies: isAllySelector },
            { key: "trainerRandomSelectorGetTargetMotion", value: 3, applies: isAllySelector },
        ]);
        // The direct fallback raises the managed target limit, but does not
        // bypass the two List<Entity> post-filters used by the bridge agent.
        installCommand("true_aoe", [
            { key: "trainerAdvancedSelectorGetMaxTargetNum", value: 128, applies: isAllySelector },
            { key: "trainerBattleUtilLimitMaxNumToBlockCnt", value: 128 },
        ]);
    }

    installCommand("no_ban_card", [
        { key: "trainerDeckCardGetIsAvailable", value: 1 },
    ]);
    installCommand("cloner_assist", [
        { key: "trainerSquadFriendAssistCheckContained", value: 0 },
        { key: "trainerSquadHomeCheckStartBattleValid", value: 1 },
    ]);

    const unavailable = DIRECT_TRAINER_COMMANDS.filter(command => !supported.has(command));
    emit({
        event: "trainer-ready",
        backend: "direct-rva",
        commands_supported: Array.from(supported),
        step_units: Array.from(stepUnits),
        commands_partial: PARTIAL_COMMANDS.filter(command => supported.has(command)),
        commands_unavailable: unavailable,
        hooks_installed: hooks.filter(name => name.startsWith("trainer")),
        lifecycle_hooks: {
            awake: uiAwakeHook,
            update: uiUpdateHook,
            destroy: uiDestroyHook,
        },
    });

    return {
        supportedCommands: () => Array.from(supported),
        enabledCommands: () => Array.from(enabled),
        supportedStepUnits: () => Array.from(stepUnits),
        requestStep: (unit, count) => requestStep(unit, count),
        invoke,
    };
}
