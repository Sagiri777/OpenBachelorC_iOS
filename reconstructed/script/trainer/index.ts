// Functional reconstruction of rel/trainer.js.
// Trainer command hooks. This aims for equivalent hook points and behavior, not original source layout.

import "frida-il2cpp-bridge";
import { ScriptConfig, il2cppModuleName, safe, waitForModule } from "../util";

declare const Il2Cpp: any;
declare const rpc: any;
declare const console: any;
declare const File: any;
declare const NULL: any;
declare const setTimeout: any;

const conf = new ScriptConfig();
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

function asm(name: string) { return Il2Cpp.domain.assembly(name).image; }
function cls(assembly: string, name: string) { return asm(assembly).class(name); }
function sameEnum(a: any, b: any) { return a.field("value__").value === b.field("value__").value; }
function perform(fn: () => void) { Il2Cpp.perform(fn); }

function commandPair(name: string, enable: () => void, disable: () => void) {
    let enabled = false;
    conf.command(`enable:${name}`, () => { if (!enabled) { enabled = true; perform(enable); } });
    conf.command(`disable:${name}`, () => { if (enabled) { enabled = false; perform(disable); } });
}

function installDumpHooks() {
    safe("dump_json hooks", () => {
        const converters = [
            cls("Assembly-CSharp", "Torappu.ListDictConverter"),
            cls("Assembly-CSharp", "Torappu.ObscuredIntConverter"),
            cls("Assembly-CSharp", "Torappu.ObscuredFloatConverter"),
            cls("Newtonsoft.Json", "Newtonsoft.Json.Converters.StringEnumConverter"),
        ];
        const serialize = cls("Newtonsoft.Json", "Newtonsoft.Json.JsonConvert")
            .method("SerializeObject").overload("System.Object", "Newtonsoft.Json.JsonSerializerSettings");
        const JsonSerializerSettings = cls("Newtonsoft.Json", "Newtonsoft.Json.JsonSerializerSettings");
        const seen = new Map<string, number>();

        const asyncLoad = cls("Assembly-CSharp", "Torappu.DB.AbstractTable").method("get_enableAsyncLoad").overload();
        asyncLoad.implementation = function () {
            return !conf.bool("dump_json") && this.method("get_enableAsyncLoad").invoke();
        };

        const doLoad = cls("Assembly-CSharp", "Torappu.DB.DBLoader")
            .method("_DoLoadTable").overload("Torappu.DB.AbstractTable", "Torappu.DB.IConverter", "System.Boolean");
        doLoad.implementation = function (table: any, converter: any, flag: boolean) {
            const ret = this.method("_DoLoadTable").invoke(table, converter, flag);
            if (conf.bool("dump_json")) {
                let getData = table.class.tryMethod("get_data");
                if (getData) {
                    if (!getData.isStatic) getData = table.method("get_data");
                    const data = getData.invoke();
                    const tableName = table.toString();
                    const count = seen.get(tableName) || 0;
                    seen.set(tableName, count + 1);
                    const filename = count ? `${tableName}.${count}.json` : `${tableName}.json`;
                    const path = `${Il2Cpp.application.dataPath}/${filename}`;
                    try {
                        const settings = JsonSerializerSettings.new();
                        const list = settings.method("get_Converters").invoke();
                        for (const c of converters) list.method("Add").invoke(c.new());
                        const json = serialize.invoke(data, settings).content;
                        const file = new File(path, "w");
                        file.write(json);
                        file.close();
                        console.log(`info: dumped ${tableName}`);
                    } catch (e) {
                        console.log(`err: failed to dump ${tableName}`);
                    }
                }
            }
            return ret;
        };
    });
}

function registerCommands() {
    conf.command("dump", () => perform(() => Il2Cpp.dump("dump.cs")));

    commandPair("zero_cost", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_cost").overload().implementation = () => 0;
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_cost").overload().implementation = () => 0;
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_cost").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_cost").overload().revert();
    });

    commandPair("zero_deploy_cnt", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_dontOccupyDeployCnt").overload().implementation = () => true;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_dontOccupyDeployCnt").overload().revert());

    commandPair("deploy_everywhere", () => {
        const all = cls("Torappu.Common", "Torappu.BuildableType").field("ALL").value;
        cls("Assembly-CSharp", "Torappu.Battle.Tile").method("get_buildableType").overload().implementation = () => all;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Tile").method("get_buildableType").overload().revert());

    commandPair("zero_cooldown", () => {
        const ready = cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").nested("State").field("READY").value;
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_state").overload().implementation = () => ready;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_state").overload().revert());

    commandPair("unlimited_token", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_remainingCnt").overload().implementation = () => 999;
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_isMaxDeployed").overload().implementation = () => false;
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_readyToSpawn").overload().implementation = () => true;
        const ObscuredInt = cls("ThirdPartyAssembly", "CodeStage.AntiCheat.ObscuredTypes.ObscuredInt");
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_maxDeployCnt").overload().implementation = () => {
            const v = ObscuredInt.alloc();
            v.method(".ctor").invoke(999);
            return v;
        };
        const queued = cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").nested("CardPolicy").field("QUEUED").value;
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard").method("get_cardPolicy").overload().implementation = () => queued;
    }, () => {
        for (const [klass, method] of [
            [cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card"), "get_remainingCnt"],
            [cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard"), "get_isMaxDeployed"],
            [cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard"), "get_readyToSpawn"],
            [cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard"), "get_maxDeployCnt"],
            [cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("TokenCard"), "get_cardPolicy"],
        ] as any[]) klass.method(method).overload().revert();
    });

    commandPair("no_sp", () => {
        const ally = cls("Assembly-CSharp", "Torappu.Battle.SideType").field("ALLY").value;
        const FP = cls("Torappu.Common", "Torappu.FP");
        const getSp = cls("Assembly-CSharp", "Torappu.Battle.Entity").method("get_sp").overload();
        getSp.implementation = function () {
            const side = this.method("get_side").invoke();
            return sameEnum(side, ally) ? FP.method("FromFloat").invoke(99999) : this.method("get_sp").invoke();
        };
        cls("Assembly-CSharp", "Torappu.Battle.BasicSkill").method("get_availableCnt").overload().implementation = () => 9;
        cls("Assembly-CSharp", "Torappu.Battle.BasicSkill").method("get_isUsedUp").overload().implementation = () => false;
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.Entity").method("get_sp").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.BasicSkill").method("get_availableCnt").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.BasicSkill").method("get_isUsedUp").overload().revert();
    });

    commandPair("withdraw_everything", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Character").method("get_withdrawable").overload().implementation = () => true;
        cls("Assembly-CSharp", "Torappu.Battle.Character").method("get_manuallyWithdrawable").overload().implementation = () => true;
        cls("Assembly-CSharp", "Torappu.Battle.Trap").method("get_withdrawable").overload().implementation = () => true;
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.Character").method("get_withdrawable").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.Character").method("get_manuallyWithdrawable").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.Trap").method("get_withdrawable").overload().revert();
    });

    commandPair("heal_everyone", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Entity").method("get_isHealFree").overload().implementation = () => false;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Entity").method("get_isHealFree").overload().revert());

    commandPair("unlimited_ammo", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Abilities.AbilityEventCounter").method("get_maxCount").overload().implementation = () => 99999;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Abilities.AbilityEventCounter").method("get_maxCount").overload().revert());

    commandPair("eat_enemy", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Enemy").method("get_lifePointReduce").overload().implementation = () => 0;
        cls("Assembly-CSharp", "Torappu.Battle.BattleController").method("ModifyLifePoint")
            .overload("System.Int32", "Torappu.Battle.Entity", "Torappu.PlayerSide", "System.Boolean").implementation = () => false;
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.Enemy").method("get_lifePointReduce").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.BattleController").method("ModifyLifePoint")
            .overload("System.Int32", "Torappu.Battle.Entity", "Torappu.PlayerSide", "System.Boolean").revert();
    });

    commandPair("anti_air", () => {
        const ally = cls("Assembly-CSharp", "Torappu.Battle.SideType").field("ALLY").value;
        const allMotion = cls("Torappu.Common", "Torappu.MotionMask").field("ALL").value;
        const isAllyOwner = (self: any) => {
            const owner = self.method("get_owner").invoke();
            return !owner.isNull() && sameEnum(owner.method("get_side").invoke(), ally);
        };
        const adv = cls("Assembly-CSharp", "Torappu.Battle.AdvancedSelector").method("get_targetMotion").overload();
        adv.implementation = function () { return isAllyOwner(this) ? allMotion : this.method("get_targetMotion").invoke(); };
        const rnd = cls("Assembly-CSharp", "Torappu.Battle.RandomSelector").method("get_targetMotion").overload();
        rnd.implementation = function () { return isAllyOwner(this) ? allMotion : this.method("get_targetMotion").invoke(); };
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.AdvancedSelector").method("get_targetMotion").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.RandomSelector").method("get_targetMotion").overload().revert();
    });

    commandPair("true_aoe", () => {
        const ally = cls("Assembly-CSharp", "Torappu.Battle.SideType").field("ALLY").value;
        const isAllyOwner = (self: any) => {
            const owner = self.method("get_owner").invoke();
            return !owner.isNull() && sameEnum(owner.method("get_side").invoke(), ally);
        };
        const maxTarget = cls("Assembly-CSharp", "Torappu.Battle.AdvancedSelector").method("get_maxTargetNum").overload();
        maxTarget.implementation = function () { return isAllyOwner(this) ? 128 : this.method("get_maxTargetNum").invoke(); };
        cls("Assembly-CSharp", "Torappu.Battle.BattleUtil").method("LimitMaxNumToBlockCnt")
            .overload("System.Int32", "System.Int32", "System.Boolean").implementation = () => 128;
        const randomPost = cls("Assembly-CSharp", "Torappu.Battle.RandomSelector").method("OnPostFilter").overload("System.Collections.Generic.List<Torappu.Battle.Entity>");
        randomPost.implementation = function (list: any) { if (!isAllyOwner(this)) this.method("OnPostFilter").invoke(list); };
        const parallelPost = cls("Assembly-CSharp", "Torappu.Battle.ParallelGroupSelector").method("OnPostFilter").overload("System.Collections.Generic.List<Torappu.Battle.Entity>");
        parallelPost.implementation = function (list: any) { if (!isAllyOwner(this)) this.method("OnPostFilter").invoke(list); };
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.AdvancedSelector").method("get_maxTargetNum").overload().revert();
        cls("Assembly-CSharp", "Torappu.Battle.BattleUtil").method("LimitMaxNumToBlockCnt")
            .overload("System.Int32", "System.Int32", "System.Boolean").revert();
        cls("Assembly-CSharp", "Torappu.Battle.RandomSelector").method("OnPostFilter").overload("System.Collections.Generic.List<Torappu.Battle.Entity>").revert();
        cls("Assembly-CSharp", "Torappu.Battle.ParallelGroupSelector").method("OnPostFilter").overload("System.Collections.Generic.List<Torappu.Battle.Entity>").revert();
    });

    commandPair("no_ban_card", () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_isAvailable").overload().implementation = () => true;
    }, () => cls("Assembly-CSharp", "Torappu.Battle.Deck").nested("Card").method("get_isAvailable").overload().revert());

    commandPair("cloner_assist", () => {
        cls("Assembly-CSharp", "Torappu.UI.Squad.SquadFriendAssistStateBean").method("CheckIfContainedInCurSquad").overload("System.String").implementation = () => false;
        cls("Assembly-CSharp", "Torappu.UI.Squad.SquadHomeState").method("_CheckIfStartBattleValid").overload().implementation = () => true;
    }, () => {
        cls("Assembly-CSharp", "Torappu.UI.Squad.SquadFriendAssistStateBean").method("CheckIfContainedInCurSquad").overload("System.String").revert();
        cls("Assembly-CSharp", "Torappu.UI.Squad.SquadHomeState").method("_CheckIfStartBattleValid").overload().revert();
    });

    commandPair("allow_dup_char", () => {
        function rewriteIds(list: any, seen: Set<number>) {
            if (list.isNull()) return;
            for (let i = 0; i < list.length; i++) {
                const item = list.get(i);
                if (item.isNull()) continue;
                const uid = item.field("uniqueId").value;
                const host = item.field("tokenOrHostUniqueId").value;
                let delta = 0;
                while (seen.has(uid + delta)) delta += 1000000;
                if (delta !== 0) {
                    item.field("uniqueId").value = uid + delta;
                    if (host !== 0) item.field("tokenOrHostUniqueId").value = host + delta;
                }
                seen.add(uid + delta);
            }
        }
        function rewritePlayerData(data: any) {
            if (data.isNull()) return;
            const seen = new Set<number>();
            rewriteIds(data.field("characters").value, seen);
            rewriteIds(data.field("tokens").value, seen);
        }
        const ctor = cls("Assembly-CSharp", "Torappu.Battle.Deck").method(".ctor")
            .overload("Torappu.Battle.BattlePlayerData", "Torappu.Battle.Deck.Options", "Torappu.PlayerSide");
        ctor.implementation = function (data: any, options: any, side: any) {
            rewritePlayerData(data);
            return this.method(".ctor").invoke(data, options, side);
        };
        const gen = cls("Assembly-CSharp", "Torappu.UI.CharSelect.CharSelectStateInputBuilder").method("_GenPlayerDefaultData")
            .overload("System.Collections.Generic.List<System.Int32>", "System.Collections.Generic.List<Torappu.UI.CharacterCardViewModel>&");
        gen.implementation = function (_ids: any, output: any) { return this.method("_GenPlayerDefaultData").invoke(NULL, output); };
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.Deck").method(".ctor")
            .overload("Torappu.Battle.BattlePlayerData", "Torappu.Battle.Deck.Options", "Torappu.PlayerSide").revert();
        cls("Assembly-CSharp", "Torappu.UI.CharSelect.CharSelectStateInputBuilder").method("_GenPlayerDefaultData")
            .overload("System.Collections.Generic.List<System.Int32>", "System.Collections.Generic.List<Torappu.UI.CharacterCardViewModel>&").revert();
    });

    // global_range is the most version-sensitive command in the release bundle. This reconstructs
    // the stable core effect: ally range selectors keep extremely large collider dimensions.
    commandPair("global_range", () => {
        const ally = cls("Assembly-CSharp", "Torappu.Battle.SideType").field("ALLY").value;
        const Vector2 = cls("UnityEngine.CoreModule", "UnityEngine.Vector2");
        const BoxCollider2D = cls("UnityEngine.Physics2DModule", "UnityEngine.BoxCollider2D");
        const AutoLoadBoxRange = cls("Assembly-CSharp", "Torappu.Battle.AutoLoadBoxRange");
        function bigV2() { const v = Vector2.alloc().unbox(); v.field("x").value = 1000; v.field("y").value = 1000; return v; }
        function isAlly(entity: any) { return !entity.isNull() && sameEnum(entity.method("get_side").invoke(), ally); }
        function widen(range: any) {
            if (range.isNull() || !range.class.isSubclassOf(AutoLoadBoxRange, false)) return;
            for (const field of ["m_colliders", "m_originColliders", "m_allColliders"]) {
                const f = range.tryField(field);
                const arr = f && f.value;
                if (!arr || arr.isNull() || !arr.length) continue;
                const col = arr.get(0);
                if (!col.isNull() && col.class.isSubclassOf(BoxCollider2D, false)) {
                    try { col.method("set_size").invoke(bigV2()); } catch (_) { }
                }
            }
        }
        const reset = cls("Assembly-CSharp", "Torappu.Battle.RangeSelector").method("Reset")
            .overload("Torappu.Battle.Entity", "Torappu.Battle.Ability", "System.Func<Torappu.Battle.Entity,System.Boolean>");
        reset.implementation = function (entity: any, ability: any, filter: any) {
            this.method("Reset").invoke(entity, ability, filter);
            if (isAlly(entity)) widen(this.field("m_range").value);
        };
        const updated = cls("Assembly-CSharp", "Torappu.Battle.RangeSelector").method("OnAbilityExtendUpdated").overload("Torappu.FP");
        updated.implementation = function (fp: any) { if (!isAlly(this.method("get_owner").invoke())) this.method("OnAbilityExtendUpdated").invoke(fp); };
    }, () => {
        cls("Assembly-CSharp", "Torappu.Battle.RangeSelector").method("Reset")
            .overload("Torappu.Battle.Entity", "Torappu.Battle.Ability", "System.Func<Torappu.Battle.Entity,System.Boolean>").revert();
        cls("Assembly-CSharp", "Torappu.Battle.RangeSelector").method("OnAbilityExtendUpdated").overload("Torappu.FP").revert();
    });
}

async function main() {
    const ok = await waitForModule(il2cppModuleName(), 10000, 100);
    if (!ok) {
        console.log("err: il2cpp not found");
        return;
    }
    await new Promise(resolve => setTimeout(resolve, 10000));
    Il2Cpp.perform(() => {
        installDumpHooks();
        registerCommands();
    });
}

main();
