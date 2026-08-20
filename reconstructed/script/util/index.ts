// Functional reconstruction utilities for OpenBachelorC Frida scripts.
// Goal: behavior-equivalent implementation, not byte-identical source recovery.

declare const recv: any;
declare const console: any;
declare const setTimeout: any;
declare const Process: any;
declare const Module: any;

type Handler = () => void;

export class ScriptConfig {
    private values = new Map<string, any>();
    private commands = new Map<string, Handler>();

    constructor(initial?: Record<string, any>) {
        if (initial) {
            for (const [k, v] of Object.entries(initial)) this.values.set(k, v);
        }
    }

    set(key: string, value: any) {
        this.values.set(key, value);
    }

    get<T = any>(key: string, fallback?: T): T {
        return this.values.has(key) ? this.values.get(key) : fallback;
    }

    bool(key: string): boolean {
        return !!this.values.get(key);
    }

    number(key: string, fallback: number): number {
        const value = this.values.get(key);
        return typeof value === "number" ? value : fallback;
    }

    command(name: string, fn: Handler) {
        this.commands.set(name, fn);
    }

    invoke(name: string) {
        const fn = this.commands.get(name);
        if (!fn) return false;
        console.log(`info: invoking ${name}`);
        fn();
        return true;
    }

    startRecvLoop() {
        const loop = () => {
            recv("conf", (message: any) => {
                const key = message.k;
                const value = message.v;
                if (key === "invoke") this.invoke(value);
                else this.set(key, value);
                loop();
            });
        };
        loop();
    }

    rpcExports() {
        return {
            init: (_stage: any, parameters: Record<string, any>) => {
                for (const [k, v] of Object.entries(parameters || {})) this.set(k, v);
            },
        };
    }
}

export function safe(name: string, fn: () => void) {
    try {
        fn();
    } catch (e) {
        // Match the released scripts' low-noise behavior: failed hooks are ignored.
        // Uncomment during development if detailed diagnostics are needed.
        // console.log(`warn: hook failed: ${name}: ${e}`);
    }
}

// Hosts that must NEVER be routed through the local forwarding proxy.
// These are SDK / analytics endpoints whose signing + response schema don't
// survive being shipped through localhost. Letting them hit the real server
// keeps the gameupdate / BI prompts quiet while still capturing game traffic.
const PASSTHROUGH_HOST_SUFFIXES = [
    "gameupdate.hypergryph.com",      // HG game-update SDK ("ERROR GAMEUPDATE COMMON" popups here)
    "bi-track.hypergryph.com",         // BI analytics
    "bi-config.hypergryph.com",        // BI config
    "event-log-api-ipv6.hypergryph.com", // noisy telemetry
    "event-log-api-data-lake-prod-cn.hypergryph.com",
];

export function rewriteUrl(url: string, conf: ScriptConfig): string {
    if (conf.bool("no_proxy")) return url;
    const proxyUrl = conf.get<string>("proxy_url", "");
    if (!proxyUrl) return url;
    if (url.startsWith("https://") || url.startsWith("http://")) {
        const hostStart = url.indexOf("://") + 3;
        const pathStart = url.indexOf("/", hostStart);
        const host = pathStart === -1 ? url.substring(hostStart) : url.substring(hostStart, pathStart);
        // Pass SDK / analytics hosts straight to the real server.
        if (PASSTHROUGH_HOST_SUFFIXES.some(suffix => host === suffix || host.endsWith("." + suffix))) {
            return url;
        }
        const path = pathStart === -1 ? "/" : url.substring(pathStart);
        return `${proxyUrl}/${host}${path}`;
    }
    return url;
}

export async function waitForModule(moduleName: string, timeoutMs = 10000, intervalMs = 100): Promise<boolean> {
    const rounds = Math.max(1, Math.ceil(timeoutMs / intervalMs));
    for (let i = 0; i < rounds; i++) {
        if (Process.findModuleByName(moduleName) !== null) return true;
        await new Promise(resolve => setTimeout(resolve, intervalMs));
    }
    return false;
}

export function il2cppModuleName(): string {
    return Process.platform === "windows" ? "GameAssembly.dll" : "libil2cpp.so";
}

export function findGlobalExport(name: string): any {
    if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
    return Module.findExportByName(null, name);
}
