declare const recv: any;
declare const console: any;

type Handler = () => void;

const PASSTHROUGH_HOST_SUFFIXES = [
    "gameupdate.hypergryph.com",
    "bi-track.hypergryph.com",
    "bi-config.hypergryph.com",
    "event-log-api-ipv6.hypergryph.com",
    "event-log-api-data-lake-prod-cn.hypergryph.com",
];

export class ScriptConfig {
    private values = new Map<string, any>();
    private commands = new Map<string, Handler>();
    private pendingCommands: string[] = [];

    constructor(initial?: Record<string, any>) {
        for (const [key, value] of Object.entries(initial || {})) {
            this.values.set(key, value);
        }
    }

    set(key: string, value: any) {
        this.values.set(key, value);
    }

    get<T = any>(key: string, fallback?: T): T {
        return this.values.has(key) ? this.values.get(key) as T : fallback as T;
    }

    bool(key: string, fallback = false): boolean {
        return this.values.has(key) ? !!this.values.get(key) : fallback;
    }

    number(key: string, fallback: number): number {
        const value = this.values.get(key);
        return typeof value === "number" ? value : fallback;
    }

    command(name: string, fn: Handler) {
        this.commands.set(name, fn);
        if (this.pendingCommands.includes(name)) {
            this.pendingCommands = this.pendingCommands.filter(item => item !== name);
            this.invoke(name);
        }
    }

    invoke(name: string): boolean {
        const fn = this.commands.get(name);
        if (!fn) {
            if (!this.pendingCommands.includes(name)) this.pendingCommands.push(name);
            console.log(`info: queued command ${name}`);
            return false;
        }
        console.log(`info: invoking ${name}`);
        fn();
        return true;
    }

    startRecvLoop() {
        const loop = () => {
            recv("conf", (message: any) => {
                if (message.k === "invoke") this.invoke(String(message.v));
                else this.set(String(message.k), message.v);
                loop();
            });
        };
        loop();
    }

    rpcExports() {
        return {
            init: (_stage: any, parameters: Record<string, any>) => {
                for (const [key, value] of Object.entries(parameters || {})) {
                    this.set(key, value);
                }
            },
        };
    }
}

export function safe(name: string, fn: () => void): boolean {
    try {
        fn();
        return true;
    } catch (error) {
        console.log(`warn: ${name}: ${error}`);
        return false;
    }
}

export function rewriteUrl(url: string, conf: ScriptConfig): string {
    if (conf.bool("no_proxy", true)) return url;
    const proxyUrl = conf.get<string>("proxy_url", "").replace(/\/$/, "");
    if (!proxyUrl || (!url.startsWith("https://") && !url.startsWith("http://"))) {
        return url;
    }
    if (
        url === proxyUrl
        || url.startsWith(`${proxyUrl}/`)
        || url.startsWith(`${proxyUrl}?`)
        || url.startsWith(`${proxyUrl}#`)
    ) {
        return url;
    }

    const hostStart = url.indexOf("://") + 3;
    const scheme = url.substring(0, hostStart - 3).toLowerCase();
    const suffixStarts = ["/", "?", "#"]
        .map(marker => url.indexOf(marker, hostStart))
        .filter(index => index !== -1);
    const pathStart = suffixStarts.length === 0 ? url.length : Math.min(...suffixStarts);
    const host = url.substring(hostStart, pathStart);
    if (
        !conf.bool("proxy_include_passthrough", false)
        && PASSTHROUGH_HOST_SUFFIXES.some(suffix => host === suffix || host.endsWith(`.${suffix}`))
    ) {
        return url;
    }
    const suffix = url.substring(pathStart);
    const path = !suffix ? "/" : suffix.startsWith("/") ? suffix : `/${suffix}`;
    if (conf.bool("proxy_encode_scheme", false)) {
        return `${proxyUrl}/__openbachelor_proxy__/${scheme}/${host}${path}`;
    }
    return `${proxyUrl}/${host}${path}`;
}

export function managedString(value: any): string {
    if (value === null || value === undefined || value.isNull?.()) return "";
    return typeof value.content === "string" ? value.content : String(value);
}

export async function delay(milliseconds: number): Promise<void> {
    await new Promise(resolve => setTimeout(resolve, milliseconds));
}
