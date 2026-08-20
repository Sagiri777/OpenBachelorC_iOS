// Functional reconstruction of rel/java.js.
// Java-layer hooks: SDK noise suppression, proxy URL rewrite, and TLS / cleartext policy bypass.

import Java from "frida-java-bridge";

declare const rpc: any;

import { ScriptConfig, rewriteUrl, safe } from "../util";

const conf = new ScriptConfig();
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

function hookNoArgVoid(className: string, methodName: string) {
    safe(`${className}.${methodName}`, () => {
        Java.use(className)[methodName].implementation = function () { };
    });
}

function installHooks() {
    console.log("java: installing hooks...");

    // The original bundle calls Java.deoptimizeEverything() inside a try/catch.
    // This ART-level optimization can fail on some emulator configurations
    // ("Unable to determine Instrumentation field offsets"), but method
    // replacement still works without it.  We replicate the try/catch to
    // match the original behavior exactly.
    safe("deoptimizeEverything", () => {
        Java.deoptimizeEverything();
    });

    hookNoArgVoid("com.hypergryph.eventlog.utils.Utils", "_GetOAID");
    hookNoArgVoid("com.hypergryph.gamebi.Utils", "_GetOAID");
    hookNoArgVoid("com.reyun.tracking.sdk.Tracking", "activation");

    safe("hgsdk Util.check", () => {
        Java.use("com.hypergryph.platform.hgsdk.common.utils.Util").check.implementation = function (_ctx: any) {
            return true;
        };
    });

    safe("gameupdate TrustAllCerts", () => {
        Java.use("com.hypergryph.gameupdate.utils.OkHttpUtils$TrustAllCerts").checkServerTrusted.implementation = function (_chain: any, _authType: any) { };
    });

    safe("hgsdk NetworkService TrustAllCerts", () => {
        Java.use("com.hypergryph.platform.hgsdk.http.NetworkService$TrustAllCerts").checkServerTrusted.implementation = function (_chain: any, _authType: any) { };
    });

    // Comprehensively rewrite every okhttp URL-construction entry point.
    // The original bundle only hooked HttpUrl.get(String); some games route through
    // HttpUrl.parse, Request$Builder.url, or the Kotlin @JvmStatic static variant,
    // which all bypass that single hook.
    safe("okhttp3.HttpUrl.get all overloads + parse", () => {
        const rewriteAndLog = (rawUrl: any): string => {
            try {
                const u = String(rawUrl);
                const r = rewriteUrl(u, conf);
                if (u && u !== r) console.log(`okhttp: ${u} -> ${r}`);
                return r;
            } catch (e) { return String(rawUrl); }
        };
        const HttpUrl = Java.use("okhttp3.HttpUrl");
        // 1) HttpUrl.get(String) — original hook
        HttpUrl.get.overload("java.lang.String").implementation = function (url: string) {
            return HttpUrl.get.call(this, rewriteAndLog(url));
        };
        // 2) HttpUrl.parse(String) — second static entry many games use
        try {
            HttpUrl.parse.overload("java.lang.String").implementation = function (url: string) {
                return HttpUrl.parse.call(this, rewriteAndLog(url));
            };
        } catch (e) { console.log(`[warn] HttpUrl.parse(String) overload not found: ${e}`); }
        // 3) Request$Builder.url(String) — Builder-style API
        try {
            const Builder = Java.use("okhttp3.Request$Builder");
            Builder.url.overload("java.lang.String").implementation = function (url: string) {
                return Builder.url.call(this, rewriteAndLog(url));
            };
        } catch (e) { console.log(`[warn] Request$Builder.url(String) overload not found: ${e}`); }
        // 4) Request$Builder.url(HttpUrl) — pass-through, just for visibility
        try {
            const Builder = Java.use("okhttp3.Request$Builder");
            Builder.url.overload("okhttp3.HttpUrl").implementation = function (u: any) {
                console.log(`okhttp: Request$Builder.url(HttpUrl) -> ${u.toString()}`);
                return Builder.url.call(this, u);
            };
        } catch (e) {}
        // 5) Kotlin companion @JvmStatic
        try {
            const Companion = Java.use("okhttp3.HttpUrl$Companion");
            if (Companion.get) {
                Companion.get.overload("java.lang.String").implementation = function (url: string) {
                    const out = Companion.get.call(this, rewriteAndLog(url));
                    return out;
                };
            }
            if (Companion.parse) {
                Companion.parse.overload("java.lang.String").implementation = function (url: string) {
                    const out = Companion.parse.call(this, rewriteAndLog(url));
                    return out;
                };
            }
        } catch (e) {}
    });

    // WebView-based URL fetching — some games (or some screens like login) use
    // WebView.loadUrl / WebView.postUrl for config or auth flows.
    safe("WebView.loadUrl URL rewrite", () => {
        try {
            const WebView = Java.use("android.webkit.WebView");
            WebView.loadUrl.overload("java.lang.String").implementation = function (url: string) {
                const u = rewriteUrl(url, conf);
                if (url && url !== u) console.log(`webview: ${url} -> ${u}`);
                return WebView.loadUrl.call(this, u);
            };
            WebView.postUrl.overload("java.lang.String", "[B").implementation = function (url: string, data: any) {
                const u = rewriteUrl(url, conf);
                if (url && url !== u) console.log(`webview-post: ${url} -> ${u}`);
                return WebView.postUrl.call(this, u, data);
            };
        } catch (e) { console.log(`[warn] WebView hooks not installed: ${e}`); }
    });

    // Last-resort: rewrite java.net.URL constructors (used by HttpURLConnection,
    // some legacy paths, and some H5 screens).
    safe("java.net.URL constructor URL rewrite", () => {
        try {
            const URL = Java.use("java.net.URL");
            URL.$init.overload("java.lang.String").implementation = function (url: string) {
                const u = rewriteUrl(url, conf);
                if (url && url !== u) console.log(`javaurl: ${url} -> ${u}`);
                return URL.$init.call(this, u);
            };
        } catch (e) { console.log(`[warn] java.net.URL hook failed: ${e}`); }
    });

    // okhttp3.OkHttpClient: leave a tracer on newCall so we can see what URLs
    // actually fly after all upstream rewrites. (read-only, not a rewrite.)
    safe("okhttp3.OkHttpClient newCall tracer", () => {
        try {
            const O = Java.use("okhttp3.OkHttpClient");
            const Call = Java.use("okhttp3.Call");
            O.newCall.overload("okhttp3.Request").implementation = function (req: any) {
                try {
                    const u = req.url();
                    console.log(`okhttp-newCall: ${u.toString()}`);
                } catch (_) {}
                return O.newCall.call(this, req);
            };
        } catch (e) {}
    });

    hookNoArgVoid("com.hg.sdk.MTPProxyApplication", "onProxyCreate");

    safe("MTPDetection.onUserLogin", () => {
        Java.use("com.hg.sdk.MTPDetection").onUserLogin.implementation = function (_a: any, _b: any, _c: any, _d: any) { };
    });

    safe("NetworkSecurityPolicy.setInstance", () => {
        Java.use("libcore.net.NetworkSecurityPolicy").setInstance.implementation = function (_policy: any) { };
    });

    safe("ConfigNetworkSecurityPolicy.isCleartextTrafficPermitted", () => {
        const Policy = Java.use("android.security.net.config.ConfigNetworkSecurityPolicy");
        Policy.isCleartextTrafficPermitted.overload().implementation = function () { return true; };
        Policy.isCleartextTrafficPermitted.overload("java.lang.String").implementation = function (_host: string) { return true; };
    });

    safe("TrustManagerImpl.checkTrusted", () => {
        const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
        const ArrayList = Java.use("java.util.ArrayList");
        TrustManagerImpl.checkTrusted
            .overload("[Ljava.security.cert.X509Certificate;", "[B", "[B", "java.lang.String", "java.lang.String", "boolean")
            .implementation = function (_chain: any, _ocsp: any, _sct: any, _authType: string, _host: string, _client: boolean) {
                return ArrayList.$new();
            };
    });

    console.log("java: hooks installed (proxy_url=" + conf.get("proxy_url", "none") + ", no_proxy=" + conf.bool("no_proxy") + ")");
}

Java.perform(installHooks);
