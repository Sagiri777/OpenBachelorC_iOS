// Functional reconstruction of rel/native.js.
// Native / IL2CPP hooks: selected library load suppression, UnityWebRequest proxy rewrite, TLS and RSA verification bypass.

import "frida-il2cpp-bridge";
import { ScriptConfig, findGlobalExport, il2cppModuleName, rewriteUrl, safe, waitForModule } from "../util";

declare const Il2Cpp: any;
declare const Interceptor: any;
declare const NativeFunction: any;
declare const NativeCallback: any;
declare const NULL: any;
declare const rpc: any;
declare const console: any;
declare const setTimeout: any;

const conf = new ScriptConfig();
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

function installDlopenFilter() {
    safe("android_dlopen_ext filter", () => {
        const address = findGlobalExport("android_dlopen_ext");
        if (!address) {
            console.log("native: android_dlopen_ext not found, skipping filter");
            return;
        }
        const real = new NativeFunction(address, "pointer", ["pointer", "int", "pointer"]);
        let lastHandle = NULL;
        Interceptor.replace(address, new NativeCallback((pathPtr: any, flags: number, extinfo: any) => {
            const path = pathPtr.readUtf8String() || "";
            if (path.includes("msaoaidsec") || path.includes("anogs")) return lastHandle;
            const handle = real(pathPtr, flags, extinfo);
            lastHandle = handle;
            return handle;
        }, "pointer", ["pointer", "int", "pointer"]));
        console.log("native: dlopen filter installed");
    });
}

async function installIl2CppHooks() {
    const ok = await waitForModule(il2cppModuleName(), 10000, 100);
    if (!ok) {
        console.log("err: il2cpp not found");
        return;
    }

    // Original bundle waits briefly after module discovery to let IL2CPP initialization settle.
    await new Promise(resolve => setTimeout(resolve, 1000));

    console.log("native: installing IL2CPP hooks...");

    Il2Cpp.perform(() => {
        safe("BouncyCastleCertVerifyer.IsValid", () => {
            Il2Cpp.domain
                .assembly("Torappu.Common")
                .image.class("Torappu.Network.Certificate.CertificateHandlerFactory")
                .nested("BouncyCastleCertVerifyer")
                .method("IsValid")
                .overload("System.Uri", "Org.BouncyCastle.Asn1.X509.X509CertificateStructure[]")
                .implementation = function (_uri: any, certs: any) {
                    return !certs.isNull();
                };
        });

        safe("UnityWebRequest.Get", () => {
            const get = Il2Cpp.domain
                .assembly("UnityEngine.UnityWebRequestModule")
                .image.class("UnityEngine.Networking.UnityWebRequest")
                .method("Get")
                .overload("System.String");
            get.implementation = function (url: any) {
                const original = url.content;
                const rewritten = rewriteUrl(original, conf);
                if (original !== rewritten) {
                    console.log(`UnityWebRequest.Get: ${original} -> ${rewritten}`);
                }
                return get.invoke(Il2Cpp.string(rewritten));
            };
        });

        safe("Torappu.CryptUtils.VerifySignMD5RSA", () => {
            Il2Cpp.domain
                .assembly("Assembly-CSharp")
                .image.class("Torappu.CryptUtils")
                .method("VerifySignMD5RSA")
                .overload("System.String", "System.String", "System.String")
                .implementation = function (_a: any, _b: any, _c: any) { return true; };
        });

        safe("RSACryptoServiceProvider.VerifyHash", () => {
            Il2Cpp.domain
                .assembly("mscorlib")
                .image.class("System.Security.Cryptography.RSACryptoServiceProvider")
                .method("VerifyHash")
                .overload("System.Byte[]", "System.String", "System.Byte[]")
                .implementation = function (_hash: any, _alg: any, _sig: any) { return true; };
        });

        // Unity-level certificate validation bypass — present in unity_capture, needed
        // for games that call ValidateCertificate directly (not via BouncyCastle).
        safe("CertificateHandler.ValidateCertificate", () => {
            Il2Cpp.domain
                .assembly("UnityEngine.UnityWebRequestModule")
                .image.class("UnityEngine.Networking.CertificateHandler")
                .method("ValidateCertificate")
                .overload("System.Byte[]")
                .implementation = function (_cert: any) { return true; };
        });

        // Hook UnityWebRequest.Post to intercept POST requests (e.g. syncData).
        // The original bundle only hooks Get; adding Post ensures POST-based API
        // calls are also rewritten through the proxy.
        safe("UnityWebRequest.Post(string,string)", () => {
            const UnityWebRequest = Il2Cpp.domain
                .assembly("UnityEngine.UnityWebRequestModule")
                .image.class("UnityEngine.Networking.UnityWebRequest");

            const post = UnityWebRequest.method("Post").overload("System.String", "System.String");
            post.implementation = function (url: any, postData: any) {
                console.log(`UnityWebRequest.Post: ${url.content}`);
                return post.invoke(Il2Cpp.string(rewriteUrl(url.content, conf)), postData);
            };
        });

        safe("UnityWebRequest.Post(string,byte[])", () => {
            const UnityWebRequest = Il2Cpp.domain
                .assembly("UnityEngine.UnityWebRequestModule")
                .image.class("UnityEngine.Networking.UnityWebRequest");

            const postRaw = UnityWebRequest.method("Post").overload("System.String", "System.Byte[]");
            postRaw.implementation = function (url: any, bodyRaw: any) {
                console.log(`UnityWebRequest.Post(raw): ${url.content}`);
                return postRaw.invoke(Il2Cpp.string(rewriteUrl(url.content, conf)), bodyRaw);
            };
        });

        // Many paths on recent Unity (notably 2021+) build a UnityWebRequest and
        // then assign the .url property instead of passing it to Get/Post ctor.
        // set_url is the IL2CPP-generated property setter — hooking it ensures
        // any later "req.url = '...'" rewrites too.
        safe("UnityWebRequest.set_url property rewrite", () => {
            try {
                const UnityWebRequest = Il2Cpp.domain
                    .assembly("UnityEngine.UnityWebRequestModule")
                    .image.class("UnityEngine.Networking.UnityWebRequest");
                const setter = UnityWebRequest.method("set_url").overload("System.String");
                setter.implementation = function (url: any) {
                    const original = String(url);
                    const rewritten = rewriteUrl(original, conf);
                    if (original !== rewritten) console.log(`UnityWebRequest.set_url: ${original} -> ${rewritten}`);
                    // frida-il2cpp-bridge: non-static methods must be invoked through
                    // an Il2Cpp.Object instance, NOT via the static class method.
                    // `this` IS the instance inside this implementation.
                    return this.method("set_url").invoke(Il2Cpp.string(rewritten));
                };
            } catch (e) { console.log(`[warn] UnityWebRequest.set_url not found: ${e}`); }
        });

        // Some games use UnityWebRequest via the ctor directly:
        //   new UnityWebRequest(url, "GET")
        // The static Get/Post helpers wrap that, but raw ctors aren't covered
        // by the helper hooks above. Hook the .ctor(string,string) signature.
        safe("UnityWebRequest ctor(string,string) URL rewrite", () => {
            try {
                const UnityWebRequest = Il2Cpp.domain
                    .assembly("UnityEngine.UnityWebRequestModule")
                    .image.class("UnityEngine.Networking.UnityWebRequest");
                const ctor = UnityWebRequest.method(".ctor").overload("System.String", "System.String");
                ctor.implementation = function (url: any, method: any) {
                    const original = String(url);
                    const rewritten = rewriteUrl(original, conf);
                    if (original !== rewritten) console.log(`UnityWebRequest.ctor: ${original} -> ${rewritten}`);
                    // ctor is non-static — invoke through `this`, not via the class.
                    return this.method(".ctor").invoke(Il2Cpp.string(rewritten), method);
                };
            } catch (e) { console.log(`[warn] UnityWebRequest ctor not found: ${e}`); }
        });

        // Diagnostic tracer on SendWebRequest so we can see what URLs actually
        // fired after all rewrites (no rewrite here, just logging).
        safe("UnityWebRequest.SendWebRequest tracer", () => {
            try {
                const UnityWebRequest = Il2Cpp.domain
                    .assembly("UnityEngine.UnityWebRequestModule")
                    .image.class("UnityEngine.Networking.UnityWebRequest");
                const send = UnityWebRequest.method("SendWebRequest").overload();
                send.implementation = function () {
                    try {
                        const u = this.field("url").value;
                        console.log(`UnityWebRequest.Send: ${u ? u.content : "<no url>"}`);
                    } catch (_) {}
                    // non-static — go through the instance.
                    return this.method("SendWebRequest").invoke();
                };
            } catch (e) {}
        });

        console.log("native: IL2CPP hooks installed (proxy_url=" + conf.get("proxy_url", "none") + ", no_proxy=" + conf.bool("no_proxy") + ")");
    });
}

installDlopenFilter();
installIl2CppHooks();
