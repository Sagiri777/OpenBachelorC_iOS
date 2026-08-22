// iOS IL2CPP hooks.

import "frida-il2cpp-bridge";
import { ScriptConfig, managedString, rewriteUrl, safe } from "./util";

declare const Il2Cpp: any;
declare const rpc: any;
declare const send: any;
declare const console: any;

const conf = new ScriptConfig({ no_proxy: true, proxy_url: "" });
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

void Il2Cpp.perform(() => {
    let installed = 0;
    const hook = (name: string, installer: () => void) => {
        if (safe(name, installer)) installed += 1;
    };

    hook("BouncyCastleCertVerifyer.IsValid", () => {
        Il2Cpp.domain
            .assembly("Torappu.Common")
            .image.class("Torappu.Network.Certificate.CertificateHandlerFactory")
            .nested("BouncyCastleCertVerifyer")
            .method("IsValid")
            .overload(
                "System.Uri",
                "Org.BouncyCastle.Asn1.X509.X509CertificateStructure[]",
            ).implementation = function (_uri: any, certs: any) {
                return !certs.isNull();
            };
    });

    hook("UnityWebRequest.Get", () => {
        const get = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest")
            .method("Get")
            .overload("System.String");
        get.implementation = function (url: any) {
            const original = managedString(url);
            const rewritten = rewriteUrl(original, conf);
            if (original !== rewritten) {
                console.log(`UnityWebRequest.Get: ${original} -> ${rewritten}`);
            }
            return get.invoke(Il2Cpp.string(rewritten));
        };
    });

    hook("UnityWebRequest.Post(string,string)", () => {
        const post = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest")
            .method("Post")
            .overload("System.String", "System.String");
        post.implementation = function (url: any, data: any) {
            const original = managedString(url);
            const rewritten = rewriteUrl(original, conf);
            if (original !== rewritten) {
                console.log(`UnityWebRequest.Post: ${original} -> ${rewritten}`);
            }
            return post.invoke(Il2Cpp.string(rewritten), data);
        };
    });

    hook("UnityWebRequest.Post(string,byte[])", () => {
        const post = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest")
            .method("Post")
            .overload("System.String", "System.Byte[]");
        post.implementation = function (url: any, data: any) {
            const original = managedString(url);
            const rewritten = rewriteUrl(original, conf);
            if (original !== rewritten) {
                console.log(`UnityWebRequest.Post(raw): ${original} -> ${rewritten}`);
            }
            return post.invoke(Il2Cpp.string(rewritten), data);
        };
    });

    hook("UnityWebRequest.set_url", () => {
        const request = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest");
        const setter = request.method("set_url").overload("System.String");
        setter.implementation = function (url: any) {
            const original = managedString(url);
            const rewritten = rewriteUrl(original, conf);
            if (original !== rewritten) {
                console.log(`UnityWebRequest.set_url: ${original} -> ${rewritten}`);
            }
            return this.method("set_url").invoke(Il2Cpp.string(rewritten));
        };
    });

    hook("UnityWebRequest.ctor", () => {
        const request = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest");
        const ctor = request
            .method(".ctor")
            .overload("System.String", "System.String");
        ctor.implementation = function (url: any, method: any) {
            const original = managedString(url);
            const rewritten = rewriteUrl(original, conf);
            if (original !== rewritten) {
                console.log(`UnityWebRequest.ctor: ${original} -> ${rewritten}`);
            }
            return this.method(".ctor").invoke(Il2Cpp.string(rewritten), method);
        };
    });

    hook("UnityWebRequest.SendWebRequest", () => {
        const request = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest");
        const sendRequest = request.method("SendWebRequest").overload();
        sendRequest.implementation = function () {
            try {
                const url = this.method("get_url").invoke();
                console.log(`UnityWebRequest.Send: ${managedString(url)}`);
            } catch (_) {
                // URL logging is diagnostic only.
            }
            return this.method("SendWebRequest").invoke();
        };
    });

    hook("CertificateHandler.ValidateCertificate", () => {
        Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.CertificateHandler")
            .method("ValidateCertificate")
            .overload("System.Byte[]").implementation = function (_cert: any) {
                return true;
            };
    });

    hook("Torappu.CryptUtils.VerifySignMD5RSA", () => {
        Il2Cpp.domain
            .assembly("Assembly-CSharp")
            .image.class("Torappu.CryptUtils")
            .method("VerifySignMD5RSA")
            .overload(
                "System.String",
                "System.String",
                "System.String",
            ).implementation = function (_a: any, _b: any, _c: any) {
                return true;
            };
    });

    hook("RSACryptoServiceProvider.VerifyHash", () => {
        Il2Cpp.domain
            .assembly("mscorlib")
            .image.class("System.Security.Cryptography.RSACryptoServiceProvider")
            .method("VerifyHash")
            .overload(
                "System.Byte[]",
                "System.String",
                "System.Byte[]",
            ).implementation = function (_hash: any, _alg: any, _sig: any) {
                return true;
            };
    });

    send({
        event: "core-ready",
        platform: Process.platform,
        module: Il2Cpp.module.name,
        hooks_installed: installed,
    });
});
