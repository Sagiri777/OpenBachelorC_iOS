// Unity + Java internal request capture.
// Rewrites ALL game HTTP/HTTPS URLs to plain HTTP on a local forwarding proxy,
// completely avoiding TLS issues.  The forwarding proxy logs every request/response.
//
// Original: https://game-config.hypergryph.com/path
// Rewritten: http://127.0.0.1:8443/game-config.hypergryph.com/path

import Java from "frida-java-bridge";
import "frida-il2cpp-bridge";
import { ScriptConfig, findGlobalExport, il2cppModuleName, rewriteUrl, safe, waitForModule } from "../util";

declare const Il2Cpp: any;
declare const Interceptor: any;
declare const NativeFunction: any;
declare const NativeCallback: any;
declare const NULL: any;
declare const console: any;
declare const rpc: any;
declare const setTimeout: any;

const PROXY_URL = "http://127.0.0.1:8443";

function rewriteToProxy(originalUrl: string): string {
    // Rewrite https://host/path → http://127.0.0.1:8443/host/path
    // The forwarding proxy reads the first path segment as the upstream host.
    if (originalUrl.startsWith("https://") || originalUrl.startsWith("http://")) {
        const schemeEnd = originalUrl.indexOf("://") + 3;
        const hostStart = schemeEnd;
        const pathStart = originalUrl.indexOf("/", hostStart);
        if (pathStart === -1) return `${PROXY_URL}/${originalUrl.substring(hostStart)}/`;
        return `${PROXY_URL}/${originalUrl.substring(hostStart)}`;
    }
    return originalUrl;
}

const conf = new ScriptConfig({
    no_proxy: false,
    proxy_url: PROXY_URL,
});
conf.startRecvLoop();
rpc.exports = conf.rpcExports();

function installJavaCaptureHooks() {
    Java.perform(() => {
        safe("gameupdate TrustAllCerts.checkServerTrusted", () => {
            Java.use("com.hypergryph.gameupdate.utils.OkHttpUtils$TrustAllCerts")
                .checkServerTrusted.implementation = function (_chain: any, _authType: any) { };
        });
        safe("hgsdk NetworkService TrustAllCerts.checkServerTrusted", () => {
            Java.use("com.hypergryph.platform.hgsdk.http.NetworkService$TrustAllCerts")
                .checkServerTrusted.implementation = function (_chain: any, _authType: any) { };
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
        safe("cleartext policy", () => {
            const Policy = Java.use("android.security.net.config.ConfigNetworkSecurityPolicy");
            Policy.isCleartextTrafficPermitted.overload().implementation = () => true;
            Policy.isCleartextTrafficPermitted.overload("java.lang.String").implementation = (_h: string) => true;
        });
        safe("NetworkSecurityPolicy.setInstance", () => {
            Java.use("libcore.net.NetworkSecurityPolicy").setInstance.implementation = function (_p: any) { };
        });
        safe("hgsdk Util.check", () => {
            Java.use("com.hypergryph.platform.hgsdk.common.utils.Util")
                .check.implementation = function (_ctx: any) { return true; };
        });
        safe("MTPProxyApplication onProxyCreate", () => {
            Java.use("com.hg.sdk.MTPProxyApplication").onProxyCreate.implementation = function () { };
        });
        safe("MTPDetection onUserLogin", () => {
            Java.use("com.hg.sdk.MTPDetection").onUserLogin.implementation = function (_a: any, _b: any, _c: any, _d: any) { };
        });
        safe("OAID/tracking noise", () => {
            Java.use("com.hypergryph.eventlog.utils.Utils")._GetOAID.implementation = function (_ctx: any) { };
            Java.use("com.hypergryph.gamebi.Utils")._GetOAID.implementation = function (_ctx: any) { };
            Java.use("com.reyun.tracking.sdk.Tracking").activation.implementation = function () { };
        });

        safe("okhttp3.HttpUrl.get URL rewrite", () => {
            const HttpUrl = Java.use("okhttp3.HttpUrl");
            const getString = HttpUrl.get.overload("java.lang.String");
            getString.implementation = function (url: string) {
                const newUrl = rewriteToProxy(url);
                console.log(`okhttp: ${url} -> ${newUrl}`);
                return getString.call(this, newUrl);
            };
        });

        console.log("unity_capture: Java capture hooks installed");
    });
}

function installNativeLoadFilter() {
    safe("android_dlopen_ext filter", () => {
        const address = findGlobalExport("android_dlopen_ext");
        if (!address) return;
        const real = new NativeFunction(address, "pointer", ["pointer", "int", "pointer"]);
        let lastHandle = NULL;
        Interceptor.replace(address, new NativeCallback((pathPtr: any, flags: number, extinfo: any) => {
            const path = pathPtr.readUtf8String() || "";
            if (path.includes("msaoaidsec") || path.includes("anogs")) return lastHandle;
            const handle = real(pathPtr, flags, extinfo);
            lastHandle = handle;
            return handle;
        }, "pointer", ["pointer", "int", "pointer"]));
    });
}

async function installUnityCaptureHooks() {
    const ok = await waitForModule(il2cppModuleName(), 10000, 100);
    if (!ok) {
        console.log("unity_capture: il2cpp not found, Java hooks only");
        return;
    }
    await new Promise(resolve => setTimeout(resolve, 1000));

    Il2Cpp.perform(() => {
        safe("BouncyCastleCertVerifyer.IsValid", () => {
            Il2Cpp.domain
                .assembly("Torappu.Common")
                .image.class("Torappu.Network.Certificate.CertificateHandlerFactory")
                .nested("BouncyCastleCertVerifyer")
                .method("IsValid")
                .overload("System.Uri", "Org.BouncyCastle.Asn1.X509.X509CertificateStructure[]")
                .implementation = function (_uri: any, certs: any) { return !certs.isNull(); };
        });
        safe("VerifySignMD5RSA", () => {
            Il2Cpp.domain.assembly("Assembly-CSharp").image.class("Torappu.CryptUtils")
                .method("VerifySignMD5RSA").overload("System.String", "System.String", "System.String")
                .implementation = function (_a: any, _b: any, _c: any) { return true; };
        });
        safe("RSACryptoServiceProvider.VerifyHash", () => {
            Il2Cpp.domain.assembly("mscorlib").image.class("System.Security.Cryptography.RSACryptoServiceProvider")
                .method("VerifyHash").overload("System.Byte[]", "System.String", "System.Byte[]")
                .implementation = function (_hash: any, _alg: any, _sig: any) { return true; };
        });
        safe("CertificateHandler.ValidateCertificate", () => {
            Il2Cpp.domain.assembly("UnityEngine.UnityWebRequestModule")
                .image.class("UnityEngine.Networking.CertificateHandler")
                .method("ValidateCertificate").overload("System.Byte[]")
                .implementation = function (_cert: any) { return true; };
        });

        const UnityWebRequest = Il2Cpp.domain
            .assembly("UnityEngine.UnityWebRequestModule")
            .image.class("UnityEngine.Networking.UnityWebRequest");

        safe("UnityWebRequest.Get URL rewrite", () => {
            const get = UnityWebRequest.method("Get").overload("System.String");
            get.implementation = function (url: any) {
                const original = url.content;
                const rewritten = rewriteToProxy(original);
                console.log(`UnityWebRequest.Get: ${original} -> ${rewritten}`);
                return this.method("Get").invoke(Il2Cpp.string(rewritten));
            };
        });

        console.log("unity_capture: IL2CPP capture hooks installed");
    });
}

installNativeLoadFilter();
installJavaCaptureHooks();
installUnityCaptureHooks();
