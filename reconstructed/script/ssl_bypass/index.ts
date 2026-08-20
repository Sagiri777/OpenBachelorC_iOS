// Dedicated SSL / certificate pinning bypass for packet capture.
// This script intentionally does NOT rewrite URLs and does NOT enable trainer/gameplay hooks.

import Java from "frida-java-bridge";
import "frida-il2cpp-bridge";
import { findGlobalExport, il2cppModuleName, safe, waitForModule } from "../util";

declare const Il2Cpp: any;
declare const Interceptor: any;
declare const NativeFunction: any;
declare const NativeCallback: any;
declare const NULL: any;
declare const console: any;
declare const rpc: any;
declare const setTimeout: any;

rpc.exports = {
    init() { }
};

function installJavaSslBypass() {
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

        safe("ConfigNetworkSecurityPolicy.isCleartextTrafficPermitted", () => {
            const Policy = Java.use("android.security.net.config.ConfigNetworkSecurityPolicy");
            Policy.isCleartextTrafficPermitted.overload().implementation = function () { return true; };
            Policy.isCleartextTrafficPermitted.overload("java.lang.String").implementation = function (_host: string) { return true; };
        });

        safe("NetworkSecurityPolicy.setInstance", () => {
            Java.use("libcore.net.NetworkSecurityPolicy").setInstance.implementation = function (_policy: any) { };
        });

        safe("hgsdk Util.check", () => {
            Java.use("com.hypergryph.platform.hgsdk.common.utils.Util").check.implementation = function (_ctx: any) {
                return true;
            };
        });

        console.log("ssl_bypass: Java SSL hooks installed");
    });
}

function installNativeLoadFilter() {
    // Keep the same light native anti-detection filter from native.js. It helps the SSL hooks survive
    // on builds that load extra detection libraries, but does not modify gameplay or URLs.
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

async function installIl2CppSslBypass() {
    const ok = await waitForModule(il2cppModuleName(), 10000, 100);
    if (!ok) {
        console.log("ssl_bypass: il2cpp not found, Java hooks only");
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
                .implementation = function (_uri: any, certs: any) {
                    return !certs.isNull();
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

        console.log("ssl_bypass: IL2CPP SSL/signature hooks installed");
    });
}

installNativeLoadFilter();
installJavaSslBypass();
installIl2CppSslBypass();
