export {};

declare const send: any;

function report(module: Module): void {
    const exports = [
        "il2cpp_get_corlib",
        "il2cpp_domain_get",
        "il2cpp_domain_get_assemblies",
        "il2cpp_string_new",
    ];
    const resolved = Object.fromEntries(
        exports.map(name => [name, module.findExportByName(name) !== null]),
    );
    send({
        event: "probe",
        platform: Process.platform,
        arch: Process.arch,
        module: module.name,
        module_base: module.base.toString(),
        module_size: module.size,
        il2cpp_exports: resolved,
        stripped: !resolved.il2cpp_get_corlib,
    });
}

const existing = Process.findModuleByName("UnityFramework");
if (existing !== null) {
    report(existing);
} else {
    send({ event: "probe-waiting", module: "UnityFramework" });
    const timer = setInterval(() => {
        const module = Process.findModuleByName("UnityFramework");
        if (module === null) return;
        clearInterval(timer);
        report(module);
    }, 25);
}
