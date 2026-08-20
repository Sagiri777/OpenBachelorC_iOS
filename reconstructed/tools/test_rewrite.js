#!/usr/bin/env node
// Test the URL rewrite logic used in the Frida scripts.
// This verifies the rewriteUrl function produces correct output for various URL formats.

function rewriteUrl(url, conf) {
    if (conf.no_proxy) return url;
    const proxyUrl = conf.proxy_url;
    if (!proxyUrl) return url;
    if (url.startsWith("https://") || url.startsWith("http://")) {
        const hostStart = url.indexOf("://") + 3;
        const pathStart = url.indexOf("/", hostStart);
        const host = pathStart === -1 ? url.substring(hostStart) : url.substring(hostStart, pathStart);
        const path = pathStart === -1 ? "/" : url.substring(pathStart);
        return `${proxyUrl}/${host}${path}`;
    }
    return url;
}

const conf = { proxy_url: "http://127.0.0.1:8443", no_proxy: false };

const tests = [
    // [input, expected_output, description]
    ["https://ak-gs.hypergryph.com/api/syncData", "http://127.0.0.1:8443/ak-gs.hypergryph.com/api/syncData", "syncData POST endpoint"],
    ["https://ak-gs.hypergryph.com/online/v2/config", "http://127.0.0.1:8443/ak-gs.hypergryph.com/online/v2/config", "game config endpoint"],
    ["https://ak-as.hypergryph.com/user/login", "http://127.0.0.1:8443/ak-as.hypergryph.com/user/login", "login endpoint"],
    ["https://launcher.hypergryph.com/api/game/get_latest_game_info?appcode=test", "http://127.0.0.1:8443/launcher.hypergryph.com/api/game/get_latest_game_info?appcode=test", "launcher API with query"],
    ["https://ak-gs.hypergryph.com/", "http://127.0.0.1:8443/ak-gs.hypergryph.com/", "root path"],
    ["https://ak-gs.hypergryph.com", "http://127.0.0.1:8443/ak-gs.hypergryph.com/", "no trailing slash"],
    ["http://example.com/path", "http://127.0.0.1:8443/example.com/path", "http scheme"],
    ["https://game-config.hypergryph.com/api/remote_config/v1/config", "http://127.0.0.1:8443/game-config.hypergryph.com/api/remote_config/v1/config", "remote config"],
    ["https://ak-webview.hypergryph.com/api/gate/meta/Android", "http://127.0.0.1:8443/ak-webview.hypergryph.com/api/gate/meta/Android", "webview API"],
    ["relative/path", "relative/path", "relative URL (no rewrite)"],
];

let passed = 0;
let failed = 0;

console.log("Testing URL rewrite logic...\n");

for (const [input, expected, desc] of tests) {
    const result = rewriteUrl(input, conf);
    if (result === expected) {
        console.log(`✓ ${desc}`);
        console.log(`  ${input} -> ${result}`);
        passed++;
    } else {
        console.log(`✗ ${desc}`);
        console.log(`  Input:    ${input}`);
        console.log(`  Expected: ${expected}`);
        console.log(`  Got:      ${result}`);
        failed++;
    }
}

console.log(`\nResults: ${passed} passed, ${failed} failed`);

// Test with no_proxy=true
const confNoProxy = { proxy_url: "http://127.0.0.1:8443", no_proxy: true };
const noProxyResult = rewriteUrl("https://ak-gs.hypergryph.com/api/syncData", confNoProxy);
if (noProxyResult === "https://ak-gs.hypergryph.com/api/syncData") {
    console.log("\n✓ no_proxy=true correctly skips rewrite");
} else {
    console.log("\n✗ no_proxy=true failed");
    failed++;
}

// Test with empty proxy_url
const confNoUrl = { proxy_url: "", no_proxy: false };
const noUrlResult = rewriteUrl("https://ak-gs.hypergryph.com/api/syncData", confNoUrl);
if (noUrlResult === "https://ak-gs.hypergryph.com/api/syncData") {
    console.log("✓ empty proxy_url correctly skips rewrite");
} else {
    console.log("✗ empty proxy_url failed");
    failed++;
}

process.exit(failed > 0 ? 1 : 0);
