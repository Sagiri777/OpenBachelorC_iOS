#!/usr/bin/env node
// Test the forwarding proxy's URL parsing logic.
// This simulates how the proxy extracts the upstream host from the rewritten URL.

function parseProxyPath(path) {
    path = path.startsWith("/") ? path.slice(1) : path;
    if (!path.includes("/")) {
        return { host: path, rest: "" };
    }
    const slashIdx = path.indexOf("/");
    return {
        host: path.substring(0, slashIdx),
        rest: path.substring(slashIdx + 1),
    };
}

function buildUpstreamUrl(scheme, path) {
    const { host, rest } = parseProxyPath(path);
    return `${scheme}://${host}/${rest}`;
}

const tests = [
    // [rewritten_path, expected_host, expected_upstream]
    ["/ak-gs.hypergryph.com/api/syncData", "ak-gs.hypergryph.com", "https://ak-gs.hypergryph.com/api/syncData"],
    ["/ak-gs.hypergryph.com/online/v2/config", "ak-gs.hypergryph.com", "https://ak-gs.hypergryph.com/online/v2/config"],
    ["/launcher.hypergryph.com/api/game/get_latest_game_info?appcode=test", "launcher.hypergryph.com", "https://launcher.hypergryph.com/api/game/get_latest_game_info?appcode=test"],
    ["/ak-gs.hypergryph.com/", "ak-gs.hypergryph.com", "https://ak-gs.hypergryph.com/"],
    ["/ak-gs.hypergryph.com", "ak-gs.hypergryph.com", "https://ak-gs.hypergryph.com/"],
    ["/game-config.hypergryph.com/api/remote_config/v1/config", "game-config.hypergryph.com", "https://game-config.hypergryph.com/api/remote_config/v1/config"],
    ["/event-log-api-data-lake-prod-cn.hypergryph.com/batch_event", "event-log-api-data-lake-prod-cn.hypergryph.com", "https://event-log-api-data-lake-prod-cn.hypergryph.com/batch_event"],
];

let passed = 0;
let failed = 0;

console.log("Testing proxy URL parsing...\n");

for (const [path, expectedHost, expectedUpstream] of tests) {
    const { host, rest } = parseProxyPath(path);
    const upstream = buildUpstreamUrl("https", path);

    const hostOk = host === expectedHost;
    const upstreamOk = upstream === expectedUpstream;

    if (hostOk && upstreamOk) {
        console.log(`✓ ${expectedHost}${rest ? "/" + rest : ""}`);
        console.log(`  ${path} -> ${upstream}`);
        passed++;
    } else {
        console.log(`✗ ${expectedHost}${rest ? "/" + rest : ""}`);
        console.log(`  Path:     ${path}`);
        if (!hostOk) {
            console.log(`  Host:     expected "${expectedHost}", got "${host}"`);
        }
        if (!upstreamOk) {
            console.log(`  Upstream: expected "${expectedUpstream}", got "${upstream}"`);
        }
        failed++;
    }
}

console.log(`\nResults: ${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
