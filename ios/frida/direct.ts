import { ScriptConfig, rewriteUrl } from "./util";

declare const send: any;

type JsonNumber = number | string;

interface DirectProfile {
    schema: number;
    id: string;
    bundle_id: string;
    version: string;
    build: string;
    arch: string;
    module: {
        name: string;
        uuid: string;
        text_vmaddr: JsonNumber;
        text_size: JsonNumber;
    };
    offsets: Record<string, JsonNumber>;
    prologues?: Record<string, string>;
    layout: Record<string, number>;
}

interface BodyData {
    data: ArrayBuffer | null;
    size: number;
    truncated: boolean;
}

interface RequestState {
    pointer: NativePointer;
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: BodyData;
    requestId?: string;
    downloadHandlerKey?: string;
    asyncOperationKey?: string;
    completed?: boolean;
}

interface BestHttpRequestState {
    pointer: NativePointer;
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: BodyData;
    requestId?: string;
    responsePointer?: NativePointer;
    completed?: boolean;
}

const conf = new ScriptConfig({
    no_proxy: true,
    proxy_url: "",
    capture: true,
    capture_max_body_bytes: 4 * 1024 * 1024,
    bypass_ssl: true,
    bypass_signatures: true,
});

let profile: DirectProfile;
let unity: Module;
let maxBodyBytes = 4 * 1024 * 1024;
let captureEnabled = true;
let fastAllocateString: any = null;
let getUrl: any = null;
let getResponseCode: any = null;
let getDownloadData: any = null;
let uriGetAbsoluteUri: any = null;
let nextRequestId = 1;
let installed = false;

const requests = new Map<string, RequestState>();
const uploadBodies = new Map<string, BodyData>();
const downloadRequests = new Map<string, RequestState>();
const asyncRequests = new Map<string, RequestState>();
const bestHttpRequests = new Map<string, BestHttpRequestState>();
const bestHttpResponses = new Map<string, BestHttpRequestState>();

function emit(payload: Record<string, any>, data?: ArrayBuffer | null): void {
    if (data !== undefined && data !== null) send(payload, data);
    else send(payload);
}

function parseInteger(value: JsonNumber, name: string): number {
    const parsed = typeof value === "number" ? value : Number.parseInt(value, 0);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`invalid ${name}: ${value}`);
    }
    return parsed;
}

function bytesToHex(data: ArrayBuffer): string {
    return Array.from(new Uint8Array(data))
        .map(value => value.toString(16).padStart(2, "0"))
        .join("");
}

function moduleUuid(module: Module): string {
    const base = module.base;
    if (base.readU32() !== 0xfeedfacf) throw new Error("UnityFramework is not a 64-bit Mach-O image");
    const commandCount = base.add(16).readU32();
    let command = base.add(32);
    for (let index = 0; index < commandCount && index < 4096; index += 1) {
        const kind = command.readU32();
        const size = command.add(4).readU32();
        if (size < 8 || size > 1024 * 1024) throw new Error(`invalid Mach-O load command size: ${size}`);
        if (kind === 0x1b) {
            const raw = command.add(8).readByteArray(16);
            if (raw === null) throw new Error("unable to read Mach-O UUID");
            const hex = bytesToHex(raw).toUpperCase();
            return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        }
        command = command.add(size);
    }
    throw new Error("Mach-O LC_UUID was not found");
}

function address(name: string): NativePointer {
    const raw = profile.offsets[name];
    if (raw === undefined) throw new Error(`profile offset is missing: ${name}`);
    const result = unity.base.add(parseInteger(raw, `offset ${name}`));
    const range = Process.findRangeByAddress(result);
    if (range === null || !range.protection.includes("x")) {
        throw new Error(`${name} does not resolve to executable memory: ${result}`);
    }
    const expected = profile.prologues?.[name]?.toLowerCase();
    if (expected) {
        const actualBytes = result.readByteArray(expected.length / 2);
        if (actualBytes === null || bytesToHex(actualBytes) !== expected) {
            throw new Error(`${name} prologue mismatch at ${result}`);
        }
    }
    return result;
}

function hasOffset(name: string): boolean {
    return profile !== undefined && profile.offsets[name] !== undefined;
}

function hasLayout(name: string): boolean {
    const value = profile?.layout?.[name];
    return Number.isSafeInteger(value) && value >= 0;
}

function layout(name: string): number {
    const value = profile.layout[name];
    if (!Number.isSafeInteger(value) || value < 0) throw new Error(`invalid layout value: ${name}`);
    return value;
}

function readManagedString(value: NativePointer, maximumLength = 1024 * 1024): string {
    if (value.isNull()) return "";
    const length = value.add(layout("stringLength")).readS32();
    if (length < 0 || length > maximumLength) throw new Error(`invalid managed string length: ${length}`);
    return value.add(layout("stringChars")).readUtf16String(length) ?? "";
}

function tryReadManagedString(value: NativePointer, maximumLength = 1024 * 1024): string | null {
    try {
        return readManagedString(value, maximumLength);
    } catch (_) {
        return null;
    }
}

function readManagedBytes(value: NativePointer): BodyData {
    if (value.isNull()) return { data: null, size: 0, truncated: false };
    const size = Number(value.add(layout("arrayLength")).readU64().toString());
    if (!Number.isSafeInteger(size) || size < 0) throw new Error(`invalid managed array length: ${size}`);
    const capturedSize = Math.min(size, maxBodyBytes);
    const data = capturedSize === 0
        ? new ArrayBuffer(0)
        : value.add(layout("arrayData")).readByteArray(capturedSize);
    return { data, size, truncated: capturedSize < size };
}

function encodeUtf8(value: string): ArrayBuffer {
    const output: number[] = [];
    for (let index = 0; index < value.length; index += 1) {
        let code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff && index + 1 < value.length) {
            const low = value.charCodeAt(index + 1);
            if (low >= 0xdc00 && low <= 0xdfff) {
                code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
                index += 1;
            }
        }
        if (code <= 0x7f) output.push(code);
        else if (code <= 0x7ff) output.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
        else if (code <= 0xffff) output.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
        else output.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
    return new Uint8Array(output).buffer;
}

function bodyFromString(value: string): BodyData {
    const encoded = encodeUtf8(value);
    const size = encoded.byteLength;
    const data = size > maxBodyBytes ? encoded.slice(0, maxBodyBytes) : encoded;
    return { data, size, truncated: data.byteLength < size };
}

function displayUrl(value: string): string {
    const match = /^([A-Za-z][A-Za-z0-9+.-]*):\/\/([^/?#]*)([^?#]*)/.exec(value);
    if (match === null) return "<url omitted>";
    const authority = match[2];
    const separator = authority.lastIndexOf("@");
    const host = separator === -1 ? authority : authority.slice(separator + 1);
    if (!host || !/^[A-Za-z0-9.:[\]-]+$/.test(host)) return "<url omitted>";
    const path = match[3] || "/";
    if (/[\u0000-\u001f\u007f]/.test(path)) return `${match[1]}://${host}/<path omitted>`;
    const boundedPath = path.length > 256 ? `${path.slice(0, 253)}...` : path;
    return `${match[1]}://${host}${boundedPath}`;
}

function requestState(pointer: NativePointer): RequestState {
    const key = pointer.toString();
    let state = requests.get(key);
    if (state === undefined) {
        state = { pointer, method: "", url: "", headers: {} };
        requests.set(key, state);
    }
    return state;
}

function allocateManagedString(value: string): NativePointer {
    if (fastAllocateString === null) throw new Error("FastAllocateString is unavailable");
    const result = fastAllocateString(value.length, NULL) as NativePointer;
    if (result.isNull()) throw new Error("FastAllocateString returned null");
    result.add(layout("stringChars")).writeUtf16String(value);
    return result;
}

function rewriteManagedUrl(value: NativePointer, source: string): { pointer: NativePointer; url: string } {
    const original = readManagedString(value, 64 * 1024);
    const rewritten = rewriteUrl(original, conf);
    if (rewritten === original) return { pointer: value, url: original };
    emit({
        event: "url-rewrite",
        source,
        original: displayUrl(original),
        rewritten: displayUrl(rewritten),
    });
    return { pointer: allocateManagedString(rewritten), url: rewritten };
}

function safeAttach(name: string, callbacks: InvocationListenerCallbacks, hooks: string[], errors: string[]): void {
    try {
        Interceptor.attach(address(name), callbacks);
        hooks.push(name);
        emit({ event: "hook-installed", hook: name });
    } catch (error) {
        const detail = String(error);
        errors.push(`${name}: ${detail}`);
        emit({ event: "hook-error", hook: name, error: detail });
    }
}

function attachReturnTrue(name: string, hooks: string[], errors: string[]): void {
    safeAttach(name, {
        onLeave(retval) {
            retval.replace(ptr(1));
        },
    }, hooks, errors);
}

function refreshRequestUrl(state: RequestState): void {
    if (getUrl === null) return;
    try {
        const value = getUrl(state.pointer, NULL) as NativePointer;
        if (!value.isNull()) state.url = readManagedString(value, 64 * 1024);
    } catch (_) {
        // The URL captured by ctor/set_url remains usable.
    }
}

function responseStatus(state: RequestState): number | string | null {
    if (getResponseCode === null) return null;
    try {
        const raw = String(getResponseCode(state.pointer, NULL));
        const value = Number(raw);
        return Number.isSafeInteger(value) ? value : raw;
    } catch (_) {
        return null;
    }
}

function emitResponse(state: RequestState, body: BodyData, source: string): void {
    if (!captureEnabled || state.completed || state.requestId === undefined) return;
    state.completed = true;
    refreshRequestUrl(state);
    emit({
        event: "capture",
        phase: "response",
        request_id: state.requestId,
        timestamp: new Date().toISOString(),
        transport: "UnityWebRequest",
        url: state.url,
        response_status: responseStatus(state),
        body_size: body.size,
        body_truncated: body.truncated,
        source,
    }, body.data);
    requests.delete(state.pointer.toString());
    if (state.downloadHandlerKey) downloadRequests.delete(state.downloadHandlerKey);
    if (state.asyncOperationKey) asyncRequests.delete(state.asyncOperationKey);
}

function bestHttpRequestState(pointer: NativePointer): BestHttpRequestState {
    const key = pointer.toString();
    let state = bestHttpRequests.get(key);
    if (state === undefined) {
        state = { pointer, method: "UNKNOWN", url: "", headers: {} };
        bestHttpRequests.set(key, state);
    }
    return state;
}

function bestHttpRequestUrl(pointer: NativePointer): string {
    if (uriGetAbsoluteUri === null || !hasLayout("bestRequestUri")) return "";
    try {
        const uri = pointer.add(layout("bestRequestUri")).readPointer();
        if (uri.isNull()) return "";
        const value = uriGetAbsoluteUri(uri, NULL) as NativePointer;
        return value.isNull() ? "" : readManagedString(value, 64 * 1024);
    } catch (_) {
        return "";
    }
}

function bestHttpRequestBody(pointer: NativePointer): BodyData {
    if (!hasLayout("bestRequestRawData")) return { data: null, size: 0, truncated: false };
    try {
        const rawData = pointer.add(layout("bestRequestRawData")).readPointer();
        return rawData.isNull()
            ? { data: null, size: 0, truncated: false }
            : readManagedBytes(rawData);
    } catch (_) {
        return { data: null, size: 0, truncated: false };
    }
}

function bestHttpMethod(pointer: NativePointer): string {
    if (!hasLayout("bestRequestMethod")) return "UNKNOWN";
    try {
        switch (pointer.add(layout("bestRequestMethod")).readU8()) {
            case 0: return "GET";
            case 1: return "HEAD";
            case 2: return "POST";
            case 3: return "PUT";
            case 4: return "DELETE";
            case 5: return "PATCH";
            case 6: return "MERGE";
            default: return "UNKNOWN";
        }
    } catch (_) {
        return "UNKNOWN";
    }
}

function emitBestHttpRequest(state: BestHttpRequestState, source: string): void {
    if (!captureEnabled || state.requestId !== undefined) return;
    state.requestId = `ios-${Date.now()}-${nextRequestId++}`;
    const body = state.body ?? bestHttpRequestBody(state.pointer);
    emit({
        event: "capture",
        phase: "request",
        request_id: state.requestId,
        timestamp: new Date().toISOString(),
        transport: "BestHTTP",
        method: state.method || "UNKNOWN",
        url: state.url,
        request_headers: state.headers,
        body_size: body.size,
        body_truncated: body.truncated,
        source,
    }, body.data);
}

function bestHttpResponseBody(response: NativePointer): BodyData {
    try {
        if (hasLayout("bestHttpResponseData")) {
            const data = response.add(layout("bestHttpResponseData")).readPointer();
            if (!data.isNull()) return readManagedBytes(data);
        }
    } catch (_) {
        // Keep the response metadata even when a body is not readable.
    }
    return { data: null, size: 0, truncated: false };
}

function webHttpResponseBody(response: NativePointer): BodyData {
    try {
        if (hasLayout("webHttpResponseData")) {
            const data = response.add(layout("webHttpResponseData")).readPointer();
            if (!data.isNull()) return readManagedBytes(data);
        }
        if (hasLayout("webHttpResponseText")) {
            const text = response.add(layout("webHttpResponseText")).readPointer();
            if (!text.isNull()) return bodyFromString(readManagedString(text, 64 * 1024 * 1024));
        }
    } catch (_) {
        // Keep the response metadata even when a body is not readable.
    }
    return { data: null, size: 0, truncated: false };
}

function bestHttpResponseStatus(response: NativePointer): number | string | null {
    if (response.isNull() || !hasLayout("bestHttpResponseCode")) return null;
    try {
        return response.add(layout("bestHttpResponseCode")).readS32();
    } catch (_) {
        return null;
    }
}

function webHttpResponseStatus(response: NativePointer): number | string | null {
    if (response.isNull() || !hasLayout("bestHttpResponseCode")) return null;
    try {
        const value = Number(response.add(layout("bestHttpResponseCode")).readS64().toString());
        return Number.isSafeInteger(value) ? value : String(value);
    } catch (_) {
        return null;
    }
}

function emitBestHttpResponse(
    state: BestHttpRequestState,
    response: NativePointer,
    outResponse: NativePointer,
    source: string,
): void {
    if (!captureEnabled || state.completed || state.requestId === undefined) return;
    state.completed = true;
    const body = outResponse.isNull() ? bestHttpResponseBody(response) : webHttpResponseBody(outResponse);
    const status = outResponse.isNull() ? bestHttpResponseStatus(response) : webHttpResponseStatus(outResponse);
    emit({
        event: "capture",
        phase: "response",
        request_id: state.requestId,
        timestamp: new Date().toISOString(),
        transport: "BestHTTP",
        url: state.url,
        response_status: status,
        body_size: body.size,
        body_truncated: body.truncated,
        source,
    }, body.data);
    bestHttpRequests.delete(state.pointer.toString());
    if (state.responsePointer) bestHttpResponses.delete(state.responsePointer.toString());
}

function installBestHttpHooks(hooks: string[], errors: string[]): void {
    const requiredOffsets = [
        "networkerPostWithBestHttp",
        "networkerGenerateHttpPostRequest",
        "networkerProcessBestHttpResponse",
    ];
    const requiredLayouts = [
        "bestRequestUri",
        "bestRequestMethod",
        "bestRequestRawData",
        "bestHttpResponseCode",
        "bestHttpResponseData",
        "webHttpResponseText",
        "webHttpResponseData",
    ];
    if (!requiredOffsets.every(hasOffset) || !requiredLayouts.every(hasLayout)) {
        emit({ event: "besthttp-unavailable", missing_offsets: requiredOffsets.filter(name => !hasOffset(name)), missing_layout: requiredLayouts.filter(name => !hasLayout(name)) });
        return;
    }

    if (hasOffset("systemUriGetAbsoluteUri")) {
        try {
            uriGetAbsoluteUri = new NativeFunction(address("systemUriGetAbsoluteUri"), "pointer", ["pointer", "pointer"]);
        } catch (error) {
            emit({ event: "besthttp-warning", stage: "uri-getter", error: String(error) });
        }
    }

    safeAttach("networkerPostWithBestHttp", {
        onEnter(args) {
            if (!captureEnabled) return;
            try {
                const url = readManagedString(args[1], 64 * 1024);
                emit({
                    event: "network-path",
                    transport: "BestHTTP",
                    phase: "post",
                    url: displayUrl(url),
                });
            } catch (error) {
                emit({ event: "besthttp-warning", stage: "post", error: String(error) });
            }
        },
    }, hooks, errors);

    safeAttach("networkerGenerateHttpPostRequest", {
        onEnter(this: InvocationContext & { url?: string; body?: BodyData; requestSlot?: NativePointer }, args) {
            if (!captureEnabled) return;
            try {
                const original = readManagedString(args[1], 64 * 1024);
                const rewritten = rewriteUrl(original, conf);
                if (rewritten !== original) args[1] = allocateManagedString(rewritten);
                this.url = rewritten;
                this.body = bodyFromString(readManagedString(args[2], 64 * 1024 * 1024));
                this.requestSlot = args[6];
            } catch (error) {
                emit({ event: "besthttp-warning", stage: "request", error: String(error) });
            }
        },
        onLeave(this: InvocationContext & { url?: string; body?: BodyData; requestSlot?: NativePointer }) {
            if (!captureEnabled || this.requestSlot === undefined) return;
            try {
                const request = this.requestSlot.readPointer();
                if (request.isNull()) return;
                const state = bestHttpRequestState(request);
                state.method = "POST";
                state.url = this.url ?? bestHttpRequestUrl(request);
                if (this.body !== undefined) state.body = this.body;
                const rawBody = bestHttpRequestBody(request);
                if (rawBody.size > 0) state.body = rawBody;
                emitBestHttpRequest(state, "Networker._GenerateHttpPostRequest");
            } catch (error) {
                emit({ event: "besthttp-warning", stage: "request-leave", error: String(error) });
            }
        },
    }, hooks, errors);

    safeAttach("networkerProcessBestHttpResponse", {
        onEnter(this: InvocationContext & { request?: NativePointer; response?: NativePointer; outResponse?: NativePointer }, args) {
            if (!captureEnabled) return;
            this.request = args[1];
            this.response = args[2];
            this.outResponse = args[3];
        },
        onLeave(this: InvocationContext & { request?: NativePointer; response?: NativePointer; outResponse?: NativePointer }) {
            if (!captureEnabled || this.request === undefined) return;
            try {
                let state = bestHttpRequests.get(this.request.toString());
                if (state === undefined) state = bestHttpRequestState(this.request);
                if (!state.url) state.url = bestHttpRequestUrl(this.request);
                if (!state.method || state.method === "UNKNOWN") state.method = bestHttpMethod(this.request);
                if (state.body === undefined) state.body = bestHttpRequestBody(this.request);
                emitBestHttpRequest(state, "Networker._ProcessHttpWebResponse");
                if (this.response !== undefined && !this.response.isNull()) {
                    state.responsePointer = this.response;
                    bestHttpResponses.set(this.response.toString(), state);
                }
                emitBestHttpResponse(
                    state,
                    this.response ?? NULL,
                    this.outResponse ?? NULL,
                    "Networker._ProcessHttpWebResponse",
                );
            } catch (error) {
                emit({ event: "besthttp-warning", stage: "response", error: String(error) });
            }
        },
    }, hooks, errors);

    const send = (name: string, requestIndex: number) => {
        if (!hasOffset(name)) return;
        safeAttach(name, {
            onEnter(args) {
                if (!captureEnabled) return;
                try {
                    const request = args[requestIndex];
                    if (request.isNull()) return;
                    const state = bestHttpRequestState(request);
                    if (!state.url) state.url = bestHttpRequestUrl(request);
                    if (!state.method || state.method === "UNKNOWN") state.method = bestHttpMethod(request);
                    if (state.body === undefined) state.body = bestHttpRequestBody(request);
                    emitBestHttpRequest(state, name);
                } catch (error) {
                    emit({ event: "besthttp-warning", stage: name, error: String(error) });
                }
            },
        }, hooks, errors);
    };
    send("bestHttpRequestSend", 0);
    send("bestHttpManagerSendRequest", 0);
}

function captureDownloadHandler(state: RequestState): void {
    if (!captureEnabled) return;
    try {
        const handler = state.pointer.add(layout("requestDownloadHandler")).readPointer();
        if (!handler.isNull()) {
            state.downloadHandlerKey = handler.toString();
            downloadRequests.set(state.downloadHandlerKey, state);
        }
    } catch (_) {
        // A request without a managed DownloadHandler has no body to capture.
    }
}

function requestBody(state: RequestState): BodyData {
    if (state.body !== undefined) return state.body;
    try {
        const handler = state.pointer.add(layout("requestUploadHandler")).readPointer();
        return uploadBodies.get(handler.toString()) ?? { data: null, size: 0, truncated: false };
    } catch (_) {
        return { data: null, size: 0, truncated: false };
    }
}

function installHooks(): void {
    const hooks: string[] = [];
    const errors: string[] = [];

    fastAllocateString = new NativeFunction(address("stringFastAllocate"), "pointer", ["int", "pointer"]);
    getUrl = new NativeFunction(address("unityWebRequestGetUrl"), "pointer", ["pointer", "pointer"]);
    getResponseCode = new NativeFunction(address("unityWebRequestGetResponseCode"), "int64", ["pointer", "pointer"]);
    getDownloadData = new NativeFunction(address("downloadHandlerGetData"), "pointer", ["pointer", "pointer"]);

    safeAttach("unityWebRequestGet", {
        onEnter(this: InvocationContext & { capturedUrl?: string }, args) {
            const rewritten = rewriteManagedUrl(args[0], "UnityWebRequest.Get");
            args[0] = rewritten.pointer;
            this.capturedUrl = rewritten.url;
        },
        onLeave(this: InvocationContext & { capturedUrl?: string }, retval) {
            if (!captureEnabled || retval.isNull()) return;
            const state = requestState(retval);
            state.method = "GET";
            if (this.capturedUrl !== undefined) state.url = this.capturedUrl;
        },
    }, hooks, errors);

    safeAttach("unityWebRequestPostString", {
        onEnter(this: InvocationContext & { capturedUrl?: string; body?: BodyData }, args) {
            const rewritten = rewriteManagedUrl(args[0], "UnityWebRequest.Post");
            args[0] = rewritten.pointer;
            this.capturedUrl = rewritten.url;
            if (captureEnabled) {
                this.body = bodyFromString(readManagedString(args[1], maxBodyBytes));
            }
        },
        onLeave(this: InvocationContext & { capturedUrl?: string; body?: BodyData }, retval) {
            if (!captureEnabled || retval.isNull()) return;
            const state = requestState(retval);
            state.method = "POST";
            if (this.capturedUrl !== undefined) state.url = this.capturedUrl;
            if (this.body !== undefined) state.body = this.body;
        },
    }, hooks, errors);

    safeAttach("unityWebRequestCtor", {
        onEnter(args) {
            const rewritten = rewriteManagedUrl(args[1], "UnityWebRequest.ctor");
            args[1] = rewritten.pointer;
            if (captureEnabled) {
                const state = requestState(args[0]);
                state.url = rewritten.url;
                state.method = readManagedString(args[2], 64);
            }
        },
    }, hooks, errors);

    safeAttach("unityWebRequestSetUrl", {
        onEnter(args) {
            const rewritten = rewriteManagedUrl(args[1], "UnityWebRequest.set_url");
            args[1] = rewritten.pointer;
            if (captureEnabled) requestState(args[0]).url = rewritten.url;
        },
    }, hooks, errors);

    safeAttach("unityWebRequestSetMethod", {
        onEnter(args) {
            if (captureEnabled) requestState(args[0]).method = readManagedString(args[1], 64);
        },
    }, hooks, errors);

    safeAttach("unityWebRequestSetRequestHeader", {
        onEnter(args) {
            if (!captureEnabled) return;
            const state = requestState(args[0]);
            const name = readManagedString(args[1], 16 * 1024);
            state.headers[name] = readManagedString(args[2], 64 * 1024);
        },
    }, hooks, errors);

    safeAttach("uploadHandlerRawCtorBytes", {
        onEnter(args) {
            if (captureEnabled) uploadBodies.set(args[0].toString(), readManagedBytes(args[1]));
        },
    }, hooks, errors);

    safeAttach("unityWebRequestSend", {
        onEnter(this: InvocationContext & { request?: RequestState }, args) {
            if (!captureEnabled) return;
            const state = requestState(args[0]);
            refreshRequestUrl(state);
            if (!state.method) state.method = "UNKNOWN";
            if (state.requestId === undefined) {
                state.requestId = `ios-${Date.now()}-${nextRequestId++}`;
                const body = requestBody(state);
                emit({
                    event: "capture",
                    phase: "request",
                    request_id: state.requestId,
                    timestamp: new Date().toISOString(),
                    transport: "UnityWebRequest",
                    method: state.method,
                    url: state.url,
                    request_headers: state.headers,
                    body_size: body.size,
                    body_truncated: body.truncated,
                }, body.data);
                captureDownloadHandler(state);
            }
            this.request = state;
        },
        onLeave(this: InvocationContext & { request?: RequestState }, retval) {
            if (!captureEnabled || retval.isNull() || this.request === undefined) return;
            const key = retval.toString();
            this.request.asyncOperationKey = key;
            asyncRequests.set(key, this.request);
        },
    }, hooks, errors);

    safeAttach("downloadHandlerGetData", {
        onEnter(this: InvocationContext & { handlerKey?: string }, args) {
            if (captureEnabled) this.handlerKey = args[0].toString();
        },
        onLeave(this: InvocationContext & { handlerKey?: string }, retval) {
            const state = this.handlerKey ? downloadRequests.get(this.handlerKey) : undefined;
            if (state !== undefined && !retval.isNull()) {
                emitResponse(state, readManagedBytes(retval), "DownloadHandler.get_data");
            }
        },
    }, hooks, errors);

    safeAttach("downloadHandlerGetText", {
        onEnter(this: InvocationContext & { handlerKey?: string }, args) {
            if (captureEnabled) this.handlerKey = args[0].toString();
        },
        onLeave(this: InvocationContext & { handlerKey?: string }, retval) {
            const state = this.handlerKey ? downloadRequests.get(this.handlerKey) : undefined;
            if (state !== undefined && !retval.isNull()) {
                emitResponse(state, bodyFromString(readManagedString(retval, 64 * 1024 * 1024)), "DownloadHandler.get_text");
            }
        },
    }, hooks, errors);

    safeAttach("asyncOperationInvokeCompletionEvent", {
        onEnter(args) {
            if (!captureEnabled) return;
            const state = asyncRequests.get(args[0].toString());
            if (state === undefined || state.completed) return;
            try {
                const handler = state.pointer.add(layout("requestDownloadHandler")).readPointer();
                if (!handler.isNull()) {
                    const data = getDownloadData(handler, NULL) as NativePointer;
                    if (!data.isNull() && !state.completed) {
                        emitResponse(state, readManagedBytes(data), "AsyncOperation.InvokeCompletionEvent");
                        return;
                    }
                }
            } catch (error) {
                emit({ event: "capture-warning", request_id: state.requestId, error: String(error) });
            }
            if (!state.completed) emitResponse(state, { data: null, size: 0, truncated: false }, "AsyncOperation.InvokeCompletionEvent");
        },
    }, hooks, errors);

    installBestHttpHooks(hooks, errors);

    if (conf.bool("bypass_ssl", true)) {
        attachReturnTrue("certificateHandlerValidate", hooks, errors);
        attachReturnTrue("certificateHandlerValidateNative", hooks, errors);
        attachReturnTrue("bouncyCastleIsValid", hooks, errors);
    }
    if (conf.bool("bypass_signatures", true)) {
        attachReturnTrue("cryptUtilsVerifySignMd5RsaString", hooks, errors);
        attachReturnTrue("rsaCryptoServiceProviderVerifyHashLegacy", hooks, errors);
    }

    emit({
        event: "direct-ready",
        profile: profile.id,
        module: unity.name,
        module_base: unity.base.toString(),
        module_uuid: moduleUuid(unity),
        hooks_installed: hooks,
        hook_errors: errors,
        capabilities: {
            capture: captureEnabled,
            url_rewrite: !conf.bool("no_proxy", true),
            ssl_bypass: conf.bool("bypass_ssl", true),
            signature_bypass: conf.bool("bypass_signatures", true),
            extra: false,
            trainer: false,
        },
    });
}

function initialize(module: Module): void {
    if (installed) return;
    installed = true;
    unity = module;
    const actualUuid = moduleUuid(module);
    const expectedUuid = profile.module.uuid.toUpperCase();
    emit({
        event: "direct-module",
        module: module.name,
        base: module.base.toString(),
        size: module.size,
        uuid: actualUuid,
        expected_uuid: expectedUuid,
    });
    if (actualUuid !== expectedUuid) {
        emit({ event: "direct-profile-mismatch", profile: profile.id, expected_uuid: expectedUuid, actual_uuid: actualUuid });
        return;
    }
    installHooks();
}

function waitForUnityFramework(): void {
    const existing = Process.findModuleByName(profile.module.name);
    if (existing !== null) {
        initialize(existing);
        return;
    }
    emit({ event: "direct-waiting-module", module: profile.module.name });
    const timer = setInterval(() => {
        const candidate = Process.findModuleByName(profile.module.name);
        if (candidate === null) return;
        clearInterval(timer);
        try {
            initialize(candidate);
        } catch (error) {
            emit({ event: "direct-error", error: String(error) });
        }
    }, 25);
}

recv("init", message => {
    try {
        profile = message.profile as DirectProfile;
        if (profile.schema !== 1) throw new Error(`unsupported profile schema: ${profile.schema}`);
        for (const [key, value] of Object.entries(message.config || {})) conf.set(key, value);
        captureEnabled = conf.bool("capture", true);
        maxBodyBytes = Math.max(0, Math.min(conf.number("capture_max_body_bytes", maxBodyBytes), 64 * 1024 * 1024));
        waitForUnityFramework();
    } catch (error) {
        emit({ event: "direct-error", error: String(error) });
    }
});

emit({ event: "direct-awaiting-init" });
