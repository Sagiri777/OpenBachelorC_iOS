#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#import <dispatch/dispatch.h>
#import <errno.h>
#import <fcntl.h>
#import <signal.h>
#import <string.h>
#import <sys/file.h>
#import <sys/stat.h>
#import <unistd.h>
#include "frida-core.h"

static const NSUInteger OBServerConnectAttempts = 20;
static const NSUInteger OBGadgetConnectAttempts = 120;
static const NSUInteger OBServerLaunchWaitAttempts = 240;
static const NSUInteger OBServerAttachAttempts = 12;
static const useconds_t OBConnectRetryDelay = 500000;
static const useconds_t OBTargetRetryDelay = 250000;
static const char * const OBGadgetEndpoint = "127.0.0.1:27043";
static const char * const OBServerEndpoint = "127.0.0.1:27042";

static GMainLoop *main_loop;
static NSString *capture_directory;
static NSString *status_path;
static NSString *pid_path;
static NSString *session_id;
static NSString *helper_backend;
static NSString *text_log_path;
static NSString *event_log_path;
static NSFileHandle *event_log_handle;
static dispatch_source_t termination_source;
static int singleton_lock_fd = -1;
static volatile sig_atomic_t stop_requested;
static BOOL terminal_status_written;
static uid_t log_owner_uid = (uid_t)-1;
static gid_t log_owner_gid = (gid_t)-1;

static void make_log_item_accessible(NSString *path, mode_t mode) {
    if (path.length == 0) return;
    chmod(path.fileSystemRepresentation, mode);
    if (log_owner_uid != (uid_t)-1 && log_owner_gid != (gid_t)-1)
        chown(path.fileSystemRepresentation, log_owner_uid, log_owner_gid);
}

static void write_status(NSString *state, NSString *message, NSDictionary *details) {
    if (status_path.length == 0) return;
    NSMutableDictionary *snapshot = [NSMutableDictionary dictionaryWithDictionary:@{
        @"schema": @1,
        @"session_id": session_id ?: @"",
        @"backend": helper_backend ?: @"unknown",
        @"state": state ?: @"unknown",
        @"message": message ?: @"",
        @"pid": @(getpid()),
        @"updated_at": @([[NSDate date] timeIntervalSince1970]),
    }];
    if (text_log_path.length != 0) snapshot[@"text_log_path"] = text_log_path;
    if (event_log_path.length != 0) snapshot[@"event_log_path"] = event_log_path;
    if (details != nil) [snapshot addEntriesFromDictionary:details];
    NSData *data = [NSJSONSerialization dataWithJSONObject:snapshot options:NSJSONWritingPrettyPrinted error:nil];
    if (data == nil) return;
    @synchronized (status_path) {
        if ([data writeToFile:status_path options:NSDataWritingAtomic error:nil])
            chmod(status_path.fileSystemRepresentation, 0600);
    }
}

static void append_agent_event(NSDictionary *envelope, GBytes *data) {
    if (event_log_handle == nil || ![envelope isKindOfClass:NSDictionary.class]) return;
    NSMutableDictionary *record = [NSMutableDictionary dictionaryWithDictionary:@{
        @"schema": @1,
        @"logged_at": @([[NSDate date] timeIntervalSince1970]),
        @"session_id": session_id ?: @"",
        @"backend": helper_backend ?: @"unknown",
        @"message": envelope,
    }];
    if (data != NULL) record[@"data_bytes"] = @(g_bytes_get_size(data));
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    if (json == nil) return;
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    @synchronized (event_log_handle) {
        [event_log_handle writeData:line];
    }
}

static void remove_own_pid_file(void) {
    NSString *contents = [NSString stringWithContentsOfFile:pid_path encoding:NSUTF8StringEncoding error:nil];
    if ((pid_t)contents.intValue == getpid())
        [[NSFileManager defaultManager] removeItemAtPath:pid_path error:nil];
}

static NSString *sha256_hex(NSData *data) {
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hex = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (NSUInteger index = 0; index < CC_SHA256_DIGEST_LENGTH; index++)
        [hex appendFormat:@"%02x", digest[index]];
    return hex;
}

static void append_capture(NSDictionary *payload, GBytes *bytes) {
    NSMutableDictionary *record = [payload mutableCopy];
    record[@"capture_schema"] = @1;
    record[@"captured_at"] = @([[NSDate date] timeIntervalSince1970]);
    if (bytes != NULL) {
        gsize size = 0;
        gconstpointer raw = g_bytes_get_data(bytes, &size);
        NSData *body = [NSData dataWithBytes:raw length:size];
        NSString *hash = sha256_hex(body);
        NSString *relative = [@"bodies" stringByAppendingPathComponent:[hash stringByAppendingString:@".bin"]];
        NSString *path = [capture_directory stringByAppendingPathComponent:relative];
        if (![[NSFileManager defaultManager] fileExistsAtPath:path]) {
            [body writeToFile:path options:NSDataWritingAtomic error:nil];
            make_log_item_accessible(path, 0600);
        }
        record[@"body_sha256"] = hash;
        record[@"body_file"] = relative;
        record[@"body_captured_bytes"] = @(size);
    }
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    if (json == nil) return;
    NSMutableData *line = [json mutableCopy];
    [line appendBytes:"\n" length:1];
    NSString *jsonl = [capture_directory stringByAppendingPathComponent:@"capture.jsonl"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:jsonl]) {
        [[NSData data] writeToFile:jsonl options:NSDataWritingAtomic error:nil];
        make_log_item_accessible(jsonl, 0600);
    }
    NSFileHandle *handle = [NSFileHandle fileHandleForWritingAtPath:jsonl];
    [handle seekToEndOfFile];
    [handle writeData:line];
    [handle closeFile];
}

static NSString *consume_error(NSString *stage, GError **error) {
    const gchar *detail = *error != NULL && (*error)->message != NULL ? (*error)->message : "unknown error";
    NSString *message = [NSString stringWithFormat:@"%@: %s", stage, detail];
    if (*error != NULL) {
        g_error_free(*error);
        *error = NULL;
    }
    return message;
}

static gboolean stop_loop(gpointer user_data) {
    (void)user_data;
    if (main_loop != NULL) g_main_loop_quit(main_loop);
    return FALSE;
}

static void install_signal_handlers(void) {
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    termination_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0,
                                                 dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    dispatch_source_set_event_handler(termination_source, ^{
        stop_requested = 1;
        write_status(@"stopping", @"正在停止 helper 并卸载 direct agent…", nil);
        stop_loop(NULL);
    });
    dispatch_resume(termination_source);
}

static void detached_handler(FridaSession *session, FridaSessionDetachReason reason,
                             FridaCrash *crash, gpointer user_data) {
    (void)session;
    (void)crash;
    (void)user_data;
    gchar *reason_string = g_enum_to_string(FRIDA_TYPE_SESSION_DETACH_REASON, reason);
    NSString *reason_text = reason_string != NULL ? @(reason_string) : @"unknown";
    fprintf(stderr, "session detached: %s\n", reason_text.UTF8String);
    if (!terminal_status_written) {
        write_status(@"stopped", [NSString stringWithFormat:@"Frida 会话已断开：%@", reason_text],
                     @{@"detach_reason": reason_text});
        terminal_status_written = YES;
    }
    g_free(reason_string);
    stop_loop(NULL);
}

static void message_handler(FridaScript *script, const gchar *message, GBytes *data,
                            gpointer user_data) {
    (void)script;
    (void)user_data;
    @autoreleasepool {
        NSData *raw_message = [NSData dataWithBytes:message length:strlen(message)];
        NSDictionary *envelope = [NSJSONSerialization JSONObjectWithData:raw_message options:0 error:nil];
        append_agent_event(envelope, data);
        NSDictionary *payload = [envelope[@"payload"] isKindOfClass:NSDictionary.class] ? envelope[@"payload"] : nil;
        NSString *event = [payload[@"event"] isKindOfClass:NSString.class] ? payload[@"event"] : nil;
        if ([envelope[@"type"] isEqual:@"send"] && [event isEqual:@"capture"]) {
            append_capture(payload, data);
            NSString *phase = payload[@"phase"] ?: @"event";
            NSString *method = payload[@"method"] ?: @"";
            NSString *transport = payload[@"transport"] ?: @"";
            fprintf(stdout, "capture: %s %s %s\n", phase.UTF8String,
                    method.UTF8String, transport.UTF8String);
        } else if ([envelope[@"type"] isEqual:@"send"] && [event isEqual:@"direct-ready"]) {
            NSArray *hooks = [payload[@"hooks_installed"] isKindOfClass:NSArray.class] ? payload[@"hooks_installed"] : @[];
            NSArray *errors = [payload[@"hook_errors"] isKindOfClass:NSArray.class] ? payload[@"hook_errors"] : @[];
            NSDictionary *capabilities = [payload[@"capabilities"] isKindOfClass:NSDictionary.class]
                ? payload[@"capabilities"] : @{};
            BOOL extra = [capabilities[@"extra"] boolValue];
            NSArray *extraFeatures = [capabilities[@"extra_features"] isKindOfClass:NSArray.class]
                ? capabilities[@"extra_features"] : @[];
            BOOL trainer = [capabilities[@"trainer"] boolValue];
            BOOL battleFinishBlock = [capabilities[@"battle_finish_block_enabled"] boolValue];
            NSArray *trainerCommands = [capabilities[@"trainer_commands"] isKindOfClass:NSArray.class]
                ? capabilities[@"trainer_commands"] : @[];
            NSArray *trainerStepUnits = [capabilities[@"trainer_step_units"] isKindOfClass:NSArray.class]
                ? capabilities[@"trainer_step_units"] : @[];
            NSString *featureText = extraFeatures.count > 0
                ? [extraFeatures componentsJoinedByString:@", "] : @"无";
            NSString *stepText = trainerStepUnits.count > 0
                ? [trainerStepUnits componentsJoinedByString:@"/"] : @"不可用";
            NSString *ready = [NSString stringWithFormat:@"注入完成：direct-ready，%lu 个 hook，%lu 个非致命错误，战斗记录拦截%@，extra %@（%@），trainer %@（%lu 项，步进 %@）。",
                               (unsigned long)hooks.count, (unsigned long)errors.count,
                               battleFinishBlock ? @"已开启" : @"未开启",
                               extra ? @"可用" : @"不可用", featureText,
                               trainer ? @"可用" : @"不可用", (unsigned long)trainerCommands.count,
                               stepText];
            write_status(@"ready", ready, @{
                @"hooks_installed": @(hooks.count), @"hook_errors": @(errors.count),
                @"extra": @(extra), @"extra_features": extraFeatures,
                @"battle_finish_block_enabled": @(battleFinishBlock),
                @"trainer": @(trainer), @"trainer_commands": trainerCommands,
                @"trainer_step_units": trainerStepUnits,
            });
            fprintf(stdout, "agent: direct-ready hooks=%lu errors=%lu battle_finish_block=%s extra=%s features=%s trainer=%s commands=%lu step_units=%s\n",
                    (unsigned long)hooks.count, (unsigned long)errors.count,
                    battleFinishBlock ? "enabled" : "disabled",
                    extra ? "available" : "unavailable", featureText.UTF8String,
                    trainer ? "available" : "unavailable", (unsigned long)trainerCommands.count,
                    stepText.UTF8String);
        } else if ([envelope[@"type"] isEqual:@"send"] &&
                   ([event isEqual:@"direct-profile-mismatch"] || [event isEqual:@"direct-error"])) {
            NSString *error = [event isEqual:@"direct-profile-mismatch"]
                ? [NSString stringWithFormat:@"direct profile 不匹配（期望 %@，实际 %@）。",
                                             payload[@"expected_uuid"] ?: @"unknown", payload[@"actual_uuid"] ?: @"unknown"]
                : [NSString stringWithFormat:@"direct agent 初始化失败：%@", payload[@"error"] ?: @"unknown"];
            write_status(@"error", error, @{@"agent_event": event});
            terminal_status_written = YES;
            fprintf(stderr, "agent: %s\n", error.UTF8String);
            stop_loop(NULL);
        } else if ([envelope[@"type"] isEqual:@"send"] && event.length != 0) {
            if ([event isEqual:@"direct-waiting-module"])
                write_status(@"running", @"目标进程正在运行，等待 UnityFramework 加载…", nil);
            fprintf(stdout, "agent: %s\n", event.UTF8String);
        } else if ([envelope[@"type"] isEqual:@"error"]) {
            NSString *error = [NSString stringWithFormat:@"agent 脚本异常：%s", message];
            write_status(@"error", error, nil);
            terminal_status_written = YES;
            fprintf(stderr, "%s\n", error.UTF8String);
            stop_loop(NULL);
        } else {
            fprintf(stdout, "agent message: %s\n", [envelope[@"type"] UTF8String] ?: "unknown");
        }
        fflush(stdout);
        fflush(stderr);
    }
}

static FridaApplication *find_application(FridaDevice *device, NSString *bundle_id,
                                          GError **error) {
    FridaApplicationQueryOptions *options = frida_application_query_options_new();
    frida_application_query_options_select_identifier(options, bundle_id.UTF8String);
    // Full scope supplies the bundle path and the live PID on iOS. Minimal
    // scope may report an installed application with pid=0 even while its
    // process is already running, which would incorrectly send us to spawn.
    frida_application_query_options_set_scope(options, FRIDA_SCOPE_FULL);
    FridaApplicationList *applications = frida_device_enumerate_applications_sync(
        device, options, NULL, error);
    g_object_unref(options);
    if (applications == NULL) return NULL;

    FridaApplication *result = NULL;
    gint count = frida_application_list_size(applications);
    for (gint index = 0; index < count; index++) {
        FridaApplication *candidate = frida_application_list_get(applications, index);
        if (strcmp(frida_application_get_identifier(candidate), bundle_id.UTF8String) == 0)
            result = g_object_ref(candidate);
        g_object_unref(candidate);
        if (result != NULL) break;
    }
    frida_unref(applications);
    return result;
}

static NSString *string_parameter(GHashTable *parameters, const gchar *key) {
    if (parameters == NULL) return nil;
    GVariant *value = g_hash_table_lookup(parameters, key);
    if (value == NULL || !g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) return nil;
    const gchar *text = g_variant_get_string(value, NULL);
    return text != NULL ? @(text) : nil;
}

static guint find_application_process(FridaDevice *device, FridaApplication *application,
                                      NSString *bundle_id, NSString **process_name) {
    guint application_pid = frida_application_get_pid(application);
    NSString *application_name = @(frida_application_get_name(application));
    if (application_pid != 0) {
        if (process_name != NULL) *process_name = application_name;
        return application_pid;
    }

    NSString *application_path = string_parameter(frida_application_get_parameters(application), "path");
    NSString *application_prefix = application_path.length != 0
        ? [application_path stringByAppendingString:@"/"] : nil;
    FridaProcessQueryOptions *options = frida_process_query_options_new();
    frida_process_query_options_set_scope(options, FRIDA_SCOPE_FULL);
    GError *query_error = NULL;
    FridaProcessList *processes = frida_device_enumerate_processes_sync(
        device, options, NULL, &query_error);
    g_object_unref(options);
    if (processes == NULL) {
        fprintf(stderr, "process fallback failed: %s\n",
                query_error != NULL && query_error->message != NULL
                    ? query_error->message : "unknown error");
        if (query_error != NULL) g_error_free(query_error);
        return 0;
    }

    guint selected_pid = 0;
    NSString *selected_name = nil;
    gint count = frida_process_list_size(processes);
    for (gint index = 0; index < count; index++) {
        FridaProcess *candidate = frida_process_list_get(processes, index);
        NSString *candidate_name = @(frida_process_get_name(candidate));
        NSString *candidate_path = string_parameter(frida_process_get_parameters(candidate), "path");
        BOOL path_matches = application_prefix.length != 0 &&
            [candidate_path hasPrefix:application_prefix];
        BOOL name_matches = application_name.length != 0 &&
            [candidate_name caseInsensitiveCompare:application_name] == NSOrderedSame;
        BOOL identifier_matches =
            [candidate_name caseInsensitiveCompare:bundle_id] == NSOrderedSame;
        if (path_matches || name_matches || identifier_matches) {
            selected_pid = frida_process_get_pid(candidate);
            selected_name = candidate_name;
        }
        g_object_unref(candidate);
        if (selected_pid != 0) break;
    }
    frida_unref(processes);
    if (process_name != NULL) *process_name = selected_name;
    return selected_pid;
}

static guint refresh_server_target(FridaDevice *device, NSString *bundle_id,
                                   NSString **process_name) {
    GError *application_error = NULL;
    FridaApplication *application = find_application(device, bundle_id, &application_error);
    if (application == NULL) {
        if (application_error != NULL) {
            fprintf(stderr, "application refresh failed: %s\n", application_error->message);
            g_error_free(application_error);
        }
        return 0;
    }
    guint pid = find_application_process(device, application, bundle_id, process_name);
    g_object_unref(application);
    return pid;
}

static gboolean is_transient_attach_error(GError *error) {
    if (error == NULL || error->domain != frida_error_quark()) return FALSE;
    return error->code == FRIDA_ERROR_PROCESS_NOT_FOUND ||
        error->code == FRIDA_ERROR_PROCESS_NOT_RESPONDING ||
        error->code == FRIDA_ERROR_TIMED_OUT;
}

static guint find_gadget_process(FridaDevice *device, NSString *bundle_id,
                                 NSString **process_name, GError **error) {
    GError *application_error = NULL;
    FridaApplication *application = find_application(device, bundle_id, &application_error);
    if (application != NULL) {
        guint application_pid = frida_application_get_pid(application);
        if (application_pid != 0 && process_name != NULL)
            *process_name = @(frida_application_get_name(application));
        g_object_unref(application);
        if (application_pid != 0) return application_pid;
    }
    if (application_error != NULL) g_error_free(application_error);

    FridaProcessQueryOptions *options = frida_process_query_options_new();
    FridaProcessList *processes = frida_device_enumerate_processes_sync(
        device, options, NULL, error);
    g_object_unref(options);
    if (processes == NULL) return 0;

    guint selected_pid = 0;
    NSString *selected_name = nil;
    gint count = frida_process_list_size(processes);
    for (gint index = 0; index < count; index++) {
        FridaProcess *candidate = frida_process_list_get(processes, index);
        NSString *candidate_name = @(frida_process_get_name(candidate));
        if (count == 1 || [candidate_name caseInsensitiveCompare:@"Gadget"] == NSOrderedSame) {
            selected_pid = frida_process_get_pid(candidate);
            selected_name = candidate_name;
        }
        g_object_unref(candidate);
        if (selected_pid != 0) break;
    }
    frida_unref(processes);
    if (process_name != NULL) *process_name = selected_name;
    return selected_pid;
}

static int run_session(NSDictionary *configuration, NSDictionary *profile, NSString *source) {
    NSString *bundle_id = configuration[@"bundle_id"];
    NSString *backend = configuration[@"backend"];
    gboolean gadget_backend = [backend isEqualToString:@"gadget"];
    NSDictionary *direct = configuration[@"direct"];
    FridaDeviceManager *manager = NULL;
    FridaDevice *device = NULL;
    FridaApplication *application = NULL;
    FridaSession *session = NULL;
    FridaScript *script = NULL;
    GError *error = NULL;
    guint pid = 0;
    gboolean spawned = FALSE;
    // The bundled Gadget uses on_load=resume so a failed automatic launch or a
    // temporarily unavailable helper can never leave the app blocked in dyld
    // until the iOS launch watchdog terminates it.
    gboolean resume_after_load = FALSE;
    gboolean resumed = FALSE;
    gboolean script_loaded = FALSE;
    NSString *failure = nil;
    NSDictionary *initialization = nil;
    NSData *initialization_data = nil;
    NSString *initialization_json = nil;
    NSString *running_message = nil;
    int result = 1;

    frida_init();
    main_loop = g_main_loop_new(NULL, TRUE);
    manager = frida_device_manager_new_with_socket_backend_only();
    FridaRemoteDeviceOptions *remote_options = frida_remote_device_options_new();
    frida_remote_device_options_set_keepalive_interval(remote_options, 5);
    NSUInteger connect_attempts = gadget_backend ? OBGadgetConnectAttempts : OBServerConnectAttempts;
    const char *remote_endpoint = gadget_backend ? OBGadgetEndpoint : OBServerEndpoint;
    if (gadget_backend)
        write_status(@"waiting_target", @"正在唤起已注入 Frida Gadget 的 TrollStore 目标应用…", nil);
    for (NSUInteger attempt = 1; attempt <= connect_attempts && !stop_requested; attempt++) {
        write_status(@"connecting",
                     [NSString stringWithFormat:@"正在连接本机 %@ %s（%lu/%lu）…",
                                                gadget_backend ? @"Frida Gadget" : @"frida-server",
                                                remote_endpoint,
                                                (unsigned long)attempt, (unsigned long)connect_attempts], nil);
        device = frida_device_manager_add_remote_device_sync(
            manager, remote_endpoint, remote_options, NULL, &error);
        if (device != NULL) break;
        fprintf(stderr, "connect attempt %lu/%lu: %s\n", (unsigned long)attempt,
                (unsigned long)connect_attempts,
                error != NULL && error->message != NULL ? error->message : "unknown error");
        if (error != NULL) {
            g_error_free(error);
            error = NULL;
        }
        if (attempt != connect_attempts) g_usleep(OBConnectRetryDelay);
    }
    g_object_unref(remote_options);
    if (stop_requested) {
        result = 0;
        goto cleanup;
    }
    if (device == NULL) {
        failure = gadget_backend
            ? @"无法连接 Frida Gadget；请在一分钟内启动目标 App，并确认已注入监听 127.0.0.1:27043、on_load=resume 的 17.9.1 Gadget。"
            : @"无法连接本机 frida-server；请确认设备已越狱、Frida 17.9.1 已启动并监听 127.0.0.1:27042。";
        goto cleanup;
    }
    fprintf(stdout, "connected: %s %s\n", gadget_backend ? "Frida Gadget" : "frida-server",
            remote_endpoint);
    write_status(@"preparing", gadget_backend ? @"已连接 Frida Gadget，正在识别目标进程…" : @"已连接 frida-server，正在查找目标应用…", nil);

    if (gadget_backend) {
        NSString *process_name = nil;
        pid = find_gadget_process(device, bundle_id, &process_name, &error);
        if (pid == 0) {
            failure = consume_error(@"Gadget 已连接但无法识别目标进程", &error);
            goto cleanup;
        }
        fprintf(stdout, "gadget target: %s pid=%u\n", process_name.UTF8String ?: "Gadget", pid);
    } else {
        application = find_application(device, bundle_id, &error);
        if (application == NULL) {
            failure = consume_error(@"找不到目标应用", &error);
            goto cleanup;
        }
        if (stop_requested) {
            result = 0;
            goto cleanup;
        }
        NSString *process_name = nil;
        pid = find_application_process(device, application, bundle_id, &process_name);
        g_object_unref(application);
        application = NULL;
        if (pid == 0) {
            FridaSpawnOptions *spawn_options = frida_spawn_options_new();
            gchar *spawn_argv[] = {(gchar *)bundle_id.UTF8String};
            frida_spawn_options_set_argv(spawn_options, spawn_argv, 1);
            pid = frida_device_spawn_sync(device, bundle_id.UTF8String, spawn_options, NULL, &error);
            g_object_unref(spawn_options);
            if (pid == 0) {
                NSString *spawn_failure = consume_error(@"Frida spawn 启动目标应用失败", &error);
                write_status(@"waiting_target",
                    @"Frida spawn 未能启动游戏，正在请求系统唤起并等待运行进程后 attach…",
                    @{@"spawn_error": spawn_failure});
                fprintf(stderr, "%s; waiting for LaunchServices/manual launch fallback\n",
                        spawn_failure.UTF8String);
                for (NSUInteger attempt = 1;
                     attempt <= OBServerLaunchWaitAttempts && !stop_requested; attempt++) {
                    pid = refresh_server_target(device, bundle_id, &process_name);
                    if (pid != 0) break;
                    g_usleep(OBTargetRetryDelay);
                }
                if (stop_requested) {
                    result = 0;
                    goto cleanup;
                }
                if (pid == 0) {
                    failure = [NSString stringWithFormat:
                        @"%@；系统唤起或手动启动后仍未发现目标进程，无法 attach。", spawn_failure];
                    goto cleanup;
                }
                fprintf(stdout, "launch fallback target: %s pid=%u\n",
                        process_name.UTF8String ?: bundle_id.UTF8String, pid);
            } else {
                spawned = TRUE;
                fprintf(stdout, "spawned: %s pid=%u\n", bundle_id.UTF8String, pid);
            }
        } else {
            fprintf(stdout, "running target: %s pid=%u\n",
                    process_name.UTF8String ?: bundle_id.UTF8String, pid);
        }
    }
    write_status(@"injecting", [NSString stringWithFormat:@"正在附加 %@（PID %u）并加载 direct agent…", bundle_id, pid], nil);

    NSUInteger attach_attempts = gadget_backend ? 1 : OBServerAttachAttempts;
    for (NSUInteger attempt = 1; attempt <= attach_attempts && !stop_requested; attempt++) {
        session = frida_device_attach_sync(device, pid, NULL, NULL, &error);
        if (session != NULL || !is_transient_attach_error(error) || attempt == attach_attempts)
            break;
        fprintf(stderr, "attach attempt %lu/%lu for pid %u: %s\n",
                (unsigned long)attempt, (unsigned long)attach_attempts, pid,
                error != NULL && error->message != NULL ? error->message : "unknown error");
        g_error_free(error);
        error = NULL;
        g_usleep(OBTargetRetryDelay);
        NSString *refreshed_name = nil;
        guint refreshed_pid = refresh_server_target(device, bundle_id, &refreshed_name);
        if (refreshed_pid != 0 && refreshed_pid != pid) {
            pid = refreshed_pid;
            spawned = FALSE;
            write_status(@"injecting",
                [NSString stringWithFormat:@"目标进程已重启，正在重新附加 %@（PID %u）…",
                                           refreshed_name ?: bundle_id, pid], nil);
        }
    }
    if (stop_requested) {
        result = 0;
        goto cleanup;
    }
    if (session == NULL) {
        failure = consume_error(@"附加目标进程失败", &error);
        goto cleanup;
    }
    if (stop_requested) {
        result = 0;
        goto cleanup;
    }
    g_signal_connect(session, "detached", G_CALLBACK(detached_handler), NULL);
    FridaScriptOptions *script_options = frida_script_options_new();
    frida_script_options_set_name(script_options, "openbachelor-ios-direct");
    frida_script_options_set_runtime(script_options, FRIDA_SCRIPT_RUNTIME_QJS);
    script = frida_session_create_script_sync(
        session, source.UTF8String, script_options, NULL, &error);
    g_object_unref(script_options);
    if (script == NULL) {
        failure = consume_error(@"创建 direct agent 失败", &error);
        goto cleanup;
    }
    g_signal_connect(script, "message", G_CALLBACK(message_handler), NULL);
    frida_script_load_sync(script, NULL, &error);
    if (error != NULL) {
        failure = consume_error(@"加载 direct agent 失败", &error);
        goto cleanup;
    }
    script_loaded = TRUE;
    if (stop_requested) {
        result = 0;
        goto cleanup;
    }

    initialization = @{@"type": @"init", @"profile": profile, @"config": direct};
    initialization_data = [NSJSONSerialization dataWithJSONObject:initialization options:0 error:nil];
    initialization_json = [[NSString alloc] initWithData:initialization_data encoding:NSUTF8StringEncoding];
    if (initialization_json.length == 0) {
        failure = @"无法序列化 direct agent 初始化配置。";
        goto cleanup;
    }
    frida_script_post(script, initialization_json.UTF8String, NULL);
    fprintf(stdout, "loaded: direct profile=%s\n", [[profile[@"id"] description] UTF8String]);

    if (spawned || resume_after_load) {
        frida_device_resume_sync(device, pid, NULL, &error);
        if (error != NULL) {
            failure = consume_error(@"恢复目标进程失败", &error);
            goto cleanup;
        }
        resumed = TRUE;
        fprintf(stdout, "target resumed\n");
    }
    if (stop_requested) {
        result = 0;
        goto cleanup;
    }
    running_message = gadget_backend
        ? @"direct agent 已附加，目标进程保持运行，正在等待运行时就绪…"
        : (spawned ? @"目标进程已恢复，direct agent 正在等待运行时就绪…"
                   : @"direct agent 已附加到运行中的目标进程，正在等待运行时就绪…");
    write_status(@"running", running_message,
        @{@"target_pid": @(pid)});
    result = 0;
    g_main_loop_run(main_loop);

cleanup:
    if (failure != nil) {
        fprintf(stderr, "error: %s\n", failure.UTF8String);
        write_status(@"error", failure, nil);
        terminal_status_written = YES;
    }
    if (!resumed && device != NULL && pid != 0) {
        if (spawned) frida_device_kill_sync(device, pid, NULL, NULL);
        else if (resume_after_load) frida_device_resume_sync(device, pid, NULL, NULL);
    }
    if (script != NULL) {
        if (script_loaded) {
            frida_script_post(script, "{\"type\":\"shutdown\"}", NULL);
            g_usleep(100000);
            frida_script_unload_sync(script, NULL, NULL);
        }
        frida_unref(script);
    }
    if (session != NULL) {
        frida_session_detach_sync(session, NULL, NULL);
        frida_unref(session);
    }
    if (application != NULL) g_object_unref(application);
    if (device != NULL) frida_unref(device);
    if (manager != NULL) {
        frida_device_manager_close_sync(manager, NULL, NULL);
        frida_unref(manager);
    }
    if (main_loop != NULL) {
        g_main_loop_unref(main_loop);
        main_loop = NULL;
    }
    frida_deinit();
    if (!terminal_status_written)
        write_status(@"stopped", stop_requested ? @"helper 已按请求停止。" : @"helper 会话已结束。", nil);
    return result;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        fprintf(stderr, "usage: OpenBachelorHelper CONFIG SCRIPT PROFILE LOG\n");
        return 2;
    }
    umask(0077);
    chdir("/");

    @autoreleasepool {
        NSString *config_path = @(argv[1]);
        NSString *state_directory = [config_path stringByDeletingLastPathComponent];
        pid_path = [state_directory stringByAppendingPathComponent:@"helper.pid"];
        status_path = [state_directory stringByAppendingPathComponent:@"status.json"];
        text_log_path = @(argv[4]);
        NSString *log_directory = [text_log_path stringByDeletingLastPathComponent];
        struct stat log_directory_attributes;
        if (stat(log_directory.fileSystemRepresentation, &log_directory_attributes) == 0) {
            log_owner_uid = log_directory_attributes.st_uid;
            log_owner_gid = log_directory_attributes.st_gid;
        }

        NSData *config_data = [NSData dataWithContentsOfFile:config_path];
        NSData *script_data = [NSData dataWithContentsOfFile:@(argv[2])];
        NSData *profile_data = [NSData dataWithContentsOfFile:@(argv[3])];
        NSDictionary *configuration = config_data != nil
            ? [NSJSONSerialization JSONObjectWithData:config_data options:0 error:nil] : nil;
        NSDictionary *profile = profile_data != nil
            ? [NSJSONSerialization JSONObjectWithData:profile_data options:0 error:nil] : nil;
        NSString *source = [[NSString alloc] initWithData:script_data encoding:NSUTF8StringEncoding];
        session_id = [configuration[@"session_id"] isKindOfClass:NSString.class] ? configuration[@"session_id"] : @"";
        helper_backend = [configuration[@"backend"] isKindOfClass:NSString.class] ? configuration[@"backend"] : @"";
        NSString *bundle_id = configuration[@"bundle_id"];
        NSDictionary *direct = configuration[@"direct"];
        if (![configuration isKindOfClass:NSDictionary.class] || session_id.length == 0 ||
            !([helper_backend isEqualToString:@"gadget"] || [helper_backend isEqualToString:@"server"]) ||
            ![bundle_id isKindOfClass:NSString.class] || ![direct isKindOfClass:NSDictionary.class] ||
            ![profile isKindOfClass:NSDictionary.class] || source.length == 0) {
            write_status(@"error", @"launcher 配置或内置资源无效。", nil);
            fprintf(stderr, "error: launcher configuration or resources are invalid\n");
            return 2;
        }
        if (![profile[@"bundle_id"] isEqual:bundle_id]) {
            NSString *error = [NSString stringWithFormat:@"内置 profile 面向 %@，不能启动 %@。",
                               profile[@"bundle_id"] ?: @"unknown", bundle_id];
            write_status(@"error", error, nil);
            fprintf(stderr, "error: %s\n", error.UTF8String);
            return 2;
        }
        NSString *lock_path = [state_directory stringByAppendingPathComponent:@"helper.lock"];
        singleton_lock_fd = open(lock_path.fileSystemRepresentation, O_RDWR | O_CREAT, 0600);
        if (singleton_lock_fd < 0 || flock(singleton_lock_fd, LOCK_EX | LOCK_NB) != 0) {
            if (singleton_lock_fd >= 0) close(singleton_lock_fd);
            singleton_lock_fd = -1;
            write_status(@"error", @"已有一个 helper 会话正在运行；请先停止旧会话。", nil);
            fprintf(stderr, "error: another helper session is already running\n");
            return 2;
        }
        NSError *logs_error = nil;
        if (![[NSFileManager defaultManager] createDirectoryAtPath:log_directory
                                        withIntermediateDirectories:YES
                                                         attributes:@{NSFilePosixPermissions: @0700}
                                                              error:&logs_error]) {
            write_status(@"error", [NSString stringWithFormat:@"无法创建日志目录：%@", logs_error.localizedDescription], nil);
            return 2;
        }
        make_log_item_accessible(log_directory, 0700);
        NSString *event_name = [NSString stringWithFormat:@"events-%.0f-%@.jsonl",
                                [[NSDate date] timeIntervalSince1970], session_id];
        event_log_path = [log_directory stringByAppendingPathComponent:event_name];
        if (![[NSData data] writeToFile:event_log_path options:NSDataWritingAtomic error:&logs_error]) {
            write_status(@"error", [NSString stringWithFormat:@"无法创建事件日志：%@", logs_error.localizedDescription], nil);
            return 2;
        }
        make_log_item_accessible(event_log_path, 0600);
        event_log_handle = [NSFileHandle fileHandleForWritingAtPath:event_log_path];
        [event_log_handle seekToEndOfFile];
        if (event_log_handle == nil) {
            write_status(@"error", @"无法打开事件日志。", nil);
            return 2;
        }

        int log_fd = open(argv[4], O_WRONLY | O_CREAT | O_APPEND, 0600);
        if (log_fd < 0) {
            write_status(@"error", [NSString stringWithFormat:@"无法打开 helper 日志：%s", strerror(errno)], nil);
            return 2;
        }
        fchmod(log_fd, 0600);
        if (log_owner_uid != (uid_t)-1 && log_owner_gid != (gid_t)-1)
            fchown(log_fd, log_owner_uid, log_owner_gid);
        if (dup2(log_fd, STDOUT_FILENO) < 0 || dup2(log_fd, STDERR_FILENO) < 0) {
            close(log_fd);
            write_status(@"error", [NSString stringWithFormat:@"无法重定向 helper 日志：%s", strerror(errno)], nil);
            return 2;
        }
        if (log_fd > STDERR_FILENO) close(log_fd);
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
        fprintf(stdout, "\n=== OpenBachelor session %s backend=%s started=%.3f ===\n",
                session_id.UTF8String, helper_backend.UTF8String,
                [[NSDate date] timeIntervalSince1970]);

        NSError *directory_error = nil;
        capture_directory = [log_directory stringByAppendingPathComponent:@"captured"];
        NSString *bodies = [capture_directory stringByAppendingPathComponent:@"bodies"];
        if (![[NSFileManager defaultManager] createDirectoryAtPath:bodies withIntermediateDirectories:YES
                                                        attributes:@{NSFilePosixPermissions: @0700}
                                                             error:&directory_error]) {
            NSString *error = [NSString stringWithFormat:@"无法创建抓包目录：%@", directory_error.localizedDescription];
            write_status(@"error", error, nil);
            fprintf(stderr, "error: %s\n", error.UTF8String);
            return 2;
        }
        make_log_item_accessible(capture_directory, 0700);
        make_log_item_accessible(bodies, 0700);
        NSString *pid_text = [NSString stringWithFormat:@"%d\n", getpid()];
        if (![pid_text writeToFile:pid_path atomically:YES encoding:NSUTF8StringEncoding error:nil]) {
            write_status(@"error", @"无法写入 helper PID 文件。", nil);
            return 2;
        }
        chmod(pid_path.fileSystemRepresentation, 0600);
        write_status(@"starting", @"helper 已启动，正在初始化 Frida Core…", nil);
        install_signal_handlers();
        int result = run_session(configuration, profile, source);
        [event_log_handle synchronizeFile];
        [event_log_handle closeFile];
        event_log_handle = nil;
        remove_own_pid_file();
        flock(singleton_lock_fd, LOCK_UN);
        close(singleton_lock_fd);
        singleton_lock_fd = -1;
        fprintf(stdout, "stopped\n");
        fflush(stdout);
        fflush(stderr);
        fsync(STDOUT_FILENO);
        return result;
    }
}
