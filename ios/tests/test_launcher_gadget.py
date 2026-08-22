import json
import plistlib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
GADGET_TEMPLATE = PROJECT_ROOT / "launcher" / "Gadget"
BUILD_SCRIPT = PROJECT_ROOT / "launcher" / "build.sh"
LAUNCHER_SOURCE = PROJECT_ROOT / "launcher" / "App" / "LauncherApp.m"
LAUNCHER_INFO = PROJECT_ROOT / "launcher" / "App" / "Info.plist"
LAUNCHER_ENTITLEMENTS = PROJECT_ROOT / "launcher" / "App" / "launcher.entitlements"
INJECTOR_SOURCE = PROJECT_ROOT / "launcher" / "Injector" / "OpenBachelorInjector.m"
HELPER_SOURCE = PROJECT_ROOT / "launcher" / "Helper" / "OpenBachelorHelper.m"
OVERLAY_SOURCE = PROJECT_ROOT / "frida" / "floating-overlay.ts"
DIRECT_TRAINER_SOURCE = PROJECT_ROOT / "frida" / "direct-trainer.ts"
PACKAGE_JSON = PROJECT_ROOT / "package.json"
GADGET_BOOTSTRAP_SOURCE = GADGET_TEMPLATE / "FridaGadgetBootstrap.c"
GADGET_EXCEPTOR_PATCH = GADGET_TEMPLATE / "patch-frida-exceptor.mjs"


def test_trollfools_gadget_template_matches_launcher_protocol():
    config = json.loads(
        GADGET_TEMPLATE.joinpath("FridaGadget.config").read_text(encoding="utf-8")
    )

    assert config == {
        "interaction": {
            "type": "listen",
            "address": "127.0.0.1",
            "port": 27043,
            "on_load": "resume",
        },
        "teardown": "full",
    }


def test_trollfools_gadget_is_packaged_as_a_framework():
    with GADGET_TEMPLATE.joinpath("Info.plist").open("rb") as stream:
        info = plistlib.load(stream)

    assert info["CFBundlePackageType"] == "FMWK"
    assert info["CFBundleExecutable"] == "FridaGadget"
    assert info["CFBundleShortVersionString"] == "17.9.1"
    assert GADGET_TEMPLATE.joinpath(".openbachelor-coretrust-v3").read_text(
        encoding="ascii"
    ).strip() == "3"


def test_trollfools_gadget_uses_compatible_arm64_slice_and_is_resigned():
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    verify_upstream = build_script.index(
        'lipo "$gadget_payload" -verify_arch arm64 arm64e'
    )
    thin_arm64 = build_script.index(
        'lipo "$gadget_payload" -thin arm64'
    )
    install_name = build_script.index(
        "install_name_tool -id @rpath/FridaGadget.framework/FridaGadgetCore.dylib"
    )
    pseudo_sign = build_script.index('ldid -S "$binary"')

    assert verify_upstream < thin_arm64 < install_name < pseudo_sign
    assert '[[ "$gadget_archs" != "arm64" ]]' in build_script
    assert '[[ "$gadget_signature_slices" -ne 1 ]]' in build_script
    assert 'ldid -h "$binary"' in build_script


def test_gadget_bootstrap_defers_frida_runtime_initialization():
    bootstrap = GADGET_BOOTSTRAP_SOURCE.read_text(encoding="utf-8")
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    injector = INJECTOR_SOURCE.read_text(encoding="utf-8")

    assert "__attribute__((constructor))" in bootstrap
    assert "2 * NSEC_PER_SEC" in bootstrap
    assert "dispatch_after_f" in bootstrap
    assert 'dlopen(path, RTLD_NOW | RTLD_LOCAL)' in bootstrap
    assert 'payload_name[] = "/FridaGadgetCore.dylib"' in bootstrap
    assert 'gadget_payload="$gadget_framework/FridaGadgetCore.dylib"' in build_script
    assert 'OBGadgetPayloadName = @"FridaGadgetCore.dylib"' in injector
    assert "OBSignForCoreTrust(stagingPayload" in injector


def test_gadget_exceptor_patch_is_version_locked_and_applied_before_resigning():
    patcher = GADGET_EXCEPTOR_PATCH.read_text(encoding="utf-8")
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert 'offset: 0x3627c, expected: "c8000037", replacement: "06000014"' in patcher
    assert 'offset: 0x4ecb0, expected: "6f010094"' in patcher
    assert 'offset: 0x4ecc0, expected: "6b010094"' in patcher
    assert patcher.count('replacement: "1f2003d5"') == 2
    assert 'payloadUuid = Buffer.from("4f424733455843338000000000000001"' in patcher
    assert 'command === 0x1b' in patcher
    patch = build_script.index('node "$SCRIPT_DIR/Gadget/patch-frida-exceptor.mjs"')
    install_name = build_script.index(
        "install_name_tool -id @rpath/FridaGadget.framework/FridaGadgetCore.dylib"
    )
    pseudo_sign = build_script.index('ldid -S "$binary"')
    assert patch < install_name < pseudo_sign


def test_launcher_packages_pinned_trollfools_injector_tools():
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")

    assert "TROLLFOOLS_COMMIT=1a4d4a301e096092f20c760fb2903c8f4db37240" in build_script
    assert "TROLLFOOLS_SHA256=9c170dde646381d458dd3b00c4258fbca4994ad14ab1c6fc59cae8c2e8595e12" in build_script
    for tool in ("ct_bypass", "insert_dylib", "ldid"):
        assert tool in build_script
    assert 'tipa_output="$DIST_DIR/OpenBachelorLauncher.tipa"' in build_script
    assert 'cp -R "$gadget_framework" "$injector_resources/"' in build_script


def test_launcher_build_auto_increments_version_after_verified_packaging():
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")

    calculate = build_script.index(
        'next_launcher_version="${version_parts[1]}.${version_parts[2]}.'
    )
    stage = build_script.index(
        "plutil -replace CFBundleShortVersionString "
        '-string "$next_launcher_version" "$app/Info.plist"'
    )
    verify = build_script.index(
        "packaged_version=$(plutil -extract CFBundleShortVersionString "
        'raw -o - "$packaged_info")'
    )
    persist = build_script.index('mv "$next_info_plist" "$LAUNCHER_INFO_PLIST"')

    assert calculate < stage < verify < persist
    assert 'next_launcher_build=$((current_launcher_build + 1))' in build_script
    assert '[[ "$packaged_version" != "$next_launcher_version"' in build_script
    assert "perl -0pi" in build_script


def test_launchservices_stays_out_of_root_injector():
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    injector = INJECTOR_SOURCE.read_text(encoding="utf-8")

    launcher_compile = build_script.index('"$SCRIPT_DIR/App/LauncherApp.m"')
    helper_compile = build_script.index('"$SCRIPT_DIR/Helper/OpenBachelorHelper.m"')
    injector_compile = build_script.index('"$SCRIPT_DIR/Injector/OpenBachelorInjector.m"')
    packaging = build_script.index('cp "$SCRIPT_DIR/App/Info.plist"')

    assert "-framework CoreServices" in build_script[launcher_compile:helper_compile]
    assert "-framework CoreServices" not in build_script[injector_compile:packaging]
    assert "LSApplicationProxy" not in injector
    assert 'applicationRoot = @"/var/containers/Bundle/Application"' in injector
    assert 'info[@"CFBundleIdentifier"]' in injector
    assert "OBTeamIDForExecutable" in injector


def test_launcher_has_root_persona_and_app_bundle_access():
    with LAUNCHER_ENTITLEMENTS.open("rb") as stream:
        entitlements = plistlib.load(stream)

    assert entitlements["com.apple.private.persona-mgmt"] is True
    assert entitlements["com.apple.private.security.storage.AppBundles"] is True
    assert entitlements["com.apple.security.exception.files.absolute-path.read-write"] == ["/"]
    assert entitlements["com.apple.frontboard.launchapplications"] is True
    assert entitlements["com.apple.springboard.launchapplications"] is True


def test_gadget_resume_mode_does_not_require_helper_to_resume_target():
    helper = HELPER_SOURCE.read_text(encoding="utf-8")

    assert "gboolean resume_after_load = FALSE;" in helper
    assert "on_load=resume" in helper


def test_gadget_and_jailbreak_server_use_distinct_ports():
    helper = HELPER_SOURCE.read_text(encoding="utf-8")

    assert 'OBGadgetEndpoint = "127.0.0.1:27043"' in helper
    assert 'OBServerEndpoint = "127.0.0.1:27042"' in helper
    assert "gadget_backend ? OBGadgetEndpoint : OBServerEndpoint" in helper


def test_jailbreak_backend_recovers_from_stale_pid_and_spawn_failure():
    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")

    assert "frida_application_query_options_set_scope(options, FRIDA_SCOPE_FULL)" in helper
    assert "frida_process_query_options_set_scope(options, FRIDA_SCOPE_FULL)" in helper
    assert "find_application_process" in helper
    assert "refresh_server_target" in helper
    assert "frida_spawn_options_set_argv(spawn_options, spawn_argv, 1)" in helper
    assert 'write_status(@"waiting_target"' in helper
    assert "OBServerAttachAttempts" in helper
    assert '[backend isEqualToString:@"server"] && [state isEqualToString:@"waiting_target"]' in launcher


def test_direct_agent_packages_a_native_floating_console():
    direct = (PROJECT_ROOT / "frida" / "direct.ts").read_text(encoding="utf-8")
    overlay = OVERLAY_SOURCE.read_text(encoding="utf-8")
    package = json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))

    assert package["devDependencies"]["frida-objc-bridge"] == "8.0.6"
    assert 'from "./floating-overlay"' in direct
    assert 'floating_gui: false' in direct
    assert 'floating_log_console: true' in direct
    assert 'logConsoleVisible: conf.bool("floating_log_console", true)' in direct
    assert 'recv("shutdown"' in direct
    assert 'import ObjC from "frida-objc-bridge"' in overlay
    assert "initWithWindowScene_" in overlay
    assert "setWindowLevel_" in overlay
    assert "window.setHidden_(false)" in overlay
    assert "makeKeyAndVisible" not in overlay
    assert 'retryMount("objc-runtime-not-loaded")' in overlay
    assert "rootController.view().addSubview_(panel)" in overlay
    assert "UIPanGestureRecognizer" in overlay
    assert 'button("抓包 开"' in overlay
    assert 'button("日志 开"' in overlay
    assert 'button("复制"' in overlay
    assert 'button("清空"' in overlay
    assert 'view cleared; saved logs kept on disk' in overlay


def test_launcher_exposes_transport_independent_battle_finish_blocker():
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    direct = (PROJECT_ROOT / "frida" / "direct.ts").read_text(encoding="utf-8")
    profile = json.loads(
        PROJECT_ROOT.joinpath("profiles/arknights-2.7.61-59.json").read_text(
            encoding="utf-8"
        )
    )

    assert 'switchRow:@"不上传战斗记录"' in launcher
    assert '@"block_battle_finish_upload": @(_battleFinishBlockSwitch.on)' in launcher
    assert 'forKey:@"block_battle_finish_upload"' in launcher
    assert 'block_battle_finish_upload: false' in direct
    assert 'isBlockedBattleUploadUrl(url)' in direct
    assert 'battlefinish|savebattlereplay' in direct
    assert 'Interceptor.replace(target, replacement)' in direct
    assert 'event: "battle-finish-blocked"' in direct
    assert "QUEST_BATTLE_FINISH_RESPONSE" in direct
    assert "apFailReturn: 0" in direct
    assert "expScale: 1.2" in direct
    assert "goldScale: 1.2" in direct
    assert 'battle_finish_block_enabled' in helper
    assert profile["offsets"]["networkerPostImplMoveNext"] == "0x6e78c8c"
    assert profile["layout"]["networkerPostImplUrl"] == 0x20
    assert profile["layout"]["networkerPostImplOutResponse"] == 0x40
    assert profile["layout"]["webHttpResponseText"] == 0x28


def test_launcher_exposes_profile_checked_direct_trainer_controls():
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    direct = (PROJECT_ROOT / "frida" / "direct.ts").read_text(encoding="utf-8")
    overlay = OVERLAY_SOURCE.read_text(encoding="utf-8")
    trainer = DIRECT_TRAINER_SOURCE.read_text(encoding="utf-8")
    profile = json.loads(
        PROJECT_ROOT.joinpath("profiles/arknights-2.7.61-59.json").read_text(
            encoding="utf-8"
        )
    )

    assert 'switchRow:@"Trainer 控制"' in launcher
    assert 'switchRow:@"悬浮窗滚动日志"' in launcher
    assert '@"floating_log_console": @(_logConsoleSwitch.on)' in launcher
    assert '@"trainer_enabled": @(_trainerSwitch.on)' in launcher
    assert 'button("Trainer"' in overlay
    assert "showTrainer" in overlay
    assert 'unlock_fps: "解锁 120 FPS"' in overlay
    assert 'tas_step: "TAS 步进"' in overlay
    assert 'title: "战斗节奏"' in overlay
    assert 'ObjC.selector("toggleTrainerCommand:")' in overlay
    assert 'ObjC.selector("stepTicks:")' in overlay
    assert 'ObjC.selector("stepFrames:")' in overlay
    assert 'trainerStepCountField.setKeyboardType_(4)' in overlay
    assert 'requestTrainerStep: (unit, count)' in direct
    assert 'requestStep(unit: DirectTrainerStepUnit, count: number)' in trainer
    assert '"trainerBattleControllerFixedUpdate"' in trainer
    assert "const controllerCaptureReady = uiAwakeHook || uiUpdateHook" in trainer
    assert "&& controllerCaptureReady" in trainer
    assert "&& uiDestroyHook" not in trainer
    assert 'supported.has("tas_step") || commands.length > 0' in overlay
    assert 'payload.event === "battle-timeline"' in overlay
    assert 'String(Math.max(0, Math.trunc(battleTimeline!.ticks)))' in overlay
    assert 'options.reportAction(expanded ? "expand" : "collapse")' not in overlay
    assert "installDirectTrainerHooks" in (
        PROJECT_ROOT / "frida" / "direct.ts"
    ).read_text(encoding="utf-8")
    assert 'event: "trainer-ready"' in trainer
    assert '@"trainer_commands": trainerCommands' in helper
    assert '@"trainer_step_units": trainerStepUnits' in helper
    assert len(
        [key for key in profile["offsets"] if key.startswith("trainer")]
    ) == 36
    assert {
        "extraBattleControllerGetFixedFrameCnt",
        "extraBattleControllerGetFixedPlayTime",
        "extraBattleControllerUpdate",
        "trainerApplicationSetTargetFrameRate",
        "trainerBattleControllerSetTimeScale",
        "trainerBattleControllerOnSpeedLevelChanged",
        "trainerBattleControllerFixedUpdate",
        "trainerUiControllerUpdate",
    }.issubset(profile["offsets"])


def test_launcher_persists_and_archives_session_logs():
    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    with LAUNCHER_INFO.open("rb") as stream:
        info = plistlib.load(stream)

    assert "append_agent_event(envelope, data)" in helper
    assert '@"events-%.0f-%@.jsonl"' in helper
    assert "O_WRONLY | O_CREAT | O_APPEND" in helper
    assert "O_TRUNC" not in helper
    assert '[event_log_handle synchronizeFile]' in helper
    assert "fsync(STDOUT_FILENO)" in helper
    assert 'frida_script_post(script, "{\\"type\\":\\"shutdown\\"}"' in helper
    assert "archiveCurrentLog" in launcher
    assert "NSDocumentDirectory" in launcher
    assert 'stringByAppendingPathComponent:@"Logs"' in launcher
    assert 'setTitle:@"打开日志位置"' in launcher
    assert "initForOpeningContentTypes" in launcher
    assert "picker.directoryURL" in launcher
    assert info["UIFileSharingEnabled"] is True
    assert info["LSSupportsOpeningDocumentsInPlace"] is True
    assert "NSString *log_directory = [text_log_path stringByDeletingLastPathComponent]" in helper
    assert "make_log_item_accessible(event_log_path, 0600)" in helper
    assert "fchown(log_fd, log_owner_uid, log_owner_gid)" in helper
    assert '@"floating_gui": @(_overlaySwitch.on || _trainerSwitch.on)' in launcher


def test_helper_does_not_fork_after_linked_runtimes_initialize():
    helper = HELPER_SOURCE.read_text(encoding="utf-8")
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")

    assert "fork(" not in helper
    assert "setsid(" not in helper
    assert "posix_spawn(&pid, helper.fileSystemRepresentation" in launcher
    assert "waitpid(pid, &status, 0)" in launcher


def test_gadget_launch_does_not_wait_for_helper_status_poll():
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    prepared = launcher.index("- (void)startPreparedSession")
    install = launcher.index("- (void)installGadget", prepared)
    prepared_body = launcher[prepared:install]

    assert "dispatch_after" in prepared_body
    assert "[self openTargetApplication]" in prepared_body


def test_launcher_auto_installs_before_starting_gadget_session():
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    start = launcher.index("- (void)startSession")
    prepared = launcher.index("- (void)startPreparedSession")
    auto_install = launcher.index('[self runInjectorCommand:@"install"', start)

    assert start < auto_install < prepared
    assert "拒绝修改" in launcher


def test_injector_is_fail_closed_and_recoverable():
    injector = INJECTOR_SOURCE.read_text(encoding="utf-8")

    assert 'OBBackupSuffix = @".openbachelor-gadget.bak"' in injector
    assert "LC_ENCRYPTION_INFO_64" in injector
    assert "LC_CODE_SIGNATURE" in injector
    assert "OBReadExactly" in injector
    assert "pread(fd" in injector
    assert "NSDataReadingMapped" not in injector
    assert "if ([candidate[@\"protected\"] boolValue]" in injector
    assert "OBAtomicRestore(backup, target" in injector
    assert '@"insert_dylib"' in injector
    assert '@"--weak"' in injector
    assert "OBLoadsGadgetWeakly(patchedImage)" in injector
    assert '@"ct_bypass"' in injector
    assert 'if (![image[@"signed"] boolValue]' in injector
    assert "由外部工具注入且没有 Launcher 备份" in injector


def test_privileged_children_have_valid_der_signing_and_safe_environment():
    build_script = BUILD_SCRIPT.read_text(encoding="utf-8")
    launcher = LAUNCHER_SOURCE.read_text(encoding="utf-8")
    injector = INJECTOR_SOURCE.read_text(encoding="utf-8")

    assert "--generate-entitlement-der" in build_script
    assert 'codesign --verify --strict "$app/OpenBachelorInjector"' in build_script
    assert 'setenv("DISABLE_TWEAKS", "1", 1)' in launcher
    assert 'setenv("DISABLE_TWEAKS", "1", 1)' in injector
    assert "injector-stage: inspecting-mach-o" in injector


def test_injector_avoids_legacy_unity_strong_load_crash_path():
    injector = INJECTOR_SOURCE.read_text(encoding="utf-8")

    assert "OBIsHighRiskInjectionTarget" in injector
    assert "leftHighRisk ? NSOrderedDescending : NSOrderedAscending" in injector
    assert "OBMigrateLegacyOwnedInjections" in injector
    assert "forceOwnedMigration" in injector
    assert 'OBSigningMarkerName = @".openbachelor-coretrust-v3"' in injector
    assert "forceOwnedMigration || !OBLoadsGadgetWeakly(record)" in injector
    assert "OBIsHighRiskInjectionTarget(record)" in injector
    assert "OBAtomicRestore(backup, target" in injector
