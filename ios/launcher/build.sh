#!/bin/zsh
set -euo pipefail

SCRIPT_DIR=${0:A:h}
IOS_DIR=${SCRIPT_DIR:h}
DIST_DIR="$SCRIPT_DIR/dist"
BUILD_DIR="$SCRIPT_DIR/build"
CACHE_DIR="$SCRIPT_DIR/.cache"
DEVKIT_VERSION=17.9.1
DEVKIT_NAME="frida-core-devkit-${DEVKIT_VERSION}-ios-arm64.tar.xz"
DEVKIT_SHA256=4e7fa9953a50e64887ffaec828666662e38904b0042cfde2eb3f446f99d83c55
DEVKIT_HEADER_SHA256=b5a12f1833320b97a2def970f7bc6778747078f6c2af53e2d45064edd64a1d8d
DEVKIT_LIBRARY_SHA256=31ca38cdc695b591a5015a178ccfa508e047f01cee611f03b72eff9e24ad278d
DEVKIT_URL="https://github.com/frida/frida/releases/download/${DEVKIT_VERSION}/${DEVKIT_NAME}"
DEVKIT_ARCHIVE=${FRIDA_DEVKIT_ARCHIVE:-"$CACHE_DIR/$DEVKIT_NAME"}
DEVKIT_DIR="$BUILD_DIR/devkit"
DEVKIT_SOURCE_DIR=${FRIDA_DEVKIT_DIR:-}
GADGET_NAME="frida-gadget-${DEVKIT_VERSION}-ios-universal.dylib.xz"
GADGET_SHA256=4707dd225c5d6f3ca7c040b2d2c1762bfc81df84c022281bc8700e468ed533aa
GADGET_BINARY_SHA256=bdda5e5dc36c6b3d0b1f181c44c9256b5a8f6ff56c831bce351eca948c08bb73
GADGET_URL="https://github.com/frida/frida/releases/download/${DEVKIT_VERSION}/${GADGET_NAME}"
GADGET_ARCHIVE=${FRIDA_GADGET_ARCHIVE:-"$CACHE_DIR/$GADGET_NAME"}
TROLLFOOLS_COMMIT=1a4d4a301e096092f20c760fb2903c8f4db37240
TROLLFOOLS_NAME="trollfools-${TROLLFOOLS_COMMIT}.tar.gz"
TROLLFOOLS_SHA256=9c170dde646381d458dd3b00c4258fbca4994ad14ab1c6fc59cae8c2e8595e12
TROLLFOOLS_URL="https://github.com/Lessica/TrollFools/archive/${TROLLFOOLS_COMMIT}.tar.gz"
TROLLFOOLS_ARCHIVE=${TROLLFOOLS_ARCHIVE:-"$CACHE_DIR/$TROLLFOOLS_NAME"}
TROLLFOOLS_SOURCE_DIR=${TROLLFOOLS_SOURCE_DIR:-}
TROLLFOOLS_CT_BYPASS_SHA256=e1cbd8b8b0f15990e48375dc34f42b26ad2930d20e65cdbdf21842cabdcbbc97
TROLLFOOLS_INSERT_DYLIB_SHA256=317c0e0125623833e2bd5e6c9b3a77c7455a2a27a3ae9d87a27fad0cfa664b48
TROLLFOOLS_LDID_SHA256=e31d728372d1d5150fda3b577730616a7b8136fbaa067e0f4a4fa2d6b5f97b57
TROLLFOOLS_LIBCRYPTO_SHA256=a5d86da73d98c926849a31bee5846a4f5645fb164ae8353d123acdcf559b5081
TROLLFOOLS_LIBIOSEXEC_SHA256=47d341ce672c114072f6ccc1d9f6dcc323e798d4798e800e1e8bf42ea281ef50
DOWNLOAD_PROXY=${OPENBACHELOR_DOWNLOAD_PROXY:-${FRIDA_DOWNLOAD_PROXY:-}}
PROFILE=${OPENBACHELOR_PROFILE:-"$IOS_DIR/profiles/arknights-2.7.61-59.json"}

mkdir -p "$CACHE_DIR" "$BUILD_DIR" "$DIST_DIR"
required_tools=(awk codesign curl ldid lipo node plutil shasum tar unzip xcrun xz zip)
for tool in "${required_tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    print -u2 "error: required build tool not found: $tool"
    exit 1
  fi
done

verify_sha256() {
  local file_path=$1
  local expected=$2
  local label=$3
  local actual
  actual=$(shasum -a 256 "$file_path" | awk '{print $1}')
  if [[ "$actual" != "$expected" ]]; then
    print -u2 "error: $label SHA-256 mismatch: $actual"
    exit 1
  fi
}

if [[ -n "$DEVKIT_SOURCE_DIR" ]]; then
  DEVKIT_SOURCE_DIR=${DEVKIT_SOURCE_DIR:A}
  for file in frida-core.h libfrida-core.a; do
    if [[ ! -f "$DEVKIT_SOURCE_DIR/$file" ]]; then
      print -u2 "error: FRIDA_DEVKIT_DIR is missing $file: $DEVKIT_SOURCE_DIR"
      exit 1
    fi
  done
  verify_sha256 "$DEVKIT_SOURCE_DIR/frida-core.h" "$DEVKIT_HEADER_SHA256" "Frida devkit header"
  verify_sha256 "$DEVKIT_SOURCE_DIR/libfrida-core.a" "$DEVKIT_LIBRARY_SHA256" "Frida devkit library"
else
  if [[ ! -f "$DEVKIT_ARCHIVE" ]]; then
    if [[ -n "${FRIDA_DEVKIT_ARCHIVE:-}" ]]; then
      print -u2 "error: FRIDA_DEVKIT_ARCHIVE does not exist: $DEVKIT_ARCHIVE"
      exit 1
    fi
    curl_args=(-fL --retry 3 --connect-timeout 20)
    if [[ -n "$DOWNLOAD_PROXY" ]]; then
      curl_args+=(-x "$DOWNLOAD_PROXY")
    fi
    partial_archive="$DEVKIT_ARCHIVE.partial.$$"
    trap 'rm -f "$partial_archive"' EXIT INT TERM
    curl "${curl_args[@]}" "$DEVKIT_URL" -o "$partial_archive"
    verify_sha256 "$partial_archive" "$DEVKIT_SHA256" "downloaded Frida devkit"
    mv "$partial_archive" "$DEVKIT_ARCHIVE"
    trap - EXIT INT TERM
  fi
  verify_sha256 "$DEVKIT_ARCHIVE" "$DEVKIT_SHA256" "Frida devkit archive"
fi

if [[ ! -f "$GADGET_ARCHIVE" ]]; then
  if [[ -n "${FRIDA_GADGET_ARCHIVE:-}" ]]; then
    print -u2 "error: FRIDA_GADGET_ARCHIVE does not exist: $GADGET_ARCHIVE"
    exit 1
  fi
  gadget_curl_args=(-fL --retry 3 --connect-timeout 20)
  if [[ -n "$DOWNLOAD_PROXY" ]]; then
    gadget_curl_args+=(-x "$DOWNLOAD_PROXY")
  fi
  partial_gadget="$GADGET_ARCHIVE.partial.$$"
  trap 'rm -f "$partial_gadget"' EXIT INT TERM
  curl "${gadget_curl_args[@]}" "$GADGET_URL" -o "$partial_gadget"
  verify_sha256 "$partial_gadget" "$GADGET_SHA256" "downloaded Frida Gadget"
  mv "$partial_gadget" "$GADGET_ARCHIVE"
  trap - EXIT INT TERM
fi
verify_sha256 "$GADGET_ARCHIVE" "$GADGET_SHA256" "Frida Gadget archive"

if [[ -n "$TROLLFOOLS_SOURCE_DIR" ]]; then
  TROLLFOOLS_SOURCE_DIR=${TROLLFOOLS_SOURCE_DIR:A}
  if [[ ! -d "$TROLLFOOLS_SOURCE_DIR/TrollFools" ]]; then
    print -u2 "error: TROLLFOOLS_SOURCE_DIR is not a TrollFools source tree: $TROLLFOOLS_SOURCE_DIR"
    exit 1
  fi
else
  if [[ ! -f "$TROLLFOOLS_ARCHIVE" ]]; then
    if [[ -n "${TROLLFOOLS_ARCHIVE:-}" && "$TROLLFOOLS_ARCHIVE" != "$CACHE_DIR/$TROLLFOOLS_NAME" ]]; then
      print -u2 "error: TROLLFOOLS_ARCHIVE does not exist: $TROLLFOOLS_ARCHIVE"
      exit 1
    fi
    trollfools_curl_args=(-fL --retry 3 --connect-timeout 20)
    if [[ -n "$DOWNLOAD_PROXY" ]]; then
      trollfools_curl_args+=(-x "$DOWNLOAD_PROXY")
    fi
    partial_trollfools="$TROLLFOOLS_ARCHIVE.partial.$$"
    trap 'rm -f "$partial_trollfools"' EXIT INT TERM
    curl "${trollfools_curl_args[@]}" "$TROLLFOOLS_URL" -o "$partial_trollfools"
    verify_sha256 "$partial_trollfools" "$TROLLFOOLS_SHA256" "downloaded TrollFools source"
    mv "$partial_trollfools" "$TROLLFOOLS_ARCHIVE"
    trap - EXIT INT TERM
  fi
  verify_sha256 "$TROLLFOOLS_ARCHIVE" "$TROLLFOOLS_SHA256" "TrollFools source archive"
  trollfools_extract="$BUILD_DIR/TrollFoolsSource"
  rm -rf "$trollfools_extract"
  mkdir -p "$trollfools_extract"
  tar -xzf "$TROLLFOOLS_ARCHIVE" --strip-components=1 -C "$trollfools_extract"
  TROLLFOOLS_SOURCE_DIR="$trollfools_extract"
fi
trollfools_tools="$TROLLFOOLS_SOURCE_DIR/TrollFools"
verify_sha256 "$trollfools_tools/ct_bypass" "$TROLLFOOLS_CT_BYPASS_SHA256" "TrollFools ct_bypass"
verify_sha256 "$trollfools_tools/insert_dylib" "$TROLLFOOLS_INSERT_DYLIB_SHA256" "TrollFools insert_dylib"
verify_sha256 "$trollfools_tools/ldid" "$TROLLFOOLS_LDID_SHA256" "TrollFools ldid"
verify_sha256 "$trollfools_tools/libcrypto.3.dylib" "$TROLLFOOLS_LIBCRYPTO_SHA256" "TrollFools libcrypto"
verify_sha256 "$trollfools_tools/libiosexec.1.dylib" "$TROLLFOOLS_LIBIOSEXEC_SHA256" "TrollFools libiosexec"
if [[ ! -x "$IOS_DIR/node_modules/.bin/frida-compile" ]]; then
  print -u2 "error: frida-compile not found; run 'npm ci' in $IOS_DIR"
  exit 1
fi
if [[ ! -f "$PROFILE" ]]; then
  print -u2 "error: direct profile not found: $PROFILE"
  exit 1
fi
plutil -lint "$SCRIPT_DIR/App/Info.plist" "$SCRIPT_DIR/App/launcher.entitlements" \
  "$SCRIPT_DIR/Helper/helper.entitlements" "$SCRIPT_DIR/Gadget/Info.plist" \
  "$SCRIPT_DIR/Injector/tool.entitlements" >/dev/null
profile_bundle=$(node -e '
  const fs = require("fs");
  const profile = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (profile.schema !== 1 || typeof profile.id !== "string" || profile.id.length === 0)
    throw new Error("direct profile has invalid schema or id");
  if (typeof profile.bundle_id !== "string" || profile.bundle_id.length === 0)
    throw new Error("direct profile has no bundle_id");
  if (!profile.module || typeof profile.module.name !== "string" ||
      typeof profile.module.uuid !== "string" || profile.module.uuid.length === 0)
    throw new Error("direct profile has invalid module identity");
  process.stdout.write(profile.bundle_id);
' "$PROFILE")

"$IOS_DIR/node_modules/.bin/frida-compile" -S "$IOS_DIR/frida/direct.ts" -o "$BUILD_DIR/direct.js"
rm -rf "$BUILD_DIR/Payload"
if [[ -n "$DEVKIT_SOURCE_DIR" ]]; then
  if [[ "$DEVKIT_SOURCE_DIR" != "${DEVKIT_DIR:A}" ]]; then
    rm -rf "$DEVKIT_DIR"
    mkdir -p "$DEVKIT_DIR"
    cp "$DEVKIT_SOURCE_DIR/frida-core.h" "$DEVKIT_SOURCE_DIR/libfrida-core.a" "$DEVKIT_DIR/"
  fi
else
  rm -rf "$DEVKIT_DIR"
  mkdir -p "$DEVKIT_DIR"
  tar -xf "$DEVKIT_ARCHIVE" -C "$DEVKIT_DIR"
fi
mkdir -p "$BUILD_DIR/Payload/OpenBachelorLauncher.app"

sdk=$(xcrun --sdk iphoneos --show-sdk-path)
cc=(xcrun --sdk iphoneos clang -arch arm64 -miphoneos-version-min=15.0 -isysroot "$sdk")
app="$BUILD_DIR/Payload/OpenBachelorLauncher.app"

"${cc[@]}" -fobjc-arc -Wall -Wextra -Werror "$SCRIPT_DIR/App/LauncherApp.m" \
  -framework UIKit -framework Foundation -framework CoreServices \
  -o "$app/OpenBachelorLauncher"
"${cc[@]}" -fobjc-arc -Wall -Wextra -Werror -I"$DEVKIT_DIR" \
  "$SCRIPT_DIR/Helper/OpenBachelorHelper.m" "$DEVKIT_DIR/libfrida-core.a" \
  -lbsm -ldl -lm -lresolv -framework Foundation -framework CoreGraphics -framework UIKit \
  -o "$app/OpenBachelorHelper"
"${cc[@]}" -fobjc-arc -Wall -Wextra -Werror "$SCRIPT_DIR/Injector/OpenBachelorInjector.m" \
  -framework Foundation -o "$app/OpenBachelorInjector"

chmod 0755 "$app/OpenBachelorLauncher" "$app/OpenBachelorHelper" "$app/OpenBachelorInjector"
# Sign the spawned child executables as standalone Mach-O files. The launcher
# and the completed app resource envelope are signed after all resources land.
codesign --force --sign - --entitlements "$SCRIPT_DIR/Helper/helper.entitlements" \
  --generate-entitlement-der "$app/OpenBachelorHelper"
codesign --force --sign - --entitlements "$SCRIPT_DIR/Injector/tool.entitlements" \
  --generate-entitlement-der "$app/OpenBachelorInjector"
codesign --verify --strict "$app/OpenBachelorHelper"
codesign --verify --strict "$app/OpenBachelorInjector"
ldid -e "$app/OpenBachelorHelper" | plutil -lint - >/dev/null
ldid -e "$app/OpenBachelorInjector" | plutil -lint - >/dev/null

cp "$SCRIPT_DIR/App/Info.plist" "$app/Info.plist"
icon_generator="$BUILD_DIR/IconGenerator"
xcrun --sdk macosx clang -fobjc-arc "$SCRIPT_DIR/App/IconGenerator.m" \
  -framework AppKit -o "$icon_generator"
"$icon_generator" "$app/AppIcon.png"
cp "$BUILD_DIR/direct.js" "$app/direct.js"
cp "$PROFILE" "$app/profile.json"

gadget_package_root="$BUILD_DIR/TrollFools"
gadget_framework="$gadget_package_root/FridaGadget.framework"
gadget_bootstrap="$gadget_framework/FridaGadget"
gadget_payload="$gadget_framework/FridaGadgetCore.dylib"
rm -rf "$gadget_package_root"
mkdir -p "$gadget_framework"
xz -dc "$GADGET_ARCHIVE" > "$gadget_payload"
verify_sha256 "$gadget_payload" "$GADGET_BINARY_SHA256" "decompressed Frida Gadget"
lipo "$gadget_payload" -verify_arch arm64 arm64e
# The arm64 slice runs on both arm64 and arm64e devices. Keep the injected
# framework small and avoid coupling the payload to one arm64e ABI revision.
gadget_arm64="$gadget_framework/FridaGadgetCore.arm64"
lipo "$gadget_payload" -thin arm64 -output "$gadget_arm64"
mv "$gadget_arm64" "$gadget_payload"
gadget_archs=$(lipo "$gadget_payload" -archs)
if [[ "$gadget_archs" != "arm64" ]]; then
  print -u2 "error: expected arm64-only Frida Gadget, got: $gadget_archs"
  exit 1
fi
# Gum's Exceptor has already installed its handlers through the original
# sigaction implementation. Avoid rewriting libc signal/sigaction, which
# suspends every application thread and triggers a process-level SIGILL in the
# target before any direct-agent hooks are loaded. The patcher validates the
# exact Frida 17.9.1 instructions before changing them to NOPs.
node "$SCRIPT_DIR/Gadget/patch-frida-exceptor.mjs" "$gadget_payload"
xcrun install_name_tool -id @rpath/FridaGadget.framework/FridaGadgetCore.dylib "$gadget_payload"
"${cc[@]}" -dynamiclib -Wall -Wextra -Werror \
  -Wl,-install_name,@rpath/FridaGadget.framework/FridaGadget \
  "$SCRIPT_DIR/Gadget/FridaGadgetBootstrap.c" -o "$gadget_bootstrap"
cp "$SCRIPT_DIR/Gadget/FridaGadget.config" "$gadget_framework/FridaGadgetCore.config"
cp "$SCRIPT_DIR/Gadget/Info.plist" "$gadget_framework/"
cp "$SCRIPT_DIR/Gadget/.openbachelor-coretrust-v3" "$gadget_framework/"
cp "$SCRIPT_DIR/Gadget/LICENSE.frida.txt" "$gadget_package_root/"
chmod 0755 "$gadget_bootstrap" "$gadget_payload"
plutil -lint "$gadget_framework/Info.plist" >/dev/null
for binary in "$gadget_bootstrap" "$gadget_payload"; do
  ldid -S "$binary"
  gadget_signature_info=$(ldid -h "$binary" 2>&1)
  gadget_signature_slices=$(print -r -- "$gadget_signature_info" | awk '/^CDHash=/{ count++ } END { print count + 0 }')
  if [[ "$gadget_signature_slices" -ne 1 ]]; then
    print -u2 "error: expected one pseudo-signature for $binary"
    exit 1
  fi
done

injector_resources="$app/InjectorResources"
injector_tools="$app/InjectorTools"
mkdir -p "$injector_resources" "$injector_tools"
cp -R "$gadget_framework" "$injector_resources/"
for file in ct_bypass insert_dylib ldid libcrypto.3.dylib libiosexec.1.dylib; do
  cp "$trollfools_tools/$file" "$injector_tools/$file"
done
cp "$SCRIPT_DIR/Injector/LICENSE.trollfools.txt" "$app/"
cp "$SCRIPT_DIR/Gadget/LICENSE.frida.txt" "$app/"

lower_ios_minos() {
  local binary=$1
  local sdk_version
  local lowered="$binary.lowered"
  sdk_version=$(xcrun vtool -show-build "$binary" | awk '$1 == "sdk" { print $2; exit }')
  if [[ -z "$sdk_version" ]]; then
    print -u2 "error: unable to read iOS SDK version from $binary"
    exit 1
  fi
  xcrun vtool -set-build-version ios 15.0 "$sdk_version" -replace -output "$lowered" "$binary"
  mv "$lowered" "$binary"
}

# The pinned TrollFools binaries only use long-standing libSystem APIs, but a few
# were built with an unnecessarily high deployment load command. Keep the
# launcher's documented iOS 15 floor and re-sign the modified copies below.
lower_ios_minos "$injector_tools/insert_dylib"
lower_ios_minos "$injector_tools/libcrypto.3.dylib"
lower_ios_minos "$injector_tools/libiosexec.1.dylib"
chmod 0755 "$injector_tools/ct_bypass" "$injector_tools/insert_dylib" "$injector_tools/ldid"
for file in ct_bypass insert_dylib ldid; do
  codesign --force --sign - --entitlements "$SCRIPT_DIR/Injector/tool.entitlements" \
    --generate-entitlement-der "$injector_tools/$file"
done
codesign --force --sign - "$injector_tools/libcrypto.3.dylib"
codesign --force --sign - "$injector_tools/libiosexec.1.dylib"
for file in ct_bypass insert_dylib ldid; do
  codesign --verify --strict "$injector_tools/$file"
  ldid -e "$injector_tools/$file" | plutil -lint - >/dev/null
  ldid -h "$injector_tools/$file" >/dev/null 2>&1
done
codesign --verify --strict "$injector_tools/libcrypto.3.dylib"
codesign --verify --strict "$injector_tools/libiosexec.1.dylib"
ldid -h "$injector_tools/libcrypto.3.dylib" >/dev/null 2>&1
ldid -h "$injector_tools/libiosexec.1.dylib" >/dev/null 2>&1
for file in insert_dylib libcrypto.3.dylib libiosexec.1.dylib; do
  tool_minos=$(xcrun vtool -show-build "$injector_tools/$file" | awk '$1 == "minos" { print $2; exit }')
  if [[ "$tool_minos" != "15.0" ]]; then
    print -u2 "error: failed to lower $file deployment target: $tool_minos"
    exit 1
  fi
done

codesign --force --sign - --entitlements "$SCRIPT_DIR/App/launcher.entitlements" \
  --generate-entitlement-der "$app"
codesign --verify --strict "$app"
ldid -e "$app/OpenBachelorLauncher" | plutil -lint - >/dev/null

output="$DIST_DIR/OpenBachelorLauncher.ipa"
tipa_output="$DIST_DIR/OpenBachelorLauncher.tipa"
gadget_output="$DIST_DIR/OpenBachelorGadget-TrollFools.zip"
rm -f "$output"
rm -f "$tipa_output"
rm -f "$gadget_output"
(cd "$BUILD_DIR" && zip -qry "$output" Payload)
cp "$output" "$tipa_output"
(cd "$gadget_package_root" && zip -qry "$gadget_output" FridaGadget.framework LICENSE.frida.txt)
unzip -t "$output" >/dev/null
unzip -t "$tipa_output" >/dev/null
unzip -t "$gadget_output" >/dev/null
output_sha=$(shasum -a 256 "$output" | awk '{print $1}')
gadget_output_sha=$(shasum -a 256 "$gadget_output" | awk '{print $1}')
print "built: $output"
print "sha256: $output_sha"
print "built: $tipa_output"
print "sha256: $output_sha"
print "built: $gadget_output"
print "sha256: $gadget_output_sha"
print "profile: $PROFILE"
print "bundle: $profile_bundle"
if [[ -n "$DEVKIT_SOURCE_DIR" ]]; then
  print "frida-core: $DEVKIT_VERSION (verified extracted files from $DEVKIT_SOURCE_DIR)"
else
  print "frida-core: $DEVKIT_VERSION ($DEVKIT_SHA256)"
fi
