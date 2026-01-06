#!/usr/bin/env bash
set -euo pipefail

# Build libsodium static library (libsodium.a) for Android ABIs and place it
# where this project expects it:
#   app/src/main/cpp/libsodium/<abi>/lib/libsodium.a
#   app/src/main/cpp/libsodium/<abi>/include/
#
# Requirements:
# - Android NDK installed (via Android Studio)
# - curl, make, autoconf/automake/libtool (or Xcode CLT + brew equivalents)
#
# Usage:
#   tools/build_libsodium_android.sh
#   ANDROID_API=23 tools/build_libsodium_android.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LIBSODIUM_VERSION="${LIBSODIUM_VERSION:-1.0.19}"
ANDROID_API="${ANDROID_API:-21}"

LIBSODIUM_DST_ROOT="$ROOT_DIR/app/src/main/cpp/libsodium"
WORK_DIR="$ROOT_DIR/.libsodium_build"

mkdir -p "$WORK_DIR"

resolve_ndk() {
  if [[ -n "${ANDROID_NDK_HOME:-}" && -d "${ANDROID_NDK_HOME}" ]]; then
    echo "$ANDROID_NDK_HOME"
    return 0
  fi

  if [[ -f "$ROOT_DIR/local.properties" ]]; then
    local ndk_dir
    ndk_dir="$(grep -E '^ndk\.dir=' "$ROOT_DIR/local.properties" | head -n 1 | cut -d= -f2- || true)"
    if [[ -n "$ndk_dir" && -d "$ndk_dir" ]]; then
      echo "$ndk_dir"
      return 0
    fi
  fi

  local sdk_root="$HOME/Library/Android/sdk"
  if [[ -d "$sdk_root/ndk" ]]; then
    local latest
    latest="$(ls -1 "$sdk_root/ndk" 2>/dev/null | sort -V | tail -n 1 || true)"
    if [[ -n "$latest" && -d "$sdk_root/ndk/$latest" ]]; then
      echo "$sdk_root/ndk/$latest"
      return 0
    fi
  fi

  echo "ERROR: Android NDK not found. Set ANDROID_NDK_HOME or add ndk.dir to local.properties." >&2
  exit 1
}

resolve_toolchain() {
  local ndk="$1"
  local tc
  for tc in "darwin-arm64" "darwin-x86_64"; do
    if [[ -d "$ndk/toolchains/llvm/prebuilt/$tc" ]]; then
      echo "$ndk/toolchains/llvm/prebuilt/$tc"
      return 0
    fi
  done
  echo "ERROR: NDK LLVM toolchain not found under $ndk/toolchains/llvm/prebuilt" >&2
  exit 1
}

fetch_libsodium() {
  local dest="$1"
  if [[ -d "$dest" ]]; then
    return 0
  fi

  local tarball="$WORK_DIR/libsodium-$LIBSODIUM_VERSION.tar.gz"
  local url="https://download.libsodium.org/libsodium/releases/libsodium-$LIBSODIUM_VERSION.tar.gz"

  echo "Downloading libsodium $LIBSODIUM_VERSION..."
  curl -L --retry 3 --fail -o "$tarball" "$url"

  echo "Extracting..."
  tar -xzf "$tarball" -C "$WORK_DIR"

  if [[ ! -d "$WORK_DIR/libsodium-$LIBSODIUM_VERSION" ]]; then
    echo "ERROR: extracted folder not found: $WORK_DIR/libsodium-$LIBSODIUM_VERSION" >&2
    exit 1
  fi

  mv "$WORK_DIR/libsodium-$LIBSODIUM_VERSION" "$dest"
}

build_one() {
  local abi="$1"
  local host="$2"
  local triple_prefix="$3"

  local ndk="$4"
  local toolchain="$5"

  local src="$WORK_DIR/src"
  local build="$WORK_DIR/build-$abi"
  local prefix="$WORK_DIR/prefix-$abi"

  rm -rf "$build" "$prefix"
  mkdir -p "$build" "$prefix"

  # Fresh copy per-ABI to avoid cross-contamination between configure runs.
  rm -rf "$src"
  cp -R "$WORK_DIR/libsodium" "$src"

  pushd "$src" >/dev/null

  export CC="$toolchain/bin/${triple_prefix}${ANDROID_API}-clang"
  export CXX="$toolchain/bin/${triple_prefix}${ANDROID_API}-clang++"
  export AR="$toolchain/bin/llvm-ar"
  export RANLIB="$toolchain/bin/llvm-ranlib"
  export STRIP="$toolchain/bin/llvm-strip"

  echo "Building libsodium for $abi (host=$host, api=$ANDROID_API)"

  # Some environments require this to generate configure scripts.
  if [[ -x ./autogen.sh ]]; then
    ./autogen.sh >/dev/null
  fi

  ./configure \
    --host="$host" \
    --prefix="$prefix" \
    --disable-shared \
    --enable-static \
    --with-pic \
    >/dev/null

  make -j"$(sysctl -n hw.ncpu)" >/dev/null
  make install >/dev/null

  popd >/dev/null

  local dst_lib="$LIBSODIUM_DST_ROOT/$abi/lib"
  local dst_inc="$LIBSODIUM_DST_ROOT/$abi/include"

  mkdir -p "$dst_lib" "$dst_inc"

  cp -f "$prefix/lib/libsodium.a" "$dst_lib/libsodium.a"
  rsync -a --delete "$prefix/include/" "$dst_inc/"

  echo "✓ Installed $dst_lib/libsodium.a"
}

main() {
  local ndk
  ndk="$(resolve_ndk)"
  local toolchain
  toolchain="$(resolve_toolchain "$ndk")"

  mkdir -p "$WORK_DIR"
  fetch_libsodium "$WORK_DIR/libsodium"

  build_one "arm64-v8a" "aarch64-linux-android" "aarch64-linux-android" "$ndk" "$toolchain"
  build_one "armeabi-v7a" "armv7a-linux-androideabi" "armv7a-linux-androideabi" "$ndk" "$toolchain"
  build_one "x86" "i686-linux-android" "i686-linux-android" "$ndk" "$toolchain"
  build_one "x86_64" "x86_64-linux-android" "x86_64-linux-android" "$ndk" "$toolchain"

  echo ""
  echo "Done. You can now rebuild the Android project." 
}

main "$@"
