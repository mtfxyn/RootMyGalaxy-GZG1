# GZG1 single-device build

A private build of Root-My-Galaxy for **one** device:

| | |
|---|---|
| Device | Samsung Galaxy Z Fold5, `SM-F946B` |
| Build | `F946BXXS7GZG1` (`BP4A.251205.006.F946BXXS7GZG1`) |
| Kernel | `5.15.189-android13-8-33404244-abF946BXXS7GZG1` |
| Serial | `RFCW71E5P6K` |

It exists because the upstream app cannot work on this device as shipped. Two
independent blockers, both fixed by this build:

**1. The feed host is unreachable.** The app fetches
`raw.githubusercontent.com/HyperRamzey/Root-My-Galaxy-Payloads/main/support/targets-v3.json`
on every launch and every boot. From this device's network that host never
answers (`curl` exit 28, connect timeout) while `api.github.com` returns 200 in
~1.2s and `github.com` also times out. `resolveTargetFresh()` therefore died
inside the manifest download and the boot pipeline aborted with
`repo_no_profile` before the exploit was ever staged. No feed entry could have
fixed this.

**2. The matching predicate cannot tell this device apart from the wrong one.**
`DeviceSnapshot.kernelVersion` keeps only the leading numeric run of the
release string, so both `...GZG1` and `...GZE5` collapse to `"5.15.189"`, and
both report `SM-F946B`. A feed lookup resolves to the `f946b-F946BXXS7GZE5`
entry, and feed order is the only tie-break. That payload's
`ASHMEM_FOPS_OFF` is `0x80` lower than this kernel's, so the cfi stage
restores a wild `ashmem_misc.fops` pointer and the kernel panics at the next
ashmem use — which is exactly what happened on 2026-09-16.

## What this build changes

| File | Change |
|---|---|
| `app/src/main/java/.../LocalFeed.kt` | **New.** The built-in profile, with the provenance record for every bundled binary. |
| `app/src/main/java/.../PayloadRepository.kt` | `loadTargets()` returns `LocalFeed.TARGETS`; artifacts are copied out of the APK's assets instead of fetched. The commit/manifest fetch, redirect-hardened HTTP client and the dead feed-retry ladder are gone. |
| `app/src/main/assets/gzg1/` | **New.** The three payloads. |
| `app/src/main/jniLibs/arm64-v8a/` | `libcve43499app.so` and `libcve43499root.so` replaced with the GZG1 builds; added `libcve43499app-f946b-F946BXXS7GZG1.so` for the per-profile lookup in `ExploitStaging`. |
| `app/build.gradle.kts` | `versionCode 37`, `versionName 0.2.30-gzg1`. Same committed release keystore, so the signature is unchanged and `adb install -r` replaces the upstream build. |
| `.github/workflows/ci.yml` | Added a step that pins the md5 of every bundled binary before the build. |

## Bundled payloads

All three were validated on `RFCW71E5P6K` on 2026-09-18 and are pinned by md5
in `ci.yml`.

| Role | Asset | Bytes | MD5 |
|---|---|---|---|
| exploit | `cve-2026-43499-app.so` | 136392 | `0187e5165b35d1c6275a341d2cbf82fc` |
| rootHelper | `cve-2026-43499-root` | 44520 | `f171c73ca3f4d88e891834f77fab2298` |
| kernelsu | `ksud-f946b-F946BXXS7GZG1-kdp` | 5465448 | `a7015ddd8cb0fd64903b61993f8b37fd` |

The exploit and helper are built from the `f946b-F946BXXS7GZG1` profile in
`Root-My-Galaxy-Payloads`. Four offsets differ from the F946BXXS7GZE5 profile:
`KMALLOC_CACHES_OFF`, `ANON_PIPE_BUF_OPS_OFF` and `ASHMEM_FOPS_OFF` are each
`-0x80`, and `SLIDE_NFULNL_LOGGER_NAME_OFF` is `-0x32`.

The ksud loader is the **F946BXXS7GZE5** build, byte-identical to
`kernelsu/ksud-f946b-F946BXXS7GZE5-kdp` upstream. It is stored under the GZG1
name because the *profile* it serves is GZG1 — the name is the loader's
identity on device (`su_daemon.c` resolves any `/data/local/tmp/ksud-*-kdp`
candidate), not a claim about which build produced it. `android13-8` is an
ABI-frozen KMI and this loader was verified live against the GZG1 kernel:
`kernelsu 221184 1 - Live (OE)`, `version=32601`. No dedicated GZG1 `.ko`
build was needed.

**Sizes are load-bearing.** `PayloadRepository` verifies every artifact
against the size in `LocalFeed` before staging, and `RootOnBootService` skips
its refresh only when the cached copy matches. Rebuilding a binary means
updating the asset, the size in `LocalFeed.kt`, and the md5 in `ci.yml`
together.

## What was verified on device

| Item | Result |
|---|---|
| tracefs slide leak (`EVENT_ID 108`, `WORKER_CALLER_OFF 0x0010db44`) | leak succeeded first attempt, both runs |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` (`-0x32`) | live-verified |
| `ASHMEM_FOPS_OFF` (`-0x80`) | passed `pipe physrw` (the upstream GZE5 build panicked here) |
| `ANON_PIPE_BUF_OPS_OFF` (`-0x80`) | passed |
| `KMALLOC_CACHES_OFF` (`-0x80`) | passed |
| full exploit | `uid=2000->0`, first attempt, no panic, no reboot |
| KernelSU late-load | `kernelsu 221184 1 - Live (OE)` |
| complete root | `su -c id` → `uid=0(root) context=u:r:ksu:s0`; manager v3.3.0 crowned; `/data/adb/ksu/bin/{busybox,resetprop,bootctl}` present |

**Not verified:** the physical-P0 slide oracle. Two runs failed at
`p0 physical pipe reclaim miss` (`hits=0 changed=0` — allocator timing, no
panic) and both successful runs took the tracefs route, so
`SLIDE_SOURCE=tracefs` is forced in `LocalFeed`. `p0_fingerprint.h` for this
build is static-verification only.

## Building

Push to a GitHub repo you own (a **new** repo, not a fork — Actions needs no
extra enablement that way) and CI builds it. `.github/workflows/ci.yml` runs
on every push and on manual dispatch, and uploads both APKs as the `apks`
artifact. The runner has JDK 21 and the Android SDK, so no local toolchain is
needed.

## Installing

```bash
adb install -r -g app-release.apk     # -g grants WRITE_SECURE_SETTINGS
```

`-g` is required: the auto-root flow enables wireless debugging itself. Then
run the in-app install once so the app's ADB key is registered with adbd;
after that the boot service can reconnect on its own.

## Limits worth knowing

- **Root is volatile.** It lasts until the next reboot. Persistence depends on
  the `BOOT_COMPLETED` ladder in `RootOnBootService` working, which in turn
  needs the one-time setup above.
- **Never remove the `RMG_SELF_UPDATE=0`** from the exploit command in
  `RootOnBootService`. Without it the helper's own self-update would try to
  fetch the upstream feed and overwrite the bundled payload with the GZE5 one.
- **The app's own updater and the KernelSU manager downloader will fail** —
  they reach `github.com`, which is unreachable from this network. Both are
  best-effort and degrade to a log line.
- **Upstream will keep drifting.** This build pins three binaries and the
  offsets they were compiled with; the `F946BXXS7GZG1` profile in
  `Root-My-Galaxy-Payloads` is the source of truth for those offsets.
