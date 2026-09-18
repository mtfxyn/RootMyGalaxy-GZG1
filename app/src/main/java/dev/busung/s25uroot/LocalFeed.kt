package dev.busung.s25uroot

/**
 * Built-in payload feed for one personally-owned SM-F946B.
 *
 * WHY THIS EXISTS
 * ---------------
 * Two independent failures made the remote feed unusable on this device.
 *
 * 1. The feed is fetched over HTTPS from raw.githubusercontent.com on every
 *    launch and every boot. From this device's network that host never
 *    answers (connect timeout, `curl` exit 28) while api.github.com returns
 *    200 in ~1.2s, so resolveTargetFresh() died inside the manifest download
 *    and the boot pipeline aborted with repo_no_profile before the exploit
 *    was ever staged. That failure had nothing to do with payload offsets.
 *
 * 2. The matching predicate cannot tell this device apart from the
 *    f946b-F946BXXS7GZE5 entry it needs to avoid. DeviceSnapshot.kernelVersion
 *    keeps only the LEADING numeric run of the release string, so both
 *    F946BXXS7GZG1 and F946BXXS7GZE5 reduce to "5.15.189" and both report
 *    model SM-F946B. The feed therefore resolves to the GZE5 payload, whose
 *    ashmem_misc.fops offset sits 0x80 lower; running it on this kernel
 *    restores a wild file_operations pointer and panics (observed on device
 *    2026-09-16). Feed ORDER is the only tie-break, so no entry added
 *    upstream could have fixed this without also breaking F946BXXS7GZE5.
 *
 * Shipping the payloads inside the APK removes both: nothing is fetched, and
 * the profile below is the only candidate, so no feed ordering can select a
 * foreign target's binaries.
 *
 * PROVENANCE
 * ----------
 * These are the exact bytes validated on device RFCW71E5P6K (SM-F946B,
 * F946BXXS7GZG1, kernel 5.15.189-android13-8-33404244-abF946BXXS7GZG1) on
 * 2026-09-18. Each hash is the MD5 of the file:
 *
 *   role        asset                              bytes    md5
 *   exploit     cve-2026-43499-app.so             136392   0187e5165b35d1c6275a341d2cbf82fc
 *   rootHelper  cve-2026-43499-root                44520   f171c73ca3f4d88e891834f77fab2298
 *   kernelsu    ksud-f946b-F946BXXS7GZG1-kdp     5465448   a7015ddd8cb0fd64903b61993f8b37fd
 *
 * The exploit and root helper are built from the f946b-F946BXXS7GZG1 profile
 * in Root-My-Galaxy-Payloads (four offsets differ from F946BXXS7GZE5:
 * KMALLOC_CACHES_OFF, ANON_PIPE_BUF_OPS_OFF and ASHMEM_FOPS_OFF each -0x80,
 * SLIDE_NFULNL_LOGGER_NAME_OFF -0x32).
 *
 * The ksud loader is the F946BXXS7GZE5 build, byte-identical to
 * kernelsu/ksud-f946b-F946BXXS7GZE5-kdp upstream. It is intentionally stored
 * under the GZG1 name because the profile it serves is GZG1 — the filename is
 * the loader's identity on device (su_daemon.c resolves any
 * /data/local/tmp/ksud-*-kdp candidate), not a claim about which build
 * produced it. android13-8 is an ABI-frozen KMI and this loader was verified
 * live against the GZG1 kernel: "kernelsu 221184 1 - Live (OE)",
 * version=32601. A dedicated GZG1 .ko build was not required.
 *
 * SIZES ARE LOAD-BEARING
 * ----------------------
 * PayloadRepository verifies every artifact against the size below before it
 * stages anything, and RootOnBootService skips its refresh only when the
 * cached copy matches. Rebuilding any binary means updating both the asset
 * and the size here in lockstep — a mismatch aborts the run rather than
 * staging a half-updated stack, which is the intended behaviour.
 */
object LocalFeed {
    /** URL scheme marking an artifact that ships inside this APK's assets. */
    const val ASSET_SCHEME = "asset:"

    const val PROFILE_ID = "f946b-F946BXXS7GZG1"

    private const val ASSET_DIR = "gzg1"

    private fun asset(name: String) = "$ASSET_SCHEME$ASSET_DIR/$name"

    val TARGETS: List<TargetProfile> = listOf(
        TargetProfile(
            profileId = PROFILE_ID,
            displayName = "SM-F946B | F946BXXS7GZG1 (built-in)",
            models = setOf("SM-F946B"),
            kernelVersions = setOf("5.15.189"),
            exploit = RemoteArtifact(asset("cve-2026-43499-app.so"), 136_392L),
            kernelSu = RemoteArtifact(asset("ksud-$PROFILE_ID-kdp"), 5_465_448L),
            rootHelper = RemoteArtifact(asset("cve-2026-43499-root"), 44_520L),
            // The physical-P0 slide oracle is NOT hardware-exercised on this
            // build: two runs failed at "p0 physical pipe reclaim miss"
            // (hits=0 changed=0 — allocator timing, no panic). The tracefs
            // route (EVENT_ID 108, WORKER_CALLER_OFF 0x0010db44) leaked the
            // slide on the first attempt both times, so it is forced here.
            slideSource = "tracefs",
        ),
    )
}
