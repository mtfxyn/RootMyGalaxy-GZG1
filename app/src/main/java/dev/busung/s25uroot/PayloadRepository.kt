package dev.busung.s25uroot

import android.content.Context
import android.system.Os
import java.io.File
import java.io.FileOutputStream

data class VerifiedPayloads(
    val profile: TargetProfile,
    val exploit: File,
    val kernelSu: File,
    val rootHelper: File? = null,
)

class PayloadRepository(private val context: Context) {
    /**
     * Resolve the built-in profile against [snapshot].
     *
     * Nothing here touches the network, so no failure is transient and no
     * retry helps: an unmatched device aborts at once with repo_no_profile
     * instead of being handed a payload built for different offsets.
     * [attempts] and [onRetry] survive only so existing callers — and their
     * "attempt N failed" diagnostics — keep compiling.
     */
    fun resolveTargetFresh(
        snapshot: DeviceSnapshot,
        attempts: Int = FEED_FETCH_ATTEMPTS,
        onRetry: (attempt: Int, error: Throwable) -> Unit = { _, _ -> },
    ): TargetProfile {
        require(attempts > 0)
        return loadTargets().firstOrNull { it.matches(snapshot) }
            ?: error(context.getString(R.string.repo_no_profile))
    }

    /**
     * The built-in feed — see [LocalFeed] for why the remote one was removed
     * rather than re-pointed at a mirror. This build never resolves a target
     * over the network.
     */
    fun loadTargets(): List<TargetProfile> = LocalFeed.TARGETS

    fun resolveTarget(snapshot: DeviceSnapshot): TargetProfile = resolveTargetFresh(snapshot)

    /**
     * Last successfully downloaded manifest, for diagnostics only. Never
     * gates staging sizes: a stale cached manifest once validated a stale
     * ksud while the exploit binaries looked fresh, crashing the rebased
     * KernelSU stack (SIGILL + driver/manager mismatch) on device.
     */
    fun lastCachedTargets(): List<TargetProfile>? = runCatching {
        val file = File(context.filesDir, MANIFEST_CACHE)
        if (!file.exists()) return null
        SupportManifest.parse(file.readBytes()).targets
    }.getOrNull()

    fun resolveTarget(profileId: String): TargetProfile = loadTargets()
        .firstOrNull { it.profileId == profileId }
        ?: error(context.getString(R.string.repo_profile_missing, profileId))

    fun download(profile: TargetProfile, onProgress: (String) -> Unit): VerifiedPayloads {
        val directory = File(context.filesDir, "payloads/${profile.profileId}").apply { mkdirs() }
        val exploit = downloadArtifact(
            profile.exploit,
            File(directory, "cve-2026-43499-app.so"),
            context.getString(R.string.artifact_exploit),
            onProgress,
        )
        val kernelSu = downloadArtifact(
            profile.kernelSu,
            File(directory, remoteFileName(profile.kernelSu.url)),
            context.getString(R.string.artifact_kernelsu),
            onProgress,
        )
        Os.chmod(exploit.absolutePath, 0b100100100)
        Os.chmod(kernelSu.absolutePath, 0b100100100)
        val rootHelper = profile.rootHelper?.let { helper ->
            val file = downloadArtifact(
                helper,
                File(directory, "cve-2026-43499-root"),
                context.getString(R.string.artifact_exploit),
                onProgress,
            )
            Os.chmod(file.absolutePath, 0b100100100)
            file
        }
        return VerifiedPayloads(profile, exploit, kernelSu, rootHelper)
    }

    private fun downloadArtifact(
        artifact: RemoteArtifact,
        destination: File,
        label: String,
        onProgress: (String) -> Unit,
    ): File {
        onProgress(context.getString(R.string.repo_downloading, label))
        val temporary = File(destination.parentFile, "${destination.name}.part")
        val total = extractAsset(artifact, temporary, label)
        require(total == artifact.size) { context.getString(R.string.repo_incomplete, label) }
        if (destination.exists()) destination.delete()
        require(temporary.renameTo(destination)) {
            context.getString(R.string.repo_finalize_failed, label)
        }
        onProgress(context.getString(R.string.repo_verified, label))
        return destination
    }

    /**
     * Copy a payload that ships inside the APK. Same size discipline as the
     * network path it replaces: the asset must be exactly
     * [RemoteArtifact.size] bytes, so an asset that drifts from the profile
     * aborts the run instead of staging a half-updated stack.
     */
    private fun extractAsset(
        artifact: RemoteArtifact,
        temporary: File,
        label: String,
    ): Long {
        require(artifact.url.startsWith(LocalFeed.ASSET_SCHEME)) {
            context.getString(R.string.repo_url_invalid)
        }
        val path = artifact.url.removePrefix(LocalFeed.ASSET_SCHEME)
        return context.assets.open(path).use { input ->
            FileOutputStream(temporary).use { output ->
                val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
                var total = 0L
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    require(total <= artifact.size) {
                        context.getString(R.string.repo_size_exceeded, label)
                    }
                    output.write(buffer, 0, count)
                }
                output.fd.sync()
                total
            }
        }
    }

    private fun remoteFileName(url: String) = url.substringAfterLast('/')

    companion object {
        /** Diagnostics cache written by older feed-based builds. */
        private const val MANIFEST_CACHE = "payloads/targets-cache.json"
        /** Only the default for [resolveTargetFresh]'s signature; see there. */
        private const val FEED_FETCH_ATTEMPTS = 3
    }
}
