package dev.dioxus.main

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import androidx.annotation.Keep
import io.github.sshvpn.BuildConfig

// need to re-export buildconfig down from the parent
typealias BuildConfig = BuildConfig

class MainActivity : WryActivity() {
    // @Keep: only called from Rust over JNI, so R8 would otherwise strip them in release builds.

    /** Called from Rust (android_vpn.rs). Asks for VPN consent first if needed. */
    @Keep
    fun startVpn() = runOnUiThread {
        val consent = VpnService.prepare(this)
        if (consent == null) {
            startTunService(SshVpnService.ACTION_START)
        } else {
            @Suppress("DEPRECATION")
            startActivityForResult(consent, VPN_REQUEST)
        }
    }

    /** Called from Rust (android_vpn.rs). */
    @Keep
    fun stopVpn() = runOnUiThread { startTunService(SshVpnService.ACTION_STOP) }

    private fun startTunService(action: String) {
        startService(Intent(this, SshVpnService::class.java).setAction(action))
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != VPN_REQUEST) return
        if (resultCode == Activity.RESULT_OK) {
            startTunService(SshVpnService.ACTION_START)
        } else {
            VpnBridge.onTunFailed("VPN permission was denied")
        }
    }

    companion object {
        const val VPN_REQUEST = 0x5356
    }
}

/** Routes all traffic of every other app into a TUN interface whose fd is handed to Rust. */
class SshVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // Rust closes the TUN fd itself; that is what actually removes the VPN.
            stopSelf()
        } else {
            establish()
        }
        return START_NOT_STICKY
    }

    private fun establish() {
        try {
            val tun = Builder()
                .setSession("SSH VPN")
                .setMtu(1500)
                .addAddress("10.233.0.2", 32)
                .addRoute("0.0.0.0", 0)
                .addAddress("fd00:233::2", 128)
                .addRoute("::", 0)
                .addDnsServer("10.233.0.1")
                // Our own SSH connection must not go into the tunnel it carries.
                .addDisallowedApplication(packageName)
                .establish() ?: throw IllegalStateException("VPN permission is not granted")
            VpnBridge.onTunReady(tun.detachFd())
        } catch (e: Exception) {
            VpnBridge.onTunFailed("Could not start VPN: ${e.message}")
            stopSelf()
        }
    }

    override fun onRevoke() {
        VpnBridge.onRevoked()
        stopSelf()
    }

    companion object {
        const val ACTION_START = "io.github.sshvpn.START"
        const val ACTION_STOP = "io.github.sshvpn.STOP"
    }
}

/** Native callbacks implemented in src/android_vpn.rs. */
object VpnBridge {
    init {
        System.loadLibrary("main")
    }

    @JvmStatic external fun onTunReady(fd: Int)
    @JvmStatic external fun onTunFailed(reason: String)
    @JvmStatic external fun onRevoked()
}
