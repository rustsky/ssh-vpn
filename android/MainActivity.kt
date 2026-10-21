package dev.dioxus.main

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.util.Log
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

/**
 * Routes all traffic of every other app into a TUN interface whose fd is handed to Rust.
 *
 * Runs as a foreground service while the VPN is up: otherwise, once the screen is locked,
 * Doze and battery saver cut this app's network, and with it the SSH connection the VPN
 * runs over.
 */
class SshVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            // Rust closes the TUN fd itself; that is what actually removes the VPN.
            stopForeground(STOP_FOREGROUND_REMOVE)
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
            goForeground()
            VpnBridge.onTunReady(tun.detachFd())
        } catch (e: Exception) {
            VpnBridge.onTunFailed("Could not start VPN: ${e.message}")
            stopSelf()
        }
    }

    private fun goForeground() {
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL, "VPN status", NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE,
        )
        @Suppress("DEPRECATION")
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        val notification = builder
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("SSH VPN is on")
            .setContentText("All apps go through your SSH server")
            .setContentIntent(open)
            .setOngoing(true)
            .build()
        try {
            if (Build.VERSION.SDK_INT >= 34) {
                // The type for VPN apps; allowed once the user has accepted the VPN.
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (e: Exception) {
            // The VPN still works, it just may drop while the phone sleeps.
            Log.w("ssh-vpn", "could not run as a foreground service", e)
        }
    }

    override fun onRevoke() {
        VpnBridge.onRevoked()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    companion object {
        const val ACTION_START = "io.github.sshvpn.START"
        const val ACTION_STOP = "io.github.sshvpn.STOP"
        private const val CHANNEL = "vpn"
        private const val NOTIFICATION_ID = 1
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
