package com.kalani.vpn

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import libXray.DialerController
import libXray.LibXray
import org.json.JSONObject
import java.io.File
import java.util.concurrent.Executors

class KalaniVpnService : VpnService() {
    private var vpnFd: ParcelFileDescriptor? = null
    private val worker = Executors.newSingleThreadExecutor()

    private val dialer = object : DialerController {
        override fun protectFd(fd: Long): Boolean = try { protect(fd.toInt()) } catch (_: Throwable) { false }
    }

    override fun onCreate() {
        super.onCreate()
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel("vpn", "VPN Service", NotificationManager.IMPORTANCE_LOW)
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "DISCONNECT") {
            stopVpn()
            stopSelf()
            return START_NOT_STICKY
        }
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        worker.execute {
            try {
                val fd = Builder()
                    .setSession("Kalani VPN")
                    .addAddress("10.10.0.2", 32)
                    .addRoute("0.0.0.0", 0)
                    .addDnsServer("1.1.1.1")
                    .allowFamily(android.system.OsConstants.AF_INET)
                    .establish() ?: return@execute

                vpnFd = fd
                LibXray.registerDialerController(dialer)

                val file = File(filesDir, "kalani_xray.json")
                if (!file.exists()) return@execute
                
                val config = JSONObject(file.readText())
                val env = config.optJSONObject("env") ?: JSONObject().also { config.put("env", it) }
                env.put("xray.tun.fd", fd.fd.toString())

                val request = JSONObject().put("apiVersion", 3).put("method", "runXray").put("payload", JSONObject().put("xrayJson", config.toString()))
                LibXray.invoke(request.toString())
                
            } catch (t: Throwable) { t.printStackTrace() }
        }
    }

    private fun stopVpn() {
        try { LibXray.invoke(JSONObject().put("apiVersion", 3).put("method", "stopXray").toString()) } catch (_: Throwable) {}
        try { vpnFd?.close() } catch (_: Throwable) {}
        vpnFd = null
    }

    override fun onDestroy() {
        stopVpn()
        worker.shutdownNow()
        super.onDestroy()
    }
}
