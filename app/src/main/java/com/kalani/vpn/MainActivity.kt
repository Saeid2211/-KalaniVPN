package com.kalani.vpn

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

class MainActivity : ComponentActivity() {
    
    private var isConnected by mutableStateOf(false)

    private val vpnPermissionLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme(colorScheme = darkColorScheme(primary = Color(0xFF1F9167), background = Color(0xFF080C14))) {
                MainScreen()
            }
        }
    }

    @Composable
    fun MainScreen() {
        Scaffold(containerColor = Color(0xFF080C14)) { padding ->
            Column(
                modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Text("KALANI VPN", fontSize = 32.sp, fontWeight = FontWeight.Bold, color = Color.White)
                Spacer(modifier = Modifier.height(50.dp))

                Box(
                    modifier = Modifier.size(150.dp).background(
                        color = if (isConnected) Color(0xFF2DDC87) else Color(0xFF1F9167),
                        shape = CircleShape
                    ),
                    contentAlignment = Alignment.Center
                ) {
                    Button(
                        onClick = { 
                            if (isConnected) {
                                isConnected = false
                                val intent = Intent(this@MainActivity, KalaniVpnService::class.java).setAction("DISCONNECT")
                                startService(intent)
                            } else {
                                val prepare = VpnService.prepare(this@MainActivity)
                                if (prepare != null) vpnPermissionLauncher.launch(prepare) else startVpnService()
                            }
                        },
                        colors = ButtonDefaults.buttonColors(containerColor = Color.Transparent)
                    ) {
                        Text(if (isConnected) "STOP" else "START", fontSize = 22.sp, color = Color.White, fontWeight = FontWeight.Bold)
                    }
                }

                Spacer(modifier = Modifier.height(30.dp))
                Text(if (isConnected) "Connected" else "Disconnected", color = if (isConnected) Color(0xFF2DDC87) else Color(0xFFFF6978), fontSize = 20.sp)
            }
        }
    }

    private fun startVpnService() {
        isConnected = true
        val intent = Intent(this, KalaniVpnService::class.java)
        if (android.os.Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }
}
