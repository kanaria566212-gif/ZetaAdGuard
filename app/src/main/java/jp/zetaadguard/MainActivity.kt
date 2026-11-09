package jp.zetaadguard

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val layout = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 48, 36, 36)
        }
        status = TextView(this).apply {
            textSize = 17f
            text = "ZetaAdGuard\n\nDNSフィルタは停止中です。"
        }
        val start = Button(this).apply {
            text = "フィルタを開始"
            setOnClickListener {
                val prepare = VpnService.prepare(this@MainActivity)
                if (prepare != null) startActivityForResult(prepare, REQUEST_VPN)
                else startFilter()
            }
        }
        val stop = Button(this).apply {
            text = "停止"
            setOnClickListener {
                stopService(Intent(this@MainActivity, DnsVpnService::class.java))
                status.text = "フィルタを停止しました。"
            }
        }
        layout.addView(status)
        layout.addView(start)
        layout.addView(stop)
        setContentView(layout)
    }

    @Deprecated("Deprecated by Android, retained for broad device compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQUEST_VPN && resultCode == RESULT_OK) startFilter()
    }

    private fun startFilter() {
        val intent = Intent(this, DnsVpnService::class.java)
        startForegroundService(intent)
        status.text = "DNSフィルタを起動しました。\n初回はVPN接続を許可してください。"
    }

    companion object { private const val REQUEST_VPN = 1001 }
}
