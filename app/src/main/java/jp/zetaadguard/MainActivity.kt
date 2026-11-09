package jp.zetaadguard

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast

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
            text = "ZetaAdGuard\n\n準備できました。\n「フィルタを開始」を押してください。"
        }
        val start = Button(this).apply {
            text = "フィルタを開始"
            setOnClickListener {
                status.text = "VPNの許可状態を確認しています…"
                try {
                    val prepareIntent = VpnService.prepare(this@MainActivity)
                    if (prepareIntent != null) {
                        status.text = "AndroidのVPN許可画面を開きます。"
                        startActivityForResult(prepareIntent, REQUEST_VPN)
                    } else {
                        startFilter()
                    }
                } catch (e: Exception) {
                    showError("VPN許可の確認に失敗しました", e)
                }
            }
        }
        val stop = Button(this).apply {
            text = "停止"
            setOnClickListener {
                try {
                    stopService(Intent(this@MainActivity, DnsVpnService::class.java))
                    status.text = "停止命令を送りました。"
                    Toast.makeText(this@MainActivity, "停止しました", Toast.LENGTH_SHORT).show()
                } catch (e: Exception) {
                    showError("停止に失敗しました", e)
                }
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
        if (requestCode == REQUEST_VPN) {
            if (resultCode == RESULT_OK) {
                startFilter()
            } else {
                status.text = "VPN接続が許可されませんでした。設定からZetaAdGuardのVPNを許可してください。"
            }
        }
    }

    private fun startFilter() {
        try {
            val intent = Intent(this, DnsVpnService::class.java)
            startForegroundService(intent)
            status.text = "起動命令を送信しました。\n通知欄に「ZetaAdGuard」が表示されるか確認してください。"
            Toast.makeText(this, "フィルタの起動命令を送りました", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            showError("フィルタを起動できませんでした", e)
        }
    }

    private fun showError(prefix: String, error: Exception) {
        val detail = error.javaClass.simpleName + ": " + (error.message ?: "詳細なし")
        status.text = "$prefix\n$detail"
        Toast.makeText(this, "$prefix: $detail", Toast.LENGTH_LONG).show()
    }

    companion object { private const val REQUEST_VPN = 1001 }
}
