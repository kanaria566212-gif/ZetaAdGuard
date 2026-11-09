package jp.zetaadguard

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

class DnsVpnService : VpnService() {
    private var tun: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, notification())
        if (running.compareAndSet(false, true)) {
            tun = Builder()
                .setSession("ZetaAdGuard DNS")
                .setMtu(1500)
                .addAddress("10.0.0.2", 32)
                .addDnsServer("10.0.0.1")
                .addRoute("10.0.0.1", 32)
                .establish()
            if (tun == null) {
                running.set(false)
                stopSelf()
                return START_NOT_STICKY
            }
            worker = Thread { processPackets() }.also { it.start() }
        }
        return START_STICKY
    }

    private fun processPackets() {
        val fd = tun?.fileDescriptor ?: return
        val input = FileInputStream(fd)
        val output = FileOutputStream(fd)
        val buffer = ByteArray(32767)
        while (running.get()) {
            try {
                val length = input.read(buffer)
                if (length <= 28) continue
                val packet = buffer.copyOf(length)
                val ihl = (packet[0].toInt() and 0x0f) * 4
                if ((packet[0].toInt() ushr 4) != 4 || ihl < 20 ||
                    (packet[9].toInt() and 0xff) != 17 || length < ihl + 8) continue
                val dst = packet.copyOfRange(16, 20).joinToString(".") { (it.toInt() and 0xff).toString() }
                if (dst != "10.0.0.1") continue
                val udp = ihl
                val srcPort = u16(packet, udp)
                val dstPort = u16(packet, udp + 2)
                if (dstPort != 53) continue
                val dnsStart = udp + 8
                val dnsLength = length - dnsStart
                if (dnsLength < 12) continue
                val blocked = readDomain(packet, dnsStart, dnsLength)?.let { name ->
                    BLOCKED_DOMAINS.any { name == it || name.endsWith(".$it") }
                } ?: false
                val dnsReply = if (blocked) nxdomain(packet.copyOfRange(dnsStart, length)) else forwardDns(packet.copyOfRange(dnsStart, length))
                if (dnsReply != null) {
                    val reply = buildUdpReply(packet, ihl, srcPort, 53, dnsReply)
                    output.write(reply)
                }
            } catch (_: Exception) {
                if (!running.get()) break
            }
        }
    }

    private fun forwardDns(query: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 4000
                val address = InetAddress.getByName("1.1.1.1")
                socket.send(DatagramPacket(query, query.size, address, 53))
                val data = ByteArray(4096)
                val response = DatagramPacket(data, data.size)
                socket.receive(response)
                data.copyOf(response.length)
            }
        } catch (_: Exception) { null }
    }

    private fun readDomain(packet: ByteArray, offset: Int, length: Int): String? {
        if (length < 17) return null
        var p = offset + 12
        val end = offset + length
        val labels = mutableListOf<String>()
        while (p < end) {
            val size = packet[p++].toInt() and 0xff
            if (size == 0) return labels.joinToString(".").lowercase()
            if (size > 63 || p + size > end) return null
            labels += String(packet, p, size, Charsets.US_ASCII)
            p += size
        }
        return null
    }

    private fun nxdomain(query: ByteArray): ByteArray {
        val qd = query.copyOf()
        if (qd.size >= 12) {
            qd[2] = 0x81.toByte()
            qd[3] = 0x83.toByte()
            for (i in 6..11) qd[i] = 0
        }
        return qd
    }

    private fun buildUdpReply(original: ByteArray, ihl: Int, originalSrcPort: Int, originalDstPort: Int, dns: ByteArray): ByteArray {
        val udpLength = 8 + dns.size
        val total = ihl + udpLength
        val out = ByteArray(total)
        original.copyInto(out, 0, 0, ihl)
        original.copyInto(out, 12, 16, 20)
        original.copyInto(out, 16, 12, 16)
        out[2] = (total shr 8).toByte()
        out[3] = total.toByte()
        out[8] = 64
        out[10] = 0; out[11] = 0
        val checksum = ipChecksum(out, ihl)
        out[10] = (checksum shr 8).toByte()
        out[11] = checksum.toByte()
        put16(out, ihl, originalDstPort)
        put16(out, ihl + 2, originalSrcPort)
        put16(out, ihl + 4, udpLength)
        out[ihl + 6] = 0; out[ihl + 7] = 0
        dns.copyInto(out, ihl + 8)
        return out
    }

    private fun ipChecksum(data: ByteArray, headerLength: Int): Int {
        var sum = 0
        var i = 0
        while (i < headerLength) {
            sum += ((data[i].toInt() and 0xff) shl 8) + (data[i + 1].toInt() and 0xff)
            i += 2
        }
        while (sum ushr 16 != 0) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.inv() and 0xffff
    }

    private fun u16(b: ByteArray, p: Int) = ((b[p].toInt() and 0xff) shl 8) or (b[p + 1].toInt() and 0xff)
    private fun put16(b: ByteArray, p: Int, v: Int) { b[p] = (v shr 8).toByte(); b[p + 1] = v.toByte() }

    override fun onDestroy() {
        running.set(false)
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        worker?.interrupt()
        worker = null
        stopForeground(STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= 26) {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(NotificationChannel(CHANNEL_ID, "DNS filter", NotificationManager.IMPORTANCE_LOW))
        }
    }

    private fun notification(): Notification {
        return if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, CHANNEL_ID).setContentTitle("ZetaAdGuard").setContentText("DNSフィルタが動作中").setSmallIcon(android.R.drawable.ic_secure).build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this).setContentTitle("ZetaAdGuard").setContentText("DNSフィルタが動作中").setSmallIcon(android.R.drawable.ic_secure).build()
        }
    }

    companion object {
        private const val CHANNEL_ID = "zeta_adguard_dns"
        private const val NOTIFICATION_ID = 7
        private val BLOCKED_DOMAINS = setOf(
            "doubleclick.net", "googlesyndication.com", "googleadservices.com",
            "adservice.google.com", "pagead2.googlesyndication.com"
        )
    }
}
