package org.suite.firewallprobe

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/** Signed, separate-UID test fixture restricted to the emulator's controlled host. */
class ProbeReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        Thread {
            try {
                val host = intent.getStringExtra("host") ?: "10.0.2.2"
                require(host in setOf("10.0.2.2", "fec0::2")) { "Only controlled emulator endpoint permitted" }
                val port = intent.getIntExtra("port", 18080)
                require(port in setOf(18080, 18081, 1053, 1853, 18443))
                val kind = intent.getStringExtra("kind") ?: "tcp"
                val nonce = intent.getStringExtra("nonce") ?: "probe"
                require(nonce.matches(Regex("[a-z0-9-]{1,64}")))
                val message = nonce.toByteArray(Charsets.US_ASCII)
                when (kind) {
                    "udp", "dns" -> DatagramSocket().use { socket ->
                        socket.soTimeout = 1500
                        val payload = if (kind == "dns") dnsQuery(nonce) else message
                        socket.send(DatagramPacket(payload, payload.size, InetAddress.getByName(host), port))
                        val reply = DatagramPacket(ByteArray(1024), 1024)
                        socket.receive(reply)
                        check(reply.address == InetAddress.getByName(host) && reply.port == port)
                        if (kind == "dns") checkDns(reply.data.copyOf(reply.length))
                        else check(reply.length == payload.size && reply.data.take(payload.size) == payload.toList())
                    }
                    "tcp", "dns-tcp", "dot", "doh" -> {
                        val socket = if (kind == "tcp" || kind == "dns-tcp") Socket() else {
                            val certificate = context.assets.open("endpoint.crt").use {
                                CertificateFactory.getInstance("X.509").generateCertificate(it)
                            }
                            val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply { load(null); setCertificateEntry("test-endpoint", certificate) }
                            val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(store) }
                            SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }.socketFactory.createSocket()
                        }
                        socket.use {
                            it.soTimeout = 1500
                            it.connect(InetSocketAddress(host, port), 1500)
                            if (it is SSLSocket) {
                                it.sslParameters = it.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                                it.startHandshake()
                            }
                            val payload = when (kind) {
                                "dot", "dns-tcp" -> dnsQuery(nonce).let { query -> byteArrayOf((query.size ushr 8).toByte(), query.size.toByte()) + query }
                                "doh" -> dnsQuery(nonce).let { query ->
                                    "POST /dns-query HTTP/1.1\r\nHost: ${if (host.contains(':')) "[$host]" else host}\r\nContent-Type: application/dns-message\r\nContent-Length: ${query.size}\r\n\r\n".toByteArray(Charsets.US_ASCII) + query
                                }
                                else -> message
                            }
                            it.getOutputStream().write(payload)
                            val input = it.getInputStream().buffered()
                            when (kind) {
                                "dot", "dns-tcp" -> {
                                    val size = (input.read() shl 8) or input.read()
                                    check(size in 12..1024)
                                    checkDns(ByteArray(size).also { response -> java.io.DataInputStream(input).readFully(response) })
                                }
                                "doh" -> {
                                    val header = StringBuilder()
                                    while (!header.endsWith("\r\n\r\n") && header.length < 4096) {
                                        val b = input.read(); check(b >= 0); header.append(b.toChar())
                                    }
                                    check(header.startsWith("HTTP/1.0 200") || header.startsWith("HTTP/1.1 200"))
                                    val size = Regex("(?i)Content-Length: ([0-9]+)").find(header)?.groupValues?.get(1)?.toInt() ?: error("No body")
                                    check(size in 12..1024)
                                    checkDns(ByteArray(size).also { response -> java.io.DataInputStream(input).readFully(response) })
                                }
                                else -> {
                                    val response = ByteArray(message.size)
                                    java.io.DataInputStream(input).readFully(response)
                                    check(response.contentEquals(message))
                                }
                            }
                        }
                    }
                    else -> error("Unknown test")
                }
                pending.resultCode = 1
                pending.resultData = "connected"
            } catch (e: Exception) {
                pending.resultCode = 0
                pending.resultData = e.javaClass.simpleName
            } finally { pending.finish() }
        }.start()
    }
    private fun checkDns(response: ByteArray) {
        check(response.size >= 12 && response[0] == 0x12.toByte() && response[1] == 0x34.toByte())
        check(response[2].toInt() and 0x80 != 0 && response[3].toInt() and 0x0f == 3) // NXDOMAIN fixture
    }
    private fun dnsQuery(nonce: String): ByteArray {
        val label = nonce.take(63).toByteArray(Charsets.US_ASCII)
        return byteArrayOf(0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, label.size.toByte()) + label +
            byteArrayOf(7) + "invalid".toByteArray(Charsets.US_ASCII) + byteArrayOf(0, 0, 1, 0, 1)
    }
}
