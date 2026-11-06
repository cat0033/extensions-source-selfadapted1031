package eu.kanade.tachiyomi.extension.zh.bakamh

import eu.kanade.tachiyomi.multisrc.madara.Madara
import eu.kanade.tachiyomi.source.model.Page
import eu.kanade.tachiyomi.source.model.SChapter
import eu.kanade.tachiyomi.source.model.SManga
import keiyoushi.annotation.Source
import keiyoushi.network.get
import keiyoushi.network.post
import keiyoushi.network.rateLimit
import okhttp3.FormBody
import okhttp3.Headers
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import java.time.format.DateTimeFormatter
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Source
abstract class Bakamh : Madara() {
    override val chapterDateFormat = DateTimeFormatter.ofPattern("yyyy 年 M 月 d 日", Locale.CHINESE)

    override fun OkHttpClient.Builder.configureClient() = apply {
        addInterceptor(UserAgentClientHintsInterceptor())
        addInterceptor(BtWafInterceptor())
        rateLimit(2)
    }

    override fun Headers.Builder.configureHeaders() = apply {
        add("Accept-Language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7")
    }

    override val mangaDetailsSelectorStatus = ".post-content_item:contains(状态) .summary-content"

    override fun chapterListSelector() = "ul.version-chap > li"

    override val chapterDateSelector = "span.chapter-release-date i"

    override suspend fun fetchMangaUpdate(
        manga: SManga,
        chapters: List<SChapter>,
        fetchDetails: Boolean,
        fetchChapters: Boolean,
    ) = super.fetchMangaUpdate(
        manga.apply {
            url = url.lowercase()
        },
        chapters,
        fetchDetails,
        fetchChapters,
    )

    @Volatile
    private var readerScript: ReaderScript? = null

    override suspend fun fetchChapterDocument(chapterUrl: String): Document {
        val rawDoc = super.fetchChapterDocument(chapterUrl)
        val document = ensureDecrypted(rawDoc)

        if (document.selectFirst(READER_CONFIG_SELECTOR) != null) {
            sendReaderBeacon(chapterUrl)
        }

        val hasDirectImages = document.selectFirst("div.reading-content img, div.page-break img") != null
        if (!hasDirectImages) {
            val scriptUrl = document.selectFirst("script#mkjp-reader-window-js")?.absUrl("src")
            if (!scriptUrl.isNullOrEmpty() && readerScript?.url != scriptUrl) {
                runCatching {
                    readerScript = ReaderScript(scriptUrl, client.get(scriptUrl).body.string())
                }
            }
        }
        return document
    }

    private suspend fun sendReaderBeacon(chapterUrl: String) {
        val headers = headersBuilder().set("Referer", chapterUrl).build()
        val body = FormBody.Builder().add("action", "mkjp_rv").build()
        client.post("$baseUrl/wp-admin/admin-ajax.php", headers, body, ensureSuccess = false).close()
    }

    override fun parsePages(document: Document): List<Page> {
        val doc = ensureDecrypted(document)

        doc.selectFirst(".mkjp-ea-lock__title")?.let { title ->
            val needsLogin = doc.selectFirst(".mkjp-ea-lock [data-target='#form-login']") != null
            error(if (needsLogin) "需在 WebView 中登录，账号有封禁风险" else title.text())
        }
        doc.selectFirst(".mkjp-tool-warning")?.let { error(it.text()) }

        val pages = doc.select("div.reading-content img, div.page-break img, img.wp-manga-chapter-img").mapNotNull { img ->
            val url = img.attr("abs:data-src").ifEmpty {
                img.attr("abs:data-manga-src").ifEmpty {
                    img.attr("abs:data-original").ifEmpty {
                        img.attr("abs:data-lazy-src").ifEmpty {
                            img.attr("abs:src")
                        }
                    }
                }
            }.trim()
            url.takeIf { it.isNotEmpty() && !it.startsWith("data:") && !it.contains("placeholder") }
        }

        if (pages.isNotEmpty()) {
            return pages.mapIndexed { index, url -> Page(index, doc.location(), url) }
        }

        val config = doc.selectFirst(READER_CONFIG_SELECTOR)?.data()
        val slots = doc.select(READER_SLOT_SELECTOR).size
        if (!config.isNullOrEmpty() && slots > 0 && readerScript != null) {
            val scriptUrls = runCatching { readerScript!!.pageUrls(config, slots) }.getOrNull()
            if (!scriptUrls.isNullOrEmpty()) {
                return scriptUrls.mapIndexed { index, url -> Page(index, doc.location(), url) }
            }
        }

        error(
            "Failed to read the page list: [Title='${doc.title()}'] [HTML len=${doc.html().length}] " +
                "[Images found=${doc.select("img").size}] [IsWAF=${doc.html().contains("raw_key")}] " +
                "[DecryptErr='$lastDecryptError']",
        )
    }

    private fun ensureDecrypted(document: Document): Document {
        val html = document.html()
        if (html.contains("raw_key") && html.contains("encrypted")) {
            val decrypted = decryptBtWaf(html)
            if (!decrypted.isNullOrEmpty()) {
                return Jsoup.parse(decrypted, document.location())
            }
        }
        return document
    }

    private class BtWafInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val response = chain.proceed(request)

            val contentType = response.body.contentType()
            val subtype = contentType?.subtype?.lowercase(Locale.ROOT)
            if (subtype != null && subtype != "html" && subtype != "xhtml+xml") {
                return response
            }

            val bodyString = response.body.string()
            if (!bodyString.contains("raw_key") || !bodyString.contains("encrypted")) {
                return response.newBuilder()
                    .body(bodyString.toResponseBody(contentType))
                    .build()
            }

            val decryptedHtml = decryptBtWaf(bodyString) ?: bodyString
            return response.newBuilder()
                .body(decryptedHtml.toResponseBody(contentType))
                .build()
        }
    }

    companion object {
        @Volatile
        var lastDecryptError: String? = null

        /**
         * 全能多模式自适应解密：自动探测 GCM / CTR / CBC / CFB 算法并消除填充块限制
         */
        fun decryptBtWaf(html: String): String? {
            return try {
                val rawKey = extractRawKey(html) ?: error("raw_key not found")
                val iv = extractIv(html) ?: error("iv not found")
                val tag = extractTag(html)
                val ciphertext = extractEncryptedHex(html) ?: error("encrypted hex not found")

                val keySpec = SecretKeySpec(rawKey, "AES")
                var decryptedBytes: ByteArray? = null

                // 1. 如果带有 16 字节 Tag 且 IV 为 12 字节，优先走 GCM
                if (tag != null && iv.size == 12) {
                    runCatching {
                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, GCMParameterSpec(128, iv))
                        decryptedBytes = cipher.doFinal(ciphertext + tag)
                    }
                }

                // 2. 尝试流密码模式 CTR（无块大小对齐限制，可解密任意长度密文）
                if (decryptedBytes == null && iv.size == 16) {
                    runCatching {
                        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
                        val candidate = cipher.doFinal(ciphertext)
                        if (candidate.isValidHtml()) decryptedBytes = candidate
                    }
                }

                // 3. 尝试 CBC 模式（自动对齐 16 字节块长度）
                if (decryptedBytes == null && iv.size == 16) {
                    runCatching {
                        val alignedCiphertext = if (ciphertext.size % 16 != 0) {
                            val padLen = 16 - (ciphertext.size % 16)
                            ciphertext + ByteArray(padLen)
                        } else {
                            ciphertext
                        }
                        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
                        val candidate = cipher.doFinal(alignedCiphertext)
                        if (candidate.isValidHtml()) decryptedBytes = candidate
                    }
                }

                // 4. 尝试 CFB 模式
                if (decryptedBytes == null && iv.size == 16) {
                    runCatching {
                        val cipher = Cipher.getInstance("AES/CFB/NoPadding")
                        cipher.init(Cipher.DECRYPT_MODE, keySpec, IvParameterSpec(iv))
                        val candidate = cipher.doFinal(ciphertext)
                        if (candidate.isValidHtml()) decryptedBytes = candidate
                    }
                }

                if (decryptedBytes == null) {
                    error("All AES algorithms failed (keySize=${rawKey.size}, ivSize=${iv.size}, cipherSize=${ciphertext.size})")
                }

                lastDecryptError = null
                String(decryptedBytes!!, Charsets.UTF_8)
            } catch (e: Throwable) {
                lastDecryptError = "${e.javaClass.simpleName}: ${e.message}"
                null
            }
        }

        private fun ByteArray.isValidHtml(): Boolean {
            val head = String(this.take(200).toByteArray(), Charsets.UTF_8).lowercase(Locale.ROOT)
            return head.contains("<html") || head.contains("<!doctype") || head.contains("<div") || head.contains("<head")
        }

        private fun extractRawKey(html: String): ByteArray? {
            val idx = html.indexOf("raw_key").takeIf { it != -1 } ?: return null
            val start = html.indexOf('[', idx).takeIf { it != -1 } ?: return null
            val end = html.indexOf(']', start).takeIf { it != -1 } ?: return null
            val bytes = html.substring(start + 1, end).split(",")
                .mapNotNull { it.trim().toIntOrNull()?.toByte() }
                .toByteArray()
            return bytes.takeIf { it.size == 16 || it.size == 24 || it.size == 32 }
        }

        private fun extractIv(html: String): ByteArray? {
            val idx = html.indexOf("var iv").takeIf { it != -1 }
                ?: html.indexOf("iv = new Uint8Array").takeIf { it != -1 }
                ?: html.indexOf("iv=new Uint8Array").takeIf { it != -1 }
                ?: html.indexOf("iv = [").takeIf { it != -1 }
                ?: html.indexOf("iv=[").takeIf { it != -1 }
                ?: html.indexOf("iv=").takeIf { it != -1 }
                ?: return null
            val start = html.indexOf('[', idx).takeIf { it != -1 } ?: return null
            val end = html.indexOf(']', start).takeIf { it != -1 } ?: return null
            val bytes = html.substring(start + 1, end).split(",")
                .mapNotNull { it.trim().toIntOrNull()?.toByte() }
                .toByteArray()
            return bytes.takeIf { it.size == 12 || it.size == 16 }
        }

        private fun extractTag(html: String): ByteArray? {
            val idx = html.indexOf("var tag").takeIf { it != -1 }
                ?: html.indexOf("tag = new Uint8Array").takeIf { it != -1 }
                ?: html.indexOf("tag=new Uint8Array").takeIf { it != -1 }
                ?: html.indexOf("tag = [").takeIf { it != -1 }
                ?: html.indexOf("tag=[").takeIf { it != -1 }
                ?: return null
            val start = html.indexOf('[', idx).takeIf { it != -1 } ?: return null
            val end = html.indexOf(']', start).takeIf { it != -1 } ?: return null
            val bytes = html.substring(start + 1, end).split(",")
                .mapNotNull { it.trim().toIntOrNull()?.toByte() }
                .toByteArray()
            return bytes.takeIf { it.size == 16 }
        }

        private fun extractEncryptedHex(html: String): ByteArray? {
            val idx = html.indexOf("encrypted").takeIf { it != -1 } ?: return null
            val q1 = html.indexOf('"', idx).takeIf { it != -1 } ?: html.indexOf('\'', idx).takeIf { it != -1 } ?: return null
            val quoteChar = html[q1]
            val q2 = html.indexOf(quoteChar, q1 + 1).takeIf { it != -1 } ?: return null
            // 清理一切空白字符与回车，防止字符错位
            val hex = html.substring(q1 + 1, q2).filter { !it.isWhitespace() }
            if (hex.length < 32) return null
            val validLen = if (hex.length % 2 != 0) hex.length - 1 else hex.length
            return ByteArray(validLen / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
