package eu.kanade.tachiyomi.extension.zh.bakamh

import android.webkit.CookieManager
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
import java.security.MessageDigest
import java.time.format.DateTimeFormatter
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

@Source
abstract class Bakamh : Madara() {
    override val chapterDateFormat = DateTimeFormatter.ofPattern("yyyy 年 M 月 d 日", Locale.CHINESE)

    override fun OkHttpClient.Builder.configureClient() = apply {
        addInterceptor(UserAgentClientHintsInterceptor())
        addInterceptor(BtWafInterceptor())
        addNetworkInterceptor(BtWafNetworkInterceptor())
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

    private class BtWafNetworkInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val request = chain.request()
            val userAgent = request.header("User-Agent")
                ?: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

            // 动态提取 btwaf cookie 名称和哈希值
            val html = runCatching {
                chain.proceed(request).peekBody(Long.MAX_VALUE).string()
            }.getOrNull() ?: ""

            val cookieName = Regex("""['"](btwaf-[0-9a-fA-F-]+)['"]""").find(html)?.groupValues?.get(1)
            val cookieValue = MessageDigest.getInstance("SHA-256")
                .digest(userAgent.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

            val existingCookie = request.header("Cookie").orEmpty()
            val mergedCookie = if (cookieName != null && !existingCookie.contains(cookieName)) {
                if (existingCookie.isEmpty()) "$cookieName=$cookieValue" else "$existingCookie; $cookieName=$cookieValue"
            } else {
                existingCookie
            }

            val newRequest = request.newBuilder()
                .header("User-Agent", userAgent)
                .header("Cookie", mergedCookie)
                .build()

            runCatching {
                if (cookieName != null) {
                    CookieManager.getInstance().setCookie("https://bakamh.com", "$cookieName=$cookieValue; Path=/; Max-Age=2592000")
                }
            }

            // 继续执行请求链，但需要重新构建响应体，因为 peekBody 已经消费了一次
            return chain.proceed(newRequest).newBuilder()
                .body(html.toResponseBody(response.body.contentType()))
                .build()
        }
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

        fun decryptBtWaf(html: String): String? {
            return try {
                val rawKey = extractByteArray(html, "raw_key", 16) ?: error("raw_key (16 bytes) not found")
                val iv = extractByteArray(html, "iv", 16) ?: error("iv (16 bytes) not found") // 修正为 16 字节
                val tag = extractByteArray(html, "tag", 16) ?: error("tag (16 bytes) not found")
                val encryptedHex = extractEncryptedHex(html) ?: error("encrypted hex not found")

                val ciphertext = ByteArray(encryptedHex.length / 2) { i ->
                    encryptedHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }

                // AES/CBC/PKCS5Padding 解密
                val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rawKey, "AES"), IvParameterSpec(iv))
                val decryptedBytes = cipher.doFinal(ciphertext)

                lastDecryptError = null
                String(decryptedBytes, Charsets.UTF_8)
            } catch (e: Throwable) {
                lastDecryptError = "${e.javaClass.simpleName}: ${e.message}"
                null
            }
        }

        // 统一的字节数组提取函数，通过锚点和预期长度更健壮地提取参数
        private fun extractByteArray(html: String, anchor: String, expectedLength: Int): ByteArray? {
            val startAnchor = "var $anchor=["
            val idx = html.indexOf(startAnchor).takeIf { it != -1 } ?: return null
            val start = idx + startAnchor.length
            val end = html.indexOf(']', start).takeIf { it != -1 } ?: return null

            val bytes = html.substring(start, end).split(",")
                .mapNotNull { it.trim().toIntOrNull()?.toByte() }
                .toByteArray()
            return bytes.takeIf { it.size == expectedLength }
        }

        private fun extractEncryptedHex(html: String): ByteArray? {
            val startAnchor = "var encrypted=\""
            val idx = html.indexOf(startAnchor).takeIf { it != -1 } ?: return null
            val start = idx + startAnchor.length
            val end = html.indexOf("\";", start).takeIf { it != -1 } ?: return null // 注意这里的分号和引号
            val hex = html.substring(start, end).trim()
            if (hex.length < 32 || hex.length % 2 != 0) return null
            return ByteArray(hex.length / 2) { i ->
                hex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
            }
        }
    }
}
