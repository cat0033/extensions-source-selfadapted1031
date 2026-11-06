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
import javax.crypto.spec.GCMParameterSpec
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
        // 确保拿到的是解密后的文档
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

        // 全面扫描各种可能的图片属性，防止漏图
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

        // 旧逻辑备用
        val config = doc.selectFirst(READER_CONFIG_SELECTOR)?.data()
        val slots = doc.select(READER_SLOT_SELECTOR).size
        if (!config.isNullOrEmpty() && slots > 0 && readerScript != null) {
            val scriptUrls = runCatching { readerScript!!.pageUrls(config, slots) }.getOrNull()
            if (!scriptUrls.isNullOrEmpty()) {
                return scriptUrls.mapIndexed { index, url -> Page(index, doc.location(), url) }
            }
        }

        error("Failed to read the page list")
    }

    private fun ensureDecrypted(document: Document): Document {
        val html = document.html()
        if (html.contains("var raw_key") && html.contains("var encrypted")) {
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
            val userAgent = request.header("User-Agent")
                ?: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36"

            val cookieName = "btwaf-21cb7f37099ce405e82768674d54a499-0711fc5487872cd6"
            val uaHash = MessageDigest.getInstance("SHA-256")
                .digest(userAgent.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }

            val existingCookie = request.header("Cookie")
            val newCookie = when {
                existingCookie.isNullOrEmpty() -> "$cookieName=$uaHash"
                !existingCookie.contains(cookieName) -> "$existingCookie; $cookieName=$uaHash"
                else -> existingCookie
            }

            val newRequest = request.newBuilder()
                .header("User-Agent", userAgent)
                .header("Cookie", newCookie)
                .build()

            runCatching {
                CookieManager.getInstance().setCookie("https://bakamh.com", "$cookieName=$uaHash; Path=/; Max-Age=2592000")
            }

            val response = chain.proceed(newRequest)

            val contentType = response.body.contentType()
            val subtype = contentType?.subtype?.lowercase(Locale.ROOT)
            if (subtype != null && subtype != "html" && subtype != "xhtml+xml") {
                return response
            }

            val bodyString = response.body.string()
            if (!bodyString.contains("var raw_key") || !bodyString.contains("var encrypted")) {
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
        fun decryptBtWaf(html: String): String? {
            return runCatching {
                val rawKeyStr = html.substringAfter("var raw_key = [", "")
                    .substringBefore("]", "")
                    .ifEmpty { return null }
                val encryptedHex = html.substringAfter("var encrypted = \"", "")
                    .substringBefore("\"", "")
                    .ifEmpty { return null }
                val tagStr = html.substringAfter("var tag = new Uint8Array([", "")
                    .substringBefore("]", "")
                    .ifEmpty { return null }
                val ivStr = html.substringAfter("var iv = new Uint8Array([", "")
                    .substringBefore("]", "")
                    .ifEmpty { return null }

                val rawKey = rawKeyStr.split(",").map { it.trim().toInt().toByte() }.toByteArray()
                val iv = ivStr.split(",").map { it.trim().toInt().toByte() }.toByteArray()
                val tag = tagStr.split(",").map { it.trim().toInt().toByte() }.toByteArray()

                val ciphertext = ByteArray(encryptedHex.length / 2) { i ->
                    encryptedHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }

                val ciphertextWithTag = ciphertext + tag
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rawKey, "AES"), GCMParameterSpec(128, iv))
                val decryptedBytes = cipher.doFinal(ciphertextWithTag)
                String(decryptedBytes, Charsets.UTF_8)
            }.getOrNull()
        }
    }
}
