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
        rateLimit(2) // Rate limit added to prevent 429 errors during library updates
    }

    override fun Headers.Builder.configureHeaders() = apply {
        add("Accept-Language", "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7")
    }

    override val mangaDetailsSelectorStatus = ".post-content_item:contains(状态) .summary-content"

    // Site keeps renaming the chapter <li> class, so match the list structure instead
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

    override suspend fun fetchChapterDocument(chapterUrl: String) = super.fetchChapterDocument(chapterUrl).also { document ->
        if (document.selectFirst(READER_CONFIG_SELECTOR) == null) return@also
        sendReaderBeacon(chapterUrl)

        val hasDirectImages = document.selectFirst("div.reading-content img[data-src], div.reading-content img[src]") != null
        if (hasDirectImages) return@also

        val scriptUrl = document.selectFirst("script#mkjp-reader-window-js")?.absUrl("src") ?: return@also
        if (scriptUrl.isNotEmpty() && readerScript?.url != scriptUrl) {
            runCatching {
                readerScript = ReaderScript(scriptUrl, client.get(scriptUrl).body.string())
            }
        }
    }

    // The reader's mkjp_rv beacon; chapters read without it end in the site's third-party tool warning
    private suspend fun sendReaderBeacon(chapterUrl: String) {
        val headers = headersBuilder().set("Referer", chapterUrl).build()
        val body = FormBody.Builder().add("action", "mkjp_rv").build()
        client.post("$baseUrl/wp-admin/admin-ajax.php", headers, body, ensureSuccess = false).close()
    }

    override fun parsePages(document: Document): List<Page> {
        // 双重兜底：若页面未被拦截器解密，在此处再次尝试解密
        val doc = if (document.selectFirst(".btbox") != null || document.html().contains("var raw_key")) {
            decryptBtWaf(document.html(), document.location())?.let {
                Jsoup.parse(it, document.location())
            } ?: document
        } else {
            document
        }

        doc.selectFirst(".mkjp-ea-lock__title")?.let { title ->
            val needsLogin = doc.selectFirst(".mkjp-ea-lock [data-target='#form-login']") != null
            error(if (needsLogin) "需在 WebView 中登录，账号有封禁风险" else title.text())
        }
        doc.selectFirst(".mkjp-tool-warning")?.let { error(it.text()) }

        // 1. 优先提取解密后 HTML 中的所有漫画图片地址
        val pages = doc.select("div.reading-content img, div.page-break img").mapNotNull { img ->
            val url = img.attr("abs:data-src").ifEmpty {
                img.attr("abs:data-manga-src").ifEmpty {
                    img.attr("abs:data-lazy-src").ifEmpty {
                        img.attr("abs:src")
                    }
                }
            }.trim()
            url.takeIf { it.isNotEmpty() && !it.startsWith("data:") }
        }

        if (pages.isNotEmpty()) {
            return pages.mapIndexed { index, url -> Page(index, doc.location(), url) }
        }

        // 2. 旧版本备用解密
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

    /**
     * 宝塔 WAF (btwaf) 自动解密拦截器
     */
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
            if (!bodyString.contains("btwaf_aes_forge") && !bodyString.contains("var raw_key")) {
                return response.newBuilder()
                    .body(bodyString.toResponseBody(contentType))
                    .build()
            }

            val decryptedHtml = decryptBtWaf(bodyString, request.url.encodedPath) ?: bodyString
            return response.newBuilder()
                .body(decryptedHtml.toResponseBody(contentType))
                .build()
        }
    }

    companion object {
        /**
         * 解密宝塔 WAF 的 AES-GCM 密文页面并设置放行 Cookie
         */
        fun decryptBtWaf(html: String, pathOrUrl: String): String? {
            return runCatching {
                val rawKeyMatch = Regex("""var\s+raw_key\s*=\s*\[(.*?)\]""").find(html)?.groupValues?.get(1) ?: return null
                val encryptedHex = Regex("""var\s+encrypted\s*=\s*"([^"]+)"""").find(html)?.groupValues?.get(1) ?: return null
                val tagMatch = Regex("""var\s+tag\s*=\s*new\s+Uint8Array\(\[(.*?)\]\)""").find(html)?.groupValues?.get(1) ?: return null
                val ivMatch = Regex("""var\s+iv\s*=\s*new\s+Uint8Array\(\[(.*?)\]\)""").find(html)?.groupValues?.get(1) ?: return null

                val rawKey = rawKeyMatch.split(",").map { it.trim().toInt().toByte() }.toByteArray()
                val iv = ivMatch.split(",").map { it.trim().toInt().toByte() }.toByteArray()
                val tag = tagMatch.split(",").map { it.trim().toInt().toByte() }.toByteArray()

                val ciphertext = ByteArray(encryptedHex.length / 2) { i ->
                    encryptedHex.substring(i * 2, i * 2 + 2).toInt(16).toByte()
                }

                // Java AES/GCM/NoPadding 解密要求将 16 字节 tag 拼在密文末尾
                val ciphertextWithTag = ciphertext + tag
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(rawKey, "AES"), GCMParameterSpec(128, iv))
                val decryptedBytes = cipher.doFinal(ciphertextWithTag)
                val decryptedHtml = String(decryptedBytes, Charsets.UTF_8)

                // 提取 WAF 放行 Cookie 并写入系统 CookieManager
                runCatching {
                    val cookieName = Regex("""['"](btwaf-[0-9a-fA-F-]+)['"]""").find(html)?.groupValues?.get(1)
                    if (cookieName != null) {
                        val path = when {
                            pathOrUrl.startsWith("http://") || pathOrUrl.startsWith("https://") ->
                                runCatching { java.net.URI(pathOrUrl).rawPath }.getOrDefault(pathOrUrl)
                            else -> pathOrUrl
                        }
                        val digest = MessageDigest.getInstance("SHA-256")
                            .digest(path.toByteArray(Charsets.UTF_8))
                            .joinToString("") { "%02x".format(it) }
                        CookieManager.getInstance().setCookie("https://bakamh.com", "$cookieName=$digest; Path=/; Max-Age=2592000")
                    }
                }

                decryptedHtml
            }.getOrNull()
        }
    }
}
