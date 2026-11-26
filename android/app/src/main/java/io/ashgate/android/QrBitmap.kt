package io.ashgate.android

import android.graphics.Bitmap
import com.google.zxing.BarcodeFormat
import com.google.zxing.BinaryBitmap
import com.google.zxing.ChecksumException
import com.google.zxing.DecodeHintType
import com.google.zxing.EncodeHintType
import com.google.zxing.FormatException
import com.google.zxing.NotFoundException
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.RGBLuminanceSource
import com.google.zxing.common.GlobalHistogramBinarizer
import com.google.zxing.common.HybridBinarizer
import com.google.zxing.qrcode.QRCodeReader
import com.google.zxing.qrcode.QRCodeWriter
import com.google.zxing.qrcode.decoder.ErrorCorrectionLevel
import org.json.JSONObject

object QrBitmap {
    fun encodePayload(profile: JSONObject): String? {
        val kind = profile.optString("kind").ifEmpty { "vless" }
        val link = profile.optString("link")
        val name = profile.optString("name")
        val host = profile.optString("host")
        val port = profile.optInt("port")
        val user = profile.optString("user")
        val pass = profile.optString("pass")
        return ProfileQr.encode(kind, link, name, host, port, user, pass)
    }

    fun generate(payload: String, sizePx: Int): Bitmap {
        val ecLevel = if (payload.length <= 400) ErrorCorrectionLevel.M else ErrorCorrectionLevel.L
        val hints = mapOf(
            EncodeHintType.CHARACTER_SET to "UTF-8",
            EncodeHintType.MARGIN to 1,
            EncodeHintType.ERROR_CORRECTION to ecLevel,
        )
        val matrix = QRCodeWriter().encode(payload, BarcodeFormat.QR_CODE, sizePx, sizePx, hints)
        val w = matrix.width
        val h = matrix.height
        val pixels = IntArray(w * h)
        val black = 0xFF000000.toInt()
        val white = 0xFFFFFFFF.toInt()
        for (y in 0 until h) {
            val offset = y * w
            for (x in 0 until w) {
                pixels[offset + x] = if (matrix.get(x, y)) black else white
            }
        }
        val bitmap = Bitmap.createBitmap(w, h, Bitmap.Config.ARGB_8888)
        bitmap.setPixels(pixels, 0, w, 0, 0, w, h)
        return bitmap
    }

    fun decodeYuv(
        yData: ByteArray,
        width: Int,
        height: Int,
        rowStride: Int,
        tryInverted: Boolean = false,
    ): String? {
        val packed = if (rowStride == width && yData.size >= width * height) {
            yData
        } else {
            val dest = ByteArray(width * height)
            for (row in 0 until height) {
                val srcOffset = row * rowStride
                val destOffset = row * width
                val copyLen = minOf(width, maxOf(0, yData.size - srcOffset))
                if (copyLen > 0) {
                    System.arraycopy(yData, srcOffset, dest, destOffset, copyLen)
                }
            }
            dest
        }

        val source = PlanarYUVLuminanceSource(packed, width, height, 0, 0, width, height, false)
        val hints = mapOf<DecodeHintType, Any>(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.CHARACTER_SET to "UTF-8",
        )
        val reader = QRCodeReader()
        return try {
            try {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
            } catch (e1: Exception) {
                if (e1 !is NotFoundException && e1 !is ChecksumException && e1 !is FormatException) throw e1
                if (!tryInverted) return null
                reader.reset()
                try {
                    reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text
                } catch (e2: Exception) {
                    if (e2 !is NotFoundException && e2 !is ChecksumException && e2 !is FormatException) throw e2
                    reader.reset()
                    try {
                        reader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)), hints).text
                    } catch (e3: Exception) {
                        if (e3 !is NotFoundException && e3 !is ChecksumException && e3 !is FormatException) throw e3
                        null
                    }
                }
            }
        } finally {
            reader.reset()
        }
    }

    fun decodeBitmap(bitmap: Bitmap): String? {
        val w = bitmap.width
        val h = bitmap.height
        val pixels = IntArray(w * h)
        bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
        val source = RGBLuminanceSource(w, h, pixels)
        val hints = mapOf<DecodeHintType, Any>(
            DecodeHintType.POSSIBLE_FORMATS to listOf(BarcodeFormat.QR_CODE),
            DecodeHintType.TRY_HARDER to true,
            DecodeHintType.CHARACTER_SET to "UTF-8",
        )
        val reader = QRCodeReader()
        return try {
            try {
                reader.decode(BinaryBitmap(HybridBinarizer(source)), hints).text
            } catch (e1: Exception) {
                if (e1 !is NotFoundException && e1 !is ChecksumException && e1 !is FormatException) throw e1
                reader.reset()
                try {
                    reader.decode(BinaryBitmap(GlobalHistogramBinarizer(source)), hints).text
                } catch (e2: Exception) {
                    if (e2 !is NotFoundException && e2 !is ChecksumException && e2 !is FormatException) throw e2
                    reader.reset()
                    try {
                        reader.decode(BinaryBitmap(HybridBinarizer(source.invert())), hints).text
                    } catch (e3: Exception) {
                        if (e3 !is NotFoundException && e3 !is ChecksumException && e3 !is FormatException) throw e3
                        null
                    }
                }
            }
        } finally {
            reader.reset()
        }
    }
}
