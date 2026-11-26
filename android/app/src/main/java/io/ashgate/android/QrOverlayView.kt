package io.ashgate.android

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Path
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View

/** Dark scrim with a rounded square cutout and accent corner brackets over the camera preview. */
class QrOverlayView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {
    private val density = resources.displayMetrics.density
    private val scrim = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xA60C0D10.toInt()
        style = Paint.Style.FILL
    }
    private val bracket = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        color = 0xFFF47A2C.toInt()
        style = Paint.Style.STROKE
        strokeWidth = 4 * density
        strokeCap = Paint.Cap.ROUND
        strokeJoin = Paint.Join.ROUND
    }
    private val scrimPath = Path().apply { fillType = Path.FillType.EVEN_ODD }
    private val bracketPath = Path()
    private val frame = RectF()

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        super.onSizeChanged(w, h, oldw, oldh)
        val fw = w.toFloat()
        val fh = h.toFloat()
        val side = minOf(minOf(fw, fh) * 0.68f, 320 * density)
        val cx = fw / 2
        val cy = fh / 2 - minOf(fh * 0.06f, 48 * density)
        frame.set(cx - side / 2, cy - side / 2, cx + side / 2, cy + side / 2)

        val radius = 20 * density
        scrimPath.rewind()
        scrimPath.addRect(0f, 0f, fw, fh, Path.Direction.CW)
        scrimPath.addRoundRect(frame, radius, radius, Path.Direction.CW)

        val len = minOf(side * 0.18f, 36 * density).coerceAtLeast(radius)
        val l = frame.left
        val t = frame.top
        val r = frame.right
        val b = frame.bottom
        bracketPath.rewind()
        // Each bracket: straight arm, quarter arc matching the cutout corner, straight arm.
        bracketPath.moveTo(l, t + len)
        bracketPath.lineTo(l, t + radius)
        bracketPath.arcTo(RectF(l, t, l + 2 * radius, t + 2 * radius), 180f, 90f)
        bracketPath.lineTo(l + len, t)

        bracketPath.moveTo(r - len, t)
        bracketPath.lineTo(r - radius, t)
        bracketPath.arcTo(RectF(r - 2 * radius, t, r, t + 2 * radius), 270f, 90f)
        bracketPath.lineTo(r, t + len)

        bracketPath.moveTo(r, b - len)
        bracketPath.lineTo(r, b - radius)
        bracketPath.arcTo(RectF(r - 2 * radius, b - 2 * radius, r, b), 0f, 90f)
        bracketPath.lineTo(r - len, b)

        bracketPath.moveTo(l + len, b)
        bracketPath.lineTo(l + radius, b)
        bracketPath.arcTo(RectF(l, b - 2 * radius, l + 2 * radius, b), 90f, 90f)
        bracketPath.lineTo(l, b - len)
    }

    override fun onDraw(canvas: Canvas) {
        canvas.drawPath(scrimPath, scrim)
        canvas.drawPath(bracketPath, bracket)
    }
}
