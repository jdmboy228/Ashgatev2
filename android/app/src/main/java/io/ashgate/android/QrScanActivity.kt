package io.ashgate.android

import android.Manifest
import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.BitmapFactory
import android.graphics.ImageFormat
import android.graphics.Matrix
import android.graphics.RectF
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.media.ImageReader
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.os.SystemClock
import android.provider.Settings
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.widget.ImageButton
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * Scans a profile QR with the back camera (Camera2, no libraries besides the zxing decoder) or
 * from a picture in the gallery. Every failure of the camera (no hardware, no permission, open
 * error) only shows a message: the gallery stays usable and the screen never crashes.
 */
class QrScanActivity : Activity() {
    companion object {
        const val EXTRA_IMPORTED_NAME = "imported_name"
        const val EXTRA_IMPORTED_COUNT = "imported_count"
        private const val REQ_CAMERA = 41
        private const val REQ_PICK = 42
        private const val STATE_ASKED = "asked"
        private const val MAX_ANALYSIS_W = 1280
        private const val MAX_ANALYSIS_H = 960
        private const val MAX_PREVIEW_W = 1920
        private const val MAX_IMAGE_SIDE = 1600
        private const val COOLDOWN_MS = 1500L
    }

    private lateinit var preview: TextureView
    private lateinit var hint: TextView
    private lateinit var errorView: TextView
    private lateinit var status: View
    private lateinit var statusText: TextView
    private lateinit var grant: TextView
    private lateinit var torch: ImageButton

    private val cameraLock = Any()
    private var camThread: HandlerThread? = null
    private var handler: Handler? = null
    private var device: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var previewSurface: Surface? = null
    private var request: CaptureRequest.Builder? = null
    private var active = false
    private var torchOn = false
    private var previewSize = android.util.Size(0, 0)
    private var sensorOrientation = 90

    private val analyzing = AtomicBoolean(false)
    private val importing = AtomicBoolean(false)

    @Volatile
    private var frameCount = 0

    @Volatile
    private var lastBad: String? = null

    @Volatile
    private var lastBadAt = 0L

    private var resumed = false
    private var asked = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Store.usable(this)) return finish()
        setContentView(R.layout.activity_qr_scan)
        asked = savedInstanceState?.getBoolean(STATE_ASKED) ?: false
        preview = findViewById(R.id.preview)
        hint = findViewById(R.id.scan_hint)
        errorView = findViewById(R.id.scan_error)
        status = findViewById(R.id.scan_status)
        statusText = findViewById(R.id.scan_status_text)
        grant = findViewById(R.id.grant_camera)
        torch = findViewById(R.id.torch)
        Fonts.set(Fonts.extrabold(this), findViewById<TextView>(R.id.scan_title))
        Fonts.set(Fonts.medium(this), hint, errorView, statusText)
        Fonts.set(Fonts.bold(this), grant)
        hint.setText(R.string.qr_scan_hint)
        findViewById<View>(R.id.back).onClick { finish() }
        findViewById<View>(R.id.pick_gallery).onClick { pickImage() }
        grant.onClick { grantCamera() }
        torch.visibility = View.GONE
        torch.onClick { toggleTorch() }

        preview.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(st: SurfaceTexture, w: Int, h: Int) {
                if (resumed) startCamera()
            }

            override fun onSurfaceTextureSizeChanged(st: SurfaceTexture, w: Int, h: Int) = configureTransform()

            override fun onSurfaceTextureDestroyed(st: SurfaceTexture): Boolean {
                stopCamera()
                return true
            }

            override fun onSurfaceTextureUpdated(st: SurfaceTexture) {}
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putBoolean(STATE_ASKED, asked)
    }

    override fun onResume() {
        super.onResume()
        resumed = true
        if (!::preview.isInitialized) return
        try {
            if (!packageManager.hasSystemFeature(PackageManager.FEATURE_CAMERA_ANY)) {
                showStatus(R.string.qr_camera_unavailable, false)
            } else if (hasPermission()) {
                status.visibility = View.GONE
                if (preview.isAvailable) startCamera()
            } else if (!asked) {
                asked = true
                requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
            } else {
                showStatus(R.string.qr_camera_denied, true)
            }
        } catch (_: Throwable) {
            showStatus(R.string.qr_camera_unavailable, false)
        }
    }

    override fun onPause() {
        resumed = false
        stopCamera()
        super.onPause()
    }

    override fun onDestroy() {
        resumed = false
        stopCamera()
        super.onDestroy()
    }

    private fun hasPermission() =
        checkSelfPermission(Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED

    private fun showStatus(text: Int, canGrant: Boolean) {
        statusText.setText(text)
        grant.visibility = if (canGrant) View.VISIBLE else View.GONE
        status.visibility = View.VISIBLE
        torch.visibility = View.GONE
    }

    override fun onRequestPermissionsResult(code: Int, permissions: Array<out String>, results: IntArray) {
        super.onRequestPermissionsResult(code, permissions, results)
        if (code != REQ_CAMERA || isFinishing || isDestroyed) return
        if (results.isNotEmpty() && results[0] == PackageManager.PERMISSION_GRANTED) {
            status.visibility = View.GONE
            if (resumed && preview.isAvailable) startCamera()
        } else {
            showStatus(R.string.qr_camera_denied, true)
        }
    }

    private fun grantCamera() {
        try {
            if (shouldShowRequestPermissionRationale(Manifest.permission.CAMERA)) {
                requestPermissions(arrayOf(Manifest.permission.CAMERA), REQ_CAMERA)
            } else {
                startActivity(
                    Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.fromParts("package", packageName, null)),
                )
            }
        } catch (_: Throwable) {
        }
    }

    // ---- Camera ----

    private fun startCamera() {
        if (isFinishing || isDestroyed || !hasPermission()) return
        synchronized(cameraLock) {
            if (active) return
            try {
                val mgr = getSystemService(Context.CAMERA_SERVICE) as CameraManager
                val ids = mgr.cameraIdList
                if (ids.isEmpty()) {
                    showStatus(R.string.qr_camera_unavailable, false)
                    return
                }
                val id = ids.firstOrNull {
                    mgr.getCameraCharacteristics(it).get(CameraCharacteristics.LENS_FACING) ==
                        CameraCharacteristics.LENS_FACING_BACK
                } ?: ids[0]
                val ch = mgr.getCameraCharacteristics(id)
                val map = ch.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
                if (map == null) {
                    showStatus(R.string.qr_camera_unavailable, false)
                    return
                }
                sensorOrientation = ch.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90
                val viewLong = maxOf(preview.width, preview.height).toFloat()
                val viewShort = minOf(preview.width, preview.height).toFloat().coerceAtLeast(1f)
                val viewRatio = viewLong / viewShort
                val pSizes = map.getOutputSizes(SurfaceTexture::class.java).orEmpty()
                    .filter { it.width <= MAX_PREVIEW_W && it.height <= 1440 }
                val pChoice = best(pSizes, viewRatio) ?: map.getOutputSizes(SurfaceTexture::class.java)?.firstOrNull()
                val allYuv = map.getOutputSizes(ImageFormat.YUV_420_888).orEmpty()
                val aSizes = allYuv.filter { it.width <= MAX_ANALYSIS_W && it.height <= MAX_ANALYSIS_H }
                val aChoice = (pChoice?.let { best(aSizes, it.width.toFloat() / it.height) }
                    ?: aSizes.firstOrNull()
                    ?: allYuv.minByOrNull { it.width.toLong() * it.height.toLong() })
                if (pChoice == null || aChoice == null) {
                    showStatus(R.string.qr_camera_unavailable, false)
                    return
                }
                previewSize = pChoice
                val flash = ch.get(CameraCharacteristics.FLASH_INFO_AVAILABLE) == true
                val afModes = ch.get(CameraCharacteristics.CONTROL_AF_AVAILABLE_MODES) ?: IntArray(0)
                val continuousAf = afModes.contains(CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)

                val st = preview.surfaceTexture ?: return
                st.setDefaultBufferSize(pChoice.width, pChoice.height)
                configureTransform()
                val t = HandlerThread("qr-camera").also { it.start() }
                val h = Handler(t.looper)
                camThread = t
                handler = h
                val r = ImageReader.newInstance(aChoice.width, aChoice.height, ImageFormat.YUV_420_888, 2)
                reader = r
                r.setOnImageAvailableListener({ ir -> analyze(ir) }, h)
                previewSurface = Surface(st)
                active = true
                mgr.openCamera(
                    id,
                    object : CameraDevice.StateCallback() {
                        override fun onOpened(camera: CameraDevice) {
                            val keep = synchronized(cameraLock) {
                                if (active && device == null && reader === r) {
                                    device = camera
                                    true
                                } else {
                                    false
                                }
                            }
                            if (!keep) {
                                camera.close()
                                return
                            }
                            createSession(camera, continuousAf, flash)
                        }

                        override fun onDisconnected(camera: CameraDevice) {
                            camera.close()
                            runOnUiThread { stopCamera() }
                        }

                        override fun onError(camera: CameraDevice, error: Int) {
                            camera.close()
                            runOnUiThread {
                                stopCamera()
                                if (!isFinishing && !isDestroyed) showStatus(R.string.qr_camera_unavailable, false)
                            }
                        }

                        override fun onClosed(camera: CameraDevice) {
                            synchronized(cameraLock) { if (device === camera) device = null }
                        }
                    },
                    h,
                )
            } catch (_: Throwable) {
                // CameraAccessException, SecurityException, IllegalArgumentException, anything the HAL throws.
                teardown()
                showStatus(R.string.qr_camera_unavailable, false)
            }
        }
    }

    private fun createSession(camera: CameraDevice, continuousAf: Boolean, flash: Boolean) {
        try {
            synchronized(cameraLock) {
                val r = reader
                val p = previewSurface
                if (!active || device !== camera || r == null || p == null) return
                val b = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW)
                b.addTarget(p)
                b.addTarget(r.surface)
                if (continuousAf) {
                    b.set(CaptureRequest.CONTROL_AF_MODE, CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE)
                }
                if (torchOn && flash) b.set(CaptureRequest.FLASH_MODE, CaptureRequest.FLASH_MODE_TORCH)
                request = b
                camera.createCaptureSession(
                    listOf(p, r.surface),
                    object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(s: CameraCaptureSession) {
                            synchronized(cameraLock) {
                                if (!active || device !== camera) {
                                    s.close()
                                    return
                                }
                                try {
                                    s.setRepeatingRequest(b.build(), null, handler)
                                    session = s
                                } catch (_: Throwable) {
                                    s.close()
                                    return
                                }
                            }
                            runOnUiThread {
                                if (isFinishing || isDestroyed) return@runOnUiThread
                                torch.visibility = if (flash) View.VISIBLE else View.GONE
                                updateTorchIcon()
                            }
                        }

                        override fun onConfigureFailed(s: CameraCaptureSession) {
                            s.close()
                            runOnUiThread {
                                stopCamera()
                                if (!isFinishing && !isDestroyed) showStatus(R.string.qr_camera_unavailable, false)
                            }
                        }
                    },
                    handler,
                )
            }
        } catch (_: Throwable) {
            runOnUiThread {
                stopCamera()
                if (!isFinishing && !isDestroyed) showStatus(R.string.qr_camera_unavailable, false)
            }
        }
    }

    /** Closest aspect ratio wins; among those the largest. */
    private fun best(sizes: List<android.util.Size>, ratio: Float): android.util.Size? =
        sizes.minWithOrNull(
            compareBy<android.util.Size> { Math.round(Math.abs(it.width.toFloat() / it.height - ratio) * 20) }
                .thenByDescending { it.width.toLong() * it.height },
        )

    /** Rotates and center-crops the camera buffer so the preview is never stretched or turned. */
    private fun configureTransform() {
        val vw = preview.width.toFloat()
        val vh = preview.height.toFloat()
        val pw = previewSize.width.toFloat()
        val ph = previewSize.height.toFloat()
        if (vw <= 0 || vh <= 0 || pw <= 0 || ph <= 0) return
        @Suppress("DEPRECATION")
        val rotation = windowManager.defaultDisplay.rotation
        val m = Matrix()
        val view = RectF(0f, 0f, vw, vh)
        val cx = view.centerX()
        val cy = view.centerY()
        if (rotation == Surface.ROTATION_90 || rotation == Surface.ROTATION_270) {
            val buf = RectF(0f, 0f, ph, pw)
            buf.offset(cx - buf.centerX(), cy - buf.centerY())
            m.setRectToRect(view, buf, Matrix.ScaleToFit.FILL)
            val scale = maxOf(vh / ph, vw / pw)
            m.postScale(scale, scale, cx, cy)
            m.postRotate(90f * (rotation - 2), cx, cy)
        } else {
            // Portrait: the buffer is landscape and the sensor is usually turned 90 degrees.
            val turned = sensorOrientation == 90 || sensorOrientation == 270
            val bw = if (turned) ph else pw
            val bh = if (turned) pw else ph
            val scale = maxOf(vw / bw, vh / bh)
            // TextureView stretches the buffer to the view; undo that, then cover the view.
            m.setScale((bw * scale) / vw, (bh * scale) / vh, cx, cy)
            if (rotation == Surface.ROTATION_180) m.postRotate(180f, cx, cy)
        }
        preview.setTransform(m)
    }

    private fun toggleTorch() {
        synchronized(cameraLock) {
            val b = request ?: return
            val s = session ?: return
            torchOn = !torchOn
            try {
                b.set(
                    CaptureRequest.FLASH_MODE,
                    if (torchOn) CaptureRequest.FLASH_MODE_TORCH else CaptureRequest.FLASH_MODE_OFF,
                )
                s.setRepeatingRequest(b.build(), null, handler)
            } catch (_: Throwable) {
                torchOn = false
            }
        }
        updateTorchIcon()
    }

    private fun updateTorchIcon() =
        torch.setImageResource(if (torchOn) R.drawable.ic_flash_on else R.drawable.ic_flash_off)

    /** Closes everything the camera holds. Safe to call twice, from any thread. */
    private fun teardown() {
        synchronized(cameraLock) {
            active = false
            try { session?.close() } catch (_: Throwable) {}
            session = null
            try { device?.close() } catch (_: Throwable) {}
            device = null
            try { reader?.setOnImageAvailableListener(null, null) } catch (_: Throwable) {}
            try { reader?.close() } catch (_: Throwable) {}
            reader = null
            try { previewSurface?.release() } catch (_: Throwable) {}
            previewSurface = null
            request = null
            try { camThread?.quitSafely() } catch (_: Throwable) {}
            camThread = null
            handler = null
        }
        analyzing.set(false)
    }

    private fun stopCamera() {
        teardown()
        if (::torch.isInitialized) torch.visibility = View.GONE
    }

    // ---- Analysis ----

    private fun analyze(ir: ImageReader) {
        val image = try { ir.acquireLatestImage() } catch (_: Throwable) { null } ?: return
        var started = false
        try {
            if (importing.get() || !analyzing.compareAndSet(false, true)) return
            started = true
            val plane = image.planes[0]
            val buf = plane.buffer
            val bytes = ByteArray(buf.remaining())
            buf.get(bytes)
            val n = frameCount++
            val raw = QrBitmap.decodeYuv(bytes, image.width, image.height, plane.rowStride, tryInverted = n % 4 == 0)
                ?: return
            if (raw == lastBad && SystemClock.elapsedRealtime() - lastBadAt < COOLDOWN_MS) return
            handleScannedText(raw)
        } catch (_: Throwable) {
            // A bad frame is only dropped.
        } finally {
            image.close()
            if (started) analyzing.set(false)
        }
    }

    // ---- Import ----

    private fun handleScannedText(raw: String) {
        if (!importing.compareAndSet(false, true)) return
        runOnUiThread {
            errorView.visibility = View.GONE
            hint.setText(R.string.qr_importing)
        }
        thread {
            try {
                val res = ProfileImporter.importQr(this, raw)
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    val msg = try {
                        if (res.count == 1) getString(R.string.qr_imported_one, res.firstName)
                        else getString(R.string.qr_imported_many, res.count)
                    } catch (_: Throwable) {
                        res.firstName
                    }
                    Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
                    setResult(
                        RESULT_OK,
                        Intent().putExtra(EXTRA_IMPORTED_NAME, res.firstName).putExtra(EXTRA_IMPORTED_COUNT, res.count),
                    )
                    finish()
                }
            } catch (e: Throwable) {
                lastBad = raw
                lastBadAt = SystemClock.elapsedRealtime()
                runOnUiThread {
                    importing.set(false)
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    hint.setText(R.string.qr_scan_hint)
                    errorView.text = e.message ?: getString(R.string.qr_image_failed)
                    errorView.visibility = View.VISIBLE
                }
            }
        }
    }

    // ---- Gallery ----

    private fun pickImage() {
        if (importing.get()) return
        try {
            startActivityForResult(
                Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
                    addCategory(Intent.CATEGORY_OPENABLE)
                    type = "image/*"
                },
                REQ_PICK,
            )
        } catch (_: Throwable) {
            try {
                startActivityForResult(Intent(Intent.ACTION_GET_CONTENT).apply { type = "image/*" }, REQ_PICK)
            } catch (_: Throwable) {
                showError(getString(R.string.qr_image_failed))
            }
        }
    }

    private fun showError(text: String) {
        errorView.text = text
        errorView.visibility = View.VISIBLE
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        val uri = data?.data
        if (requestCode != REQ_PICK || resultCode != RESULT_OK || uri == null) return
        if (importing.get()) return
        errorView.visibility = View.GONE
        thread {
            var failed = false
            val raw = try {
                decodeImage(uri)
            } catch (_: Throwable) {
                failed = true
                null
            }
            if (raw != null) {
                handleScannedText(raw)
            } else {
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    showError(getString(if (failed) R.string.qr_image_failed else R.string.qr_not_found_image))
                }
            }
        }
    }

    /** Reads the picture downsampled to at most 1600 px: a 50 MP photo never runs out of memory. */
    private fun decodeImage(uri: Uri): String? {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, bounds) }
        if (bounds.outWidth <= 0 || bounds.outHeight <= 0) throw IllegalStateException("not an image")
        var sample = 1
        while (maxOf(bounds.outWidth, bounds.outHeight) / sample > MAX_IMAGE_SIDE) sample *= 2
        val opts = BitmapFactory.Options().apply { inSampleSize = sample }
        val bmp = contentResolver.openInputStream(uri)?.use { BitmapFactory.decodeStream(it, null, opts) }
            ?: throw IllegalStateException("not an image")
        try {
            return QrBitmap.decodeBitmap(bmp)
        } finally {
            bmp.recycle()
        }
    }
}

