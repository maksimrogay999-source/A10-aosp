package com.android.emulA10

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.util.AttributeSet
import android.view.SurfaceHolder
import android.view.SurfaceView

class EmulatorSurfaceView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : SurfaceView(context, attrs, defStyleAttr), SurfaceHolder.Callback {

    private var isRunning = false

    init {
        holder.addCallback(this)
    }

    override fun surfaceCreated(holder: SurfaceHolder) {
        // Поверхность создана
    }

    override fun surfaceChanged(holder: SurfaceHolder, format: Int, width: Int, height: Int) {
        // Поверхность изменена
    }

    override fun surfaceDestroyed(holder: SurfaceHolder) {
        // Поверхность уничтожена
    }

    fun startRendering() {
        isRunning = true
        val canvas = holder.lockCanvas()
        canvas?.drawColor(Color.BLACK)
        holder.unlockCanvasAndPost(canvas)
    }

    fun stopRendering() {
        isRunning = false
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        if (isRunning) {
            // Отрисовка гостевой системы
            canvas.drawColor(Color.BLACK)
        }
    }
}