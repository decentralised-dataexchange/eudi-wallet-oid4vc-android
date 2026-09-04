package com.ewc.eudiwalletoidcandroid

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.ewc.eudi_wallet_oidc_android.logging.Logger
import com.ewc.eudiwalletoidcandroid.databinding.ActivityMainBinding
import io.igrant.qrcode_scanner_android.qrcode.utils.QRScanner

/**
 * A test harness for the issuance SDK, one function per button.
 *
 * Scan a credential offer, then run each step on its own and read what the SDK actually did.
 * Nothing runs implicitly, so a failing step can be repeated without redoing the ones before it.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private lateinit var viewModel: MainViewModel

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // The harness exists to show what the SDK is doing, so its logging is on here. A library is
        // silent until the host asks; a wallet would not turn this on in release.
        Logger.configure(
            level = Logger.Level.DEBUG,
            // BODY, not HEADERS: the point of the harness is to see the request that went out.
            networkLevel = Logger.NetworkLevel.BODY,
        )

        binding = DataBindingUtil.setContentView(this, R.layout.activity_main)
        viewModel = ViewModelProvider(this)[MainViewModel::class.java]
        binding.viewModel = viewModel
        binding.lifecycleOwner = this

        // Seedable and runnable from the command line, so a flow can be driven without a camera or
        // a single tap:
        //   adb shell am start -n <pkg>/.MainActivity \
        //     --es offer "openid-credential-offer://..." --ez autorun true
        intent?.getStringExtra("offer")?.takeIf { it.isNotBlank() }?.let { offer ->
            viewModel.onScanned(offer)
            if (intent.getBooleanExtra("autorun", false)) viewModel.runAll()
        }

        binding.btnScan.setOnClickListener { scan() }
        binding.btnResolveOffer.setOnClickListener { viewModel.resolveOffer() }
        binding.btnIssuerMetadata.setOnClickListener { viewModel.discoverIssuer() }
        binding.btnAuthServer.setOnClickListener { viewModel.discoverAuthServer() }
        binding.btnAuthorization.setOnClickListener { viewModel.requestAuthorization() }
        binding.btnToken.setOnClickListener { viewModel.requestToken() }
        binding.btnRunAll.setOnClickListener { viewModel.runAll() }
        binding.btnClear.setOnClickListener { viewModel.clear() }
    }

    private fun scan() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA)
            != PackageManager.PERMISSION_GRANTED
        ) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.CAMERA), REQUEST_CODE_SCAN)
            return
        }
        QRScanner().withLocale("en").start(this, REQUEST_CODE_SCAN)
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode != REQUEST_CODE_SCAN) return

        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            scan()
        } else {
            Toast.makeText(this, R.string.harness_camera_permission, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode != REQUEST_CODE_SCAN || resultCode != Activity.RESULT_OK || data == null) return

        val scanned = try {
            data.getStringExtra(QR_RESULT_EXTRA)
        } catch (e: Exception) {
            null
        }
        if (scanned.isNullOrBlank()) {
            Toast.makeText(this, R.string.harness_scan_empty, Toast.LENGTH_SHORT).show()
            return
        }
        viewModel.onScanned(scanned)
    }

    private companion object {
        const val REQUEST_CODE_SCAN = 101

        /** The scanner library's result extra; the misspelling is the library's, not ours. */
        const val QR_RESULT_EXTRA = "com.blikoon.qrcodescanner.got_qr_scan_relult"
    }
}
