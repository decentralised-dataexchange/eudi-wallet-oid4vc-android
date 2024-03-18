package com.ewc.eudiwalletoidcandroid

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudiwalletoidcandroid.databinding.ActivityMainBinding
import io.igrant.qrcode_scanner_android.qrcode.utils.QRScanner

class MainActivity : AppCompatActivity() {

    companion object {
        const val REQUEST_CODE_SCAN_ISSUE = 101
        const val REQUEST_CODE_SCAN_VERIFY = 102
    }

    private var viewModel: MainViewModel? = null
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding =
            DataBindingUtil.setContentView(this, R.layout.activity_main)

        viewModel = ViewModelProvider(this)[MainViewModel::class.java]
        binding.viewModel = viewModel
        binding.lifecycleOwner = this
        viewModel?.subJwk = DIDService().createJWK()
        viewModel?.did = DIDService().createDID(viewModel?.subJwk!!)

        initClicks()
    }

    private fun initClicks() {
        binding.addCredential.setOnClickListener {
            binding.tvCredential.text = ""
            QRScanner().withLocale("en").start(
                this,
                REQUEST_CODE_SCAN_ISSUE
            )
        }

        binding.verifyCredential.setOnClickListener {
            QRScanner().withLocale("en").start(
                this,
                REQUEST_CODE_SCAN_VERIFY
            )
        }

        binding.verifyPin.setOnClickListener {
            if (binding.etPin.text.length == 4) {
                viewModel?.verifyPin(binding.etPin.text.toString())

                binding.etPin.visibility = View.GONE
                binding.verifyPin.visibility = View.GONE
                binding.etPin.text.clear()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode == Activity.RESULT_OK) {
            when (requestCode) {
                REQUEST_CODE_SCAN_ISSUE -> {
                    if (data == null) return

                    val url = try {
                        data.getStringExtra("com.blikoon.qrcodescanner.got_qr_scan_relult")
                    } catch (e: Exception) {
                        ""
                    }

                    viewModel?.issueCredential(url ?: "")
                }

                REQUEST_CODE_SCAN_VERIFY -> {
                    if (data == null) return

                    val url = try {
                        data.getStringExtra("com.blikoon.qrcodescanner.got_qr_scan_relult")
                    } catch (e: Exception) {
                        ""
                    }

                    viewModel?.verifyCredential(url ?: "")
                }
            }
        }
    }

}