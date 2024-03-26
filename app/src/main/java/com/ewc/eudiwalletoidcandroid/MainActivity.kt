package com.ewc.eudiwalletoidcandroid

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import com.ewc.eudi_wallet_oidc_android.services.did.DIDService
import com.ewc.eudiwalletoidcandroid.databinding.ActivityMainBinding
import com.google.gson.Gson
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

        initClicks()
    }

    private fun initClicks() {
        binding.btnCreateDID.setOnClickListener {
            viewModel?.subJwk = DIDService().createJWK()
            viewModel?.did = DIDService().createDID(viewModel?.subJwk!!)

            viewModel?.displayText?.value = "Sub JWK : \n ${Gson().toJson(viewModel?.subJwk)}\n\n"
            viewModel?.displayText?.value =
                "${viewModel?.displayText?.value}Did : ${viewModel?.did}\n\n"
        }

        binding.addCredential.setOnClickListener {
            if (ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.CAMERA
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.CAMERA),
                    REQUEST_CODE_SCAN_ISSUE
                )
            } else {
                issueCredential()
            }
        }

        binding.verifyCredential.setOnClickListener {
            if (ContextCompat.checkSelfPermission(
                    this,
                    android.Manifest.permission.CAMERA
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.CAMERA),
                    REQUEST_CODE_SCAN_VERIFY
                )
            } else {
                verifyCredential()
            }

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

    private fun issueCredential() {
        binding.tvCredential.text = ""
        QRScanner().withLocale("en").start(
            this,
            REQUEST_CODE_SCAN_ISSUE
        )
    }

    private fun verifyCredential() {
        QRScanner().withLocale("en").start(
            this,
            REQUEST_CODE_SCAN_VERIFY
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)

        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            when (requestCode) {
                REQUEST_CODE_SCAN_VERIFY -> {
                    verifyCredential()
                }

                REQUEST_CODE_SCAN_ISSUE -> {
                    issueCredential()
                }
            }
        } else {
            Toast.makeText(
                this,
                "Please give permission for camera to continue",
                Toast.LENGTH_SHORT
            )
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

                    viewModel?.displayText?.value =
                        "${viewModel?.displayText?.value}Scanned data : $url\n\n"

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