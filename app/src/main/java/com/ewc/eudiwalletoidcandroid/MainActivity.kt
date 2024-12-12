package com.ewc.eudiwalletoidcandroid

import android.Manifest
import android.app.Activity
import android.content.ContentValues.TAG
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.databinding.DataBindingUtil
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.lifecycleScope
import com.ewc.eudi_wallet_oidc_android.models.CredentialOffer
import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import com.ewc.eudi_wallet_oidc_android.services.utils.credentialRevocation.CredentialRevocationUtil
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil
import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.initiateWalletUnitAttestation
//import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.prepareIntegrityTokenProvider
//import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.requestIntegrityToken
//import com.ewc.eudi_wallet_oidc_android.services.utils.walletUnitAttestation.WalletAttestationUtil.sendWUARequest
import com.ewc.eudiwalletoidcandroid.databinding.ActivityMainBinding
import io.igrant.qrcode_scanner_android.qrcode.utils.QRScanner
import kotlinx.coroutines.launch

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
        // Call the suspend function inside a coroutine scope
        lifecycleScope.launch {
            initiateWalletUnitAttestation(applicationContext, 872246932852) // Pass appropriate context and project number
        }
        initClicks()
    }

    private fun initClicks() {

        // Example usage of tokenProvider in button click
//        binding.someButton.setOnClickListener {
//            tokenProvider?.let { provider ->
//                WalletAttestationUtil.requestIntegrityToken(
//                    tokenProvider = provider,
//                    requestHash = "your_action_hash_here",
//                    onSuccess = { token ->
//                        println("Received Integrity Token: $token")
//                        // Send token to the server for verification
//                    },
//                    onError = { error ->
//                        println("Error requesting integrity token: ${error.localizedMessage}")
//                    }
//                )
//            } ?: run {
//                println("Token provider is not initialized yet.")
//            }
//        }

//        binding.btnCreateDID.setOnClickListener {
//            viewModel?.subJwk = DIDService().createJWK()
//            viewModel?.did = DIDService().createDID(viewModel?.subJwk!!)
//
//            viewModel?.displayText?.value = "Sub JWK : \n ${Gson().toJson(viewModel?.subJwk)}\n\n"
//            viewModel?.displayText?.value =
//                "${viewModel?.displayText?.value}Did : ${viewModel?.did}\n\n"
//        }

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
//            if (ContextCompat.checkSelfPermission(
//                    this,
//                    android.Manifest.permission.CAMERA
//                ) != PackageManager.PERMISSION_GRANTED
//            ) {
//                ActivityCompat.requestPermissions(
//                    this,
//                    arrayOf(Manifest.permission.CAMERA),
//                    REQUEST_CODE_SCAN_VERIFY
//                )
//            } else {
//                verifyCredential()
//            }

//            val credentialsList: List<String?> = listOf(
//                "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii1hZzAxSmNJTjBYOGhNWjV6UE8tVG13N1BMUnRuSWpIZW5MSVRRTnlZUzgiLCJ0eXAiOiJKV1QifQ.eyJfc2QiOlsiZ2xXSUxUc0N3ZFZxTElMZ2lEYjRKOGZMcTNsMUFuMlhtQ0liZ0lWR3lRWSIsInFyYmdTcDVZdi11dEgwLUZWU0FOaEJqQkRxS2J6ek9JdGwxNThENUNNNlkiLCJ2SU5JODBGbXZHN1JMZERJOGNIZk84dERyWElXOGptOEdUQlRFcnF0SjZzIiwiMUwyNENxbzBEZGgwbUM3SnM0UWwzTlFCRTBpYkR0dHFWdDdta3MxaS05SSIsImJIY1lacjFyQ011SW0yVEtoZ1laaTViX3M1c0VaRnFnZHJjTG5NeFpzLUUiLCJHYnBHcmNWRGVYeW00NDhzcmRVYkFhMXpNTUlZMHN6SXg1YzhLWGY3eTlJIiwidURLLVp3dHRrallWeXFyMDVHYmZpdV9EelEzZkVLZVF3Q0ZmeDdfME1ROCJdLCJleHAiOjE3MzU0NTYzODQsImlhdCI6MTczMjg2NDM4NCwiaXNzIjoiaHR0cHM6Ly9zdGFnaW5nLW9pZDR2Yy5pZ3JhbnQuaW8vb3JnYW5pc2F0aW9uLzMwZTMyMTk5LTZhYjMtNDU0My05OWUwLTg5ZDNhNGRiNTZiZS9zZXJ2aWNlIiwianRpIjoidXJuOmRpZDpjYzIyMGI2Ni0zYmJhLTQ3MjQtOGVlMC00Y2NlN2ZkNmFkNDgiLCJuYmYiOjE3MzI4NjQzODQsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJpZHgiOjEyNjIsInVyaSI6Imh0dHBzOi8vc3RhZ2luZy1vaWQ0dmMuaWdyYW50LmlvL29yZ2FuaXNhdGlvbi8zMGUzMjE5OS02YWIzLTQ1NDMtOTllMC04OWQzYTRkYjU2YmUvc2VydmljZS9yZXZvY2F0aW9uLXN0YXR1c2xpc3RzLzJiZGI2YjhlLTJkZTctNDRkNi1iNzY0LWZmZmRiZDA0NDZkMiJ9fSwic3ViIjoiZGlkOmtleTp6MmRtekQ4MWNnUHg4VmtpN0pidXVNbUZZcldQZ1lveXR5a1VaM2V5cWh0MWo5S2Jud0dQU2o0TlIzTnJEdUV2RnBBZGhMYU5LMXQ4U0pveDdtc1dUNlhHZHhGaDFSNUNFWXpFbWZOUkxVQnZSNzVqUm9IZEtCdlBTa0ZIaXd0bjFjaHN5ZG1UekQ1UUZuWkd1eUFHV3d0ZHNCUGk5eEpSeXJaakZqVnlKNVdSNVZ5ZzNFIiwidmN0IjoiQ2VydGlmaWNhdGVPZlJlZ2lzdHJhdGlvbiJ9.m-PC86WmEZq7Go6rv8Y_mJFmos8cXvF5TXh_tC3Hu2pnT3LHcyPDvuQAUd9rZhzehksZ3FDRF05UAv3g9fjIFA~WyJhMzFlMzNhZjBhMzIzY2QyMjllMmYxMzg4ZTc5MGExOTcxMTNlZmZlZDdkMDc4M2RiZGNkNjdhZTBjNWVkYjdkIiwiYWN0aXZpdHkiLCJDT1IiXQ~WyI0ZjUzZDU5M2M2NTBmNGM1ODViNWQzYTg3YmJmOWFmYTQ1NWM2NGE4MmIxNWFhYTQ4NzQ2OTY1ZmVlYjY3YTEyIiwibGVnYWxGb3JtIiwibGVnYWwiXQ~WyJmMjE3MDZhMzcwNzg0NDllMzk0YWJkZjYxOWE5YWM5MDBiYWZhMDY0ZWE0NWNkZmU5ZjVhYTNjMmRmNTBlOGY4IiwibGVnYWxTdGF0dXMiLCJhY3RpdmUgbGVnYWwiXQ~WyJjZTQ0ZWQ1MjQyNjEwNmQzZjEwYmU2YWVjZDdiM2NiYzg5MjEzNjk5ZTc5MTdmZTAzYTk3ZmYyYmYxNDVjYjk3IiwibmFtZSIsIkxpam8iXQ~WyIzMjE3ODdlYjZlZjFmZmZlN2RlY2EyZTBkMGM4ZTZkYmRlZmMzYmMxYTI3MjIzYTYyOGY4MmM4NmIzNjhkZGE0Iiwib3JnTnVtYmVyIiwiOSJd~WyJlMzkyOGM3NmE3MDhmNDk5ZDRhN2QxYTI5ODgzZWM0NWUyZWNmMjYyNzhhZTNmZjlhNjdlNTdmNWZhMGYzOTQ1IiwicmVnaXN0ZXJlZEFkZHJlc3MiLHsiYWRtaW5Vbml0TGV2ZWwxIjoiTDIiLCJmdWxsQWRkcmVzcyI6IlBvcnV0aHVyIEhvdXNlLCBQIE8gUGFyYXBwdXIsIFRocmlzc3VyIiwibG9jYXRvckRlc2lnbmF0b3IiOiJEZXZlbG9wZXIiLCJwb3N0Q29kZSI6IjY4MDU1MiIsInBvc3ROYW1lIjoiUGFyYXBwdXIiLCJ0aG9yb3VnaEZhcmUiOiIxMDAwIn1d~WyIxOWNkYzc2NDgyYjRjNGJiZWQ2OWI3MDhlMTE2MzA0NTg2ODYxZmUyM2Q2YjRkYTUxYzZhMzZhYTU0YzIwMzkzIiwicmVnaXN0cmF0aW9uRGF0ZSIsIjA1LTExLTIwMjQiXQ",
//                "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii1hZzAxSmNJTjBYOGhNWjV6UE8tVG13N1BMUnRuSWpIZW5MSVRRTnlZUzgiLCJ0eXAiOiJKV1QifQ.eyJfc2QiOlsiX0tjWGdRLUI0eDh1WU85cHRURkRRUzd5Nk9OX2g1YU1RLXpZQmlCMXhIOCIsIlVFSXRNaXhFcVB0RkhxLXpfQ1ZqSkgyUGp5aE1jMnVYNDM4VDlXdHVpbGMiXSwiZXhwIjoxNzM1NDU2MzQ2LCJpYXQiOjE3MzI4NjQzNDYsImlzcyI6Imh0dHBzOi8vc3RhZ2luZy1vaWQ0dmMuaWdyYW50LmlvL29yZ2FuaXNhdGlvbi8zMGUzMjE5OS02YWIzLTQ1NDMtOTllMC04OWQzYTRkYjU2YmUvc2VydmljZSIsImp0aSI6InVybjpkaWQ6NzViZDljM2QtMDU5MS00NmY5LWI2ZjQtOGRmMzMyM2MwNjdhIiwibmJmIjoxNzMyODY0MzQ2LCJzdGF0dXMiOnsic3RhdHVzX2xpc3QiOnsiaWR4IjoxMjYxLCJ1cmkiOiJodHRwczovL3N0YWdpbmctb2lkNHZjLmlncmFudC5pby9vcmdhbmlzYXRpb24vMzBlMzIxOTktNmFiMy00NTQzLTk5ZTAtODlkM2E0ZGI1NmJlL3NlcnZpY2UvcmV2b2NhdGlvbi1zdGF0dXNsaXN0cy8yYmRiNmI4ZS0yZGU3LTQ0ZDYtYjc2NC1mZmZkYmQwNDQ2ZDIifX0sInN1YiI6ImRpZDprZXk6ejJkbXpEODFjZ1B4OFZraTdKYnV1TW1GWXJXUGdZb3l0eWtVWjNleXFodDFqOUtibndHUFNqNE5SM05yRHVFdkZwQWRoTGFOSzF0OFNKb3g3bXNXVDZYR2R4RmgxUjVDRVl6RW1mTlJMVUJ2Ujc1alJvSGRLQnZQU2tGSGl3dG4xY2hzeWRtVHpENVFGblpHdXlBR1d3dGRzQlBpOXhKUnlyWmpGalZ5SjVXUjVWeWczRSIsInZjdCI6IkxlZ2FsUGVyc29uYWxJZGVudGlmaWNhdGlvbkRhdGEifQ.THxbWNTlPv7iEqcJLywDJP4pW1KFShGl0FoNGU_Atayw41TMzE2g-5RG9jyWzCi_sLGcP-wWjokTYyU3mJhsIg~WyIzNzJjMzYwMTA1MWI1YzJhZTM5MDNhMTk2MDIzZWZjMGUxOTY3NWM1Y2I4NGFhNDY0NDJkYWEwN2JlMTVmODM2IiwiaWRlbnRpZmllciIsInRlc3QiXQ~WyIyNTdjODMxMWI1MGJjNjBmZGI3Y2IyYjkzNTU0YzU2OTU1ZmMxZmY5ODYzZTQ0NTkyZjA4NzhiMzMxMDE5OTE5IiwibGVnYWxOYW1lIiwidGVzdCJd",
//                "eyJhbGciOiJFUzI1NiIsImtpZCI6Ii1hZzAxSmNJTjBYOGhNWjV6UE8tVG13N1BMUnRuSWpIZW5MSVRRTnlZUzgiLCJ0eXAiOiJKV1QifQ.eyJfc2QiOlsiN2VjZE5hcHEydnluei02Wk96QnhiQ2lGZVZrbGd2ZWg4TW5odU84WXZzMCIsIk5OYWZrQ2lpQ1QzbjRqWE9wakFnX2NINEt3VjFWbVM3RzFpV3RaTjRXSTgiLCJqaDdfSFhwd1NSeC1WNnRpZ3hNcnFjQlBkWkdFRHlfOGNMOG1hTm9CYnQ0Iiwid0RNN2tGUTR0T3ZTMHdRZXhpcjNOdUFHTFRsX25peGN2RWtTQzdxa0E4OCIsIm5NdnE0cWxTRzVmd0V3RXQxNmpzajlVM09MQlpSRnVHc0kyTjB0OU5XQkkiLCJqbXVNMW9VZWNTaXNMVGV2NGRpMExWYXpTa1BWWmZUQXJVcHBYeHVzdnowIl0sImV4cCI6MTczNTM2OTg2MSwiaWF0IjoxNzMyODY0MjYxLCJpc3MiOiJodHRwczovL3N0YWdpbmctb2lkNHZjLmlncmFudC5pby9vcmdhbmlzYXRpb24vMzBlMzIxOTktNmFiMy00NTQzLTk5ZTAtODlkM2E0ZGI1NmJlL3NlcnZpY2UiLCJqdGkiOiJ1cm46ZGlkOjFkMjdkODhiLTBmODMtNDQyZi04M2E3LTk2Y2Q3YjE1ZmYzZCIsIm5iZiI6MTczMjg2NDI2MSwic3RhdHVzIjp7InN0YXR1c19saXN0Ijp7ImlkeCI6MTI2MCwidXJpIjoiaHR0cHM6Ly9zdGFnaW5nLW9pZDR2Yy5pZ3JhbnQuaW8vb3JnYW5pc2F0aW9uLzMwZTMyMTk5LTZhYjMtNDU0My05OWUwLTg5ZDNhNGRiNTZiZS9zZXJ2aWNlL3Jldm9jYXRpb24tc3RhdHVzbGlzdHMvMmJkYjZiOGUtMmRlNy00NGQ2LWI3NjQtZmZmZGJkMDQ0NmQyIn19LCJzdWIiOiJkaWQ6a2V5OnoyZG16RDgxY2dQeDhWa2k3SmJ1dU1tRllyV1BnWW95dHlrVVozZXlxaHQxajlLYm53R1BTajROUjNOckR1RXZGcEFkaExhTksxdDhTSm94N21zV1Q2WEdkeEZoMVI1Q0VZekVtZk5STFVCdlI3NWpSb0hkS0J2UFNrRkhpd3RuMWNoc3lkbVR6RDVRRm5aR3V5QUdXd3Rkc0JQaTl4SlJ5clpqRmpWeUo1V1I1VnlnM0UiLCJ2Y3QiOiJQb3J0YWJsZURvY3VtZW50QTEifQ._Q3gLscRNmjSBweh7TLgAFhNNFS1s3lFHdDYLPyGeVDjdVVUfGarqYj15ydEyV63aERHQGFE0WbpzjT1Bl2kmw~WyJhMDJjZTliOWE4YThlM2I1ZWVhYjdkZDQ3NzM2ZGEyMDljM2Q1ZTE3MjU0Nzk5NWM0NjRiZjQzMWQ3YTlhZDhhIiwic2VjdGlvbjEiLHsiZGF0ZUJpcnRoIjoiMDItMDktMTk4OCIsImZvcmVuYW1lcyI6Imxpam8iLCJuYXRpb25hbGl0aWVzIjpbIkluZGlhIiwic3dlZGVuIl0sInBlcnNvbmFsSWRlbnRpZmljYXRpb25OdW1iZXIiOiIxMiIsInBsYWNlQmlydGgiOnsiY291bnRyeUNvZGUiOiJJTiIsInJlZ2lvbiI6IlNvdXRoIiwidG93biI6IlRocmlzc3VyIn0sInNleCI6Ik1hbGUiLCJzdGF0ZU9mUmVzaWRlbmNlQWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IklOIiwicG9zdENvZGUiOiI2ODA1NTIiLCJzdHJlZXRObyI6IjE3IiwidG93biI6IlBhcmFwcHVyIn0sInN0YXRlT2ZTdGF5QWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IklOIiwicG9zdENvZGUiOiI2ODA1NTIiLCJzdHJlZXRObyI6IjE3IiwidG93biI6IlBhcmFwcHVyIn0sInN1cm5hbWUiOiJHZW9yZ2UiLCJzdXJuYW1lQXRCaXJ0aCI6IkFudG9ueSJ9XQ~WyI0NzYyYTg2MmFlNTZkMzhiNGM1YzVjYjlmYzNjNTRkYzA5N2E1MWM2ODBjZTk0MDMyMzlkZmNmMmE0YzgzZTcyIiwic2VjdGlvbjIiLHsiY2VydGlmaWNhdGVGb3JEdXJhdGlvbkFjdGl2aXR5Ijp0cnVlLCJkZXRlcm1pbmF0aW9uUHJvdmlzaW9uYWwiOnRydWUsImVuZGluZ0RhdGUiOiIzMC0wOC0yMDI0IiwibWVtYmVyU3RhdGVXaGljaExlZ2lzbGF0aW9uQXBwbGllcyI6IktlcmFsYSIsInN0YXJ0aW5nRGF0ZSI6IjAxLTA4LTIwMjQiLCJ0cmFuc2l0aW9uUnVsZXNBcHBseUFzRUM4ODMyMDA0Ijp0cnVlfV0~WyI1ZjQ4YWM4OTk3OTcyZWI4Y2EwMzBlY2FlZTM3ODI4OTA3YWUxMjMyZWFlODc4ZDNkMGVjYzFiYTZkNmE2MWI2Iiwic2VjdGlvbjMiLHsiY2l2aWxBbmRFbXBsb3llZFNlbGZFbXBsb3llZCI6dHJ1ZSwiY2l2aWxTZXJ2YW50Ijp0cnVlLCJjb250cmFjdFN0YWZmIjp0cnVlLCJlbXBsb3llZEFuZFNlbGZFbXBsb3llZCI6dHJ1ZSwiZW1wbG95ZWRUd29Pck1vcmVTdGF0ZXMiOnRydWUsImV4Y2VwdGlvbiI6dHJ1ZSwiZXhjZXB0aW9uRGVzY3JpcHRpb24iOiJOb3RoaW5nIHRvIGRlc2NyaWJlIiwiZmxpZ2h0Q3Jld01lbWJlciI6dHJ1ZSwibWFyaW5lciI6dHJ1ZSwicG9zdGVkRW1wbG95ZWRQZXJzb24iOnRydWUsInBvc3RlZFNlbGZFbXBsb3llZFBlcnNvbiI6dHJ1ZSwic2VsZkVtcGxveWVkVHdvT3JNb3JlU3RhdGVzIjp0cnVlLCJ3b3JraW5nSW5TdGF0ZVVuZGVyMjEiOnRydWV9XQ~WyI5MzMwNGMxNDY1NGY1YmI3OGY4Y2RiMWJkMGRhMjhkMThlNzBmZjAyNjg3YzMyYjg3NDk4YWEwMjZlYmJkZWQzIiwic2VjdGlvbjQiLHsiZW1wbG95ZWUiOnRydWUsImVtcGxveWVyU2VsZkVtcGxveWVkQWN0aXZpdHlDb2RlcyI6WyJlMDAxIiwiZTAwMiJdLCJuYW1lQnVzaW5lc3NOYW1lIjoiUGFubyIsInJlZ2lzdGVyZWRBZGRyZXNzIjp7ImNvdW50cnlDb2RlIjoiSU4iLCJwb3N0Q29kZSI6IjY4MDAwMSIsInN0cmVldE5vIjoiMjAiLCJ0b3duIjoiQ2hldm9vciJ9LCJzZWxmRW1wbG95ZWRBY3Rpdml0eSI6dHJ1ZX1d~WyJkZTc5NzllNzM3ZTQ2MWFlNzc0NjQ3OTcyNzhjYTlhZTkwYTQ4MzU2NDIwNzM2MTA1YTljMDQ3MGZhZGUyZjhkIiwic2VjdGlvbjUiLHsibm9GaXhlZEFkZHJlc3MiOmZhbHNlLCJ3b3JrUGxhY2VBZGRyZXNzZXMiOlt7ImFkZHJlc3MiOnsiY291bnRyeUNvZGUiOiJJTiIsInBvc3RDb2RlIjoiNjgwNTUyIiwic3RyZWV0Tm8iOiIxNyIsInRvd24iOiJQYXJhcHB1ciJ9LCJzZXFubyI6MH0seyJhZGRyZXNzIjp7ImNvdW50cnlDb2RlIjoiSU4iLCJwb3N0Q29kZSI6IjY4MDU1MiIsInN0cmVldE5vIjoiMTciLCJ0b3duIjoiUGFyYXBwdXIifSwic2Vxbm8iOjB9XSwid29ya1BsYWNlTmFtZXMiOlt7ImNvbXBhbnlOYW1lVmVzc2VsTmFtZSI6IlBhbm8gd29vZGxpbmVzIiwic2Vxbm8iOjB9LHsiY29tcGFueU5hbWVWZXNzZWxOYW1lIjoid29vZCBBcnRzIiwic2Vxbm8iOjB9XX1d~WyI0YmIzZjQ0YmQ4MDEwZDA1NzgyZTZmNjRkNjA4MTY4Zjk2MDA3YmVlODJiYTA2ZTJiYjMxODhlNWU0ZWQxNTBjIiwic2VjdGlvbjYiLHsiYWRkcmVzcyI6eyJjb3VudHJ5Q29kZSI6IklOIiwicG9zdENvZGUiOiI2ODA1NTIiLCJzdHJlZXRObyI6IjE3IiwidG93biI6IlBhcmFwcHVyIn0sImRhdGUiOiIwMi0wOC0yMDI0IiwiZW1haWwiOiJsaWpvLmdlb3JnZUBpZ3JhbnQuaW8iLCJpbnN0aXR1dGlvbklEIjoiSTAwMTIiLCJuYW1lIjoiU3QuSm9obidzIEhzIiwib2ZmaWNlRmF4Tm8iOiIwNDg3MjI4NzE5MiIsIm9mZmljZVBob25lTm8iOiIwNDg3MjI4NzE5MiIsInNpZ25hdHVyZSI6Imxpam8ifV0"
//            )
//
//            CredentialRevocationUtil().credentialRevocation(credentialsList) { revokedCredentials ->
//                // This callback will be called with the list of revoked credentials
//                if (revokedCredentials.isNotEmpty()) {
//                    // Handle the revoked credentials here
//                    Log.d("RevokedCredentials", "Revoked credentials: $revokedCredentials")
//                } else {
//                    Log.d("RevokedCredentials", "No credentials were revoked.")
//                }
//            }
//            lifecycleScope.launch {
//                CredentialValidator().validateCredential(
//                    jwt = "eyJ4NWMiOlsiTUlJR0JUQ0NBKzJnQXdJQkFnSUlQZnFjNnRveVRNa3dEUVlKS29aSWh2Y05BUUVMQlFBd2diTXhPakE0QmdOVkJBTU1NVWx1ZEdWemFTQkhjbTkxY0NCRlZTQlJkV0ZzYVdacFpXUWdSV3hsWTNSeWIyNXBZeUJUWldGc0lFTkJJRlJsYzNReExqQXNCZ05WQkFzTUpWUmxjM1FnVVhWaGJHbG1hV1ZrSUZSeWRYTjBJRk5sY25acFkyVWdVSEp2ZG1sa1pYSXhIREFhQmdOVkJBb01FMGx1ZEdWemFTQkhjbTkxY0NCVExuQXVRUzR4R2pBWUJnTlZCR0VNRVZaQlZFbFVMVEF5Tnpnd05EZ3dPVFkwTVFzd0NRWURWUVFHRXdKSlZEQWVGdzB5TkRBMk1UQXhORE00TVRsYUZ3MHlOekEyTVRFeE5ETTRNVGxhTUd3eEN6QUpCZ05WQkFZVEFrTklNUmN3RlFZRFZRUmhEQTVXUVZSRFNDMHhNak0wTlRZM09ERVVNQklHQTFVRUNnd0xRMjl0Y0dGdWVTQk1kR1F4RkRBU0JnTlZCQU1NQzBOdmJYQmhibmtnVEhSa01SZ3dGZ1lEVlFRdUV3OVNSVEUyT1RNNU1qa3hNREl5TnpZd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFSMTlaYXFQYkk5L2kwTm5sdzlXd0lwZHBxbXI1eDV4Q2FJZ25mWTZqS0hqWUo2Qm1Jc2xXUFFOaDE3TUN1Q3RQOEdVRVBFRDZldG5Yd1U3NGE0VnBLYm80SUNMRENDQWlnd2V3WUlLd1lCQlFVSEFRRUViekJ0TUVRR0NDc0dBUVVGQnpBQ2hqaG9kSFJ3T2k4dmQzZDNMblJsYzNRMGJXbHVaQzVqYjIwdlNXNTBaWE5wTDNGMVlXeHBabWxsWkhOcFoyNWhkSFZ5WlVOQkxtTmxjakFsQmdnckJnRUZCUWN3QVlZWmFIUjBjRG92TDI5amMzQXVkR1Z6ZERSdGFXNWtMbU52YlRBZEJnTlZIUTRFRmdRVW1yRlFObWRIZ3orNG9CRU9TbEQvbWlDNVUwOHdEQVlEVlIwVEFRSC9CQUl3QURBZkJnTlZIU01FR0RBV2dCVElBdmFVVm5jamxwSnlTKzB0R3hzNCtXM2VDRENCa3dZSUt3WUJCUVVIQVFNRWdZWXdnWU13RlFZSUt3WUJCUVVIQ3dJd0NRWUhCQUNMN0VrQkFqQUlCZ1lFQUk1R0FRRXdDd1lHQkFDT1JnRURBZ0VVTUFnR0JnUUFqa1lCQkRBVEJnWUVBSTVHQVFZd0NRWUhCQUNPUmdFR0FqQTBCZ1lFQUk1R0FRVXdLakFvRmlKb2RIUndjem92TDNkM2R5NXBiblJsYzJsbmNtOTFjQzVqYjIwdlpXNHZkSE53RXdKbGJqQlZCZ05WSFNBRVRqQk1NQWtHQndRQWkreEFBUU13UHdZTUt3WUJCQUdDL2w0QkF3UUJNQzh3TFFZSUt3WUJCUVVIQWdFV0lXaDBkSEE2THk5M2QzY3VhVzUwWlhOcFozSnZkWEF1WTI5dEwyVnVMM1J6Y0RCRUJnTlZIUjhFUFRBN01EbWdONkExaGpOb2RIUndPaTh2WTNKc0xuUmxjM1EwYldsdVpDNWpiMjB2U1c1MFpYTnBMM0YxWVd4cFptbGxaSE5sWVd4RFFTNWpjbXd3RGdZRFZSMFBBUUgvQkFRREFnWkFNQmdHQTFVZEVRUVJNQStDRFdScGNDNXphV053WVM1amIyMHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBRjdEdEFOMHZSaU9xSXUwVDZIblFqL2dHU21ISERtYWgzeE1kZTNtVCtrU1hmV0Nnclk3eE9IN2h1MGFNZXQyV3VybDRSMzJJdmRxVEwzUWloOXdZK3dmT2srWGNlaTRSbDk3ajVPZ24xK25rVWcyc1k4dG1Ia1pUTFd3Mjd0VDQ4TllZTGgrcFROWmxSNnU1ZzZyN0hiMjhsTCtRTlVIb09wb3Y0NXJubkNtbUNpMjVCZExyb2s4bXRkL2t0VS92Wnd1TW1uN2VuS1BVbm5oMm1kbDgyYzB0TlU1eVJJMXZNU3U2b0FOQ1M5OCt5eWMzcEFRbUFmT2VmdTRrQUlkZFpZNEdLYWNJWnhhU3dyUGViQWRqMmtHYkxVNnlpUVdUejlUKzEyaXBvMmtIUDdGVUhvNHhlTWRnaUFQZEhiSHZFR1FPN3luNFZ0b3BHZ29Ya0N6Rld3VmU3czZkNFNVRVJMZjNmeXhyNEhsTEgxTUZwemhuekh4bXJ2SHA3RTZiVTQ3TGI2SHdka1k2ZnNSY05xUUtqbGZ5bmZQQVhSYm94OFpLR3NrOG9sd2xodEhZVE51Q0ZEUU5mZHNOQUJBMHZ3ZkZwVGRGMk9ldXNadzFvbVhIbWhFUXpkRTMwSW5aRW4yUzh1WXNlSEd3SXlFaUpxTDVFOWRnZ1NsbHR4MVZkUlNZcFUrL3YzWVhwOThQZEVjUHd6V3E4bTFuVXFXSU9ZSGFibktWRzNzQ3Q4cUFFWGROY0xaSFM0VmU5WnN0eHBWZUx2OFNldzNuakd1ZzA1d3ordk9pU3ZFdTh1T0dQeGd1WU5wOWlRTy84NUhUSDZ0RHVoWkpxWFNVTVFJNGlpNzRRZUtGRm9ydEszNXM2Z3huRG1US09QdGQzOEdxYTNubVpKUk13UzEiLCJNSUlHS3pDQ0JCT2dBd0lCQWdJSVdWTW15Sk5ubDlJd0RRWUpLb1pJaHZjTkFRRUxCUUF3VGpFb01DWUdBMVVFQXd3ZlNXNTBaWE5wSUVkeWIzVndJRU5zYjNWa0lGSnZiM1FnUTBFZ1ZHVnpkREVWTUJNR0ExVUVDZ3dNU1c1MFpYTnBJRWR5YjNWd01Rc3dDUVlEVlFRR0V3SkpWREFlRncweE56QTNNVGt4TkRFME5ERmFGdzB5TnpBM01Ua3hOREUwTkRGYU1JR3pNVG93T0FZRFZRUUREREZKYm5SbGMya2dSM0p2ZFhBZ1JWVWdVWFZoYkdsbWFXVmtJRVZzWldOMGNtOXVhV01nVTJWaGJDQkRRU0JVWlhOME1TNHdMQVlEVlFRTERDVlVaWE4wSUZGMVlXeHBabWxsWkNCVWNuVnpkQ0JUWlhKMmFXTmxJRkJ5YjNacFpHVnlNUnd3R2dZRFZRUUtEQk5KYm5SbGMya2dSM0p2ZFhBZ1V5NXdMa0V1TVJvd0dBWURWUVJoREJGV1FWUkpWQzB3TWpjNE1EUTRNRGsyTkRFTE1Ba0dBMVVFQmhNQ1NWUXdnZ0lpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElDRHdBd2dnSUtBb0lDQVFDNTJZZnBFQXcrUzNxa0xxS016MzloSzVpcFNiVWlFVDc5SVlSejZ5ZStWRFVQbmVydEtiZkUxTnlhQ2wzVTdWUzNsREd2R2dWcWJQMFI0Wnk3S1o4L011YzVuZld2UFFPQzBHa2taOXVKcXhGa2VDL2t0QUl4d0czS3BPOTBqVTJHSmhvS3MxSmlVZkNKOUdNZUZjMVk0anBJL0k4WHdwc29YNXZtVTYxb0VXd3dPZFd5bm9TSjlRdjVSMkJvWHFETkxpQjI0ck55NlJqbVpYT0ljbnJRZWdESXp4N3MwQW9lZGtxeFpkUkU0MDlwd2VEbEpqWU5iK1pZcG1zcXhJK0ZqcXlwblY1Z0RTOFJtRFZiOG5VdkxNbUg2eVFBbnh6NUFNNGlySEF2Mi83d2daVm5yL0ZXcmlNa0pvWkNxUUxiWTRDb3lSOVR6MlRkbDFMRStsZ2svWlZUcHlTK0VWUVpXdjhaQTdVaVV6d3d6YVFMb0lIbVBsVnNPMnFnMmF5YTVZbmdYMVJiUWsvRU4vUUtWZEV0V2xEYkI5bU9OODZkQ1crc09BZytIUHhsa3pBR28yMnJ3eTM3TDRuMTNTdXpZdEJxSWMwRTBuZExoWlkzdFNSMnZqRTFOS2MveW1pVjA4anlUbkRjYnVLeUtmd0VZNDRLNlBaWWNXeW5SakxIb0VEcENaVWlpYWh3OWgvWjU1cEZaTng3QTJ0Z0lLV0NzQjhFYzNYK1E2VDI0akRzVXZkZStyYmRHN3Uwd082Z2wrYUplYi9BNURVZTAvOHBBUWNZaEFYZ3FFYmFDeTl3YkgzbGlsblQvVzFydVdEMlp0N3l4Qzd3Q3NvSkhHTWF1cks1ZjVjUEVOU2dWcnphNnNMWlFtR2RSbzJNR2kyMldSMmJKcVYrendJREFRQUJvNEdtTUlHak1CMEdBMVVkRGdRV0JCVElBdmFVVm5jamxwSnlTKzB0R3hzNCtXM2VDREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQjhHQTFVZEl3UVlNQmFBRk9tUHhmWmxEbWtEcm84dlNQaUVGc2hsMmRIck1FQUdBMVVkSHdRNU1EY3dOYUF6b0RHR0wyaDBkSEE2THk5amNtd3VkR1Z6ZERSdGFXNWtMbU52YlM5SmJuUmxjMmt2UTJ4dmRXUlNiMjkwUTBFdVkzSnNNQTRHQTFVZER3RUIvd1FFQXdJQkJqQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFTaFdTWGJZMmR6RVlROVh6QWZBRXFRNEluS2xZUEJ3dVVnTmZuUVBKK1NvSTJ2SjgyU2t5YkgrMUNMWThWb3VwM2dSVXIydDVRa0JzMU5WYXpTRVhkajYvdU82TWhrK09udld2eis4T2JNVHNoTTFFR2NyTEgwNDZCTzllaDMwZWZYN0xMYmJCQnhxM2xFbnQ2UG1GNFBMWTFlTlh5dFJENlhLNVZhOUlmZ2lWQkxkVUVrK0lUSVRzSFFDV3paOUY1SjZaM2FQYkhMb1hLazhYS2ZMbVZ6Z0xVOVl0Mk5jNURLR0hPUzNBTFllbjlIclFXcnpNN24xT2N3eXhMejdWTXJIM3B4aUNhbHR6K0hnWnd0dFg4UDgwYitvVnIwME9LZmlHeEVFaitWY0NIaG5Ld2p2UUZNMzQxVWhMaCtXUGhySVlyL2RRZVpwOU1rOTFzb0RYL1c2d1Z1RUJDWWt1anByTi9zVS9rSTFZWW1PcnExbVh3UG83WU4wS3BvMUNnZldGa3c5cXZKc0htL2haSWRlcElaM3hsakdmMS9lc2FFTTFGNnV1WlcrU0ppZnErTzZ5eG5mbTN3QmEwbU9keExBOXFibmxFS3M5a2QwYWZBaW8wMFdvVDJJK01Jc0t3VjFaUHdkSERBcGZ1WTJOTzEwU1ZFbDNSNXg0SlV5WDMrMFlNb0ErdTZEaXB1YldjRlpnM0JnVlZCZUNqc1dPNWZ0WUFIUHFhdWZPZnNpYnNQMEJiUklhazJDUlozbUZYWVNjUTlJMmVpVGlHQzRpWmRjMHdpZklaR2dySFFVUU41K21ZSUs5V04zazlXRVA0YmxuVnVyZ3VLUTlvSHhPTkhGSWNrQVlNNW5ibkMvbUEvTjlVTHM5TlNQK2NzcC81S3d5OC9EdFloYz0iLCJNSUlGZ1RDQ0EybWdBd0lCQWdJSVZMQWprS2ROVjk0d0RRWUpLb1pJaHZjTkFRRUxCUUF3VGpFb01DWUdBMVVFQXd3ZlNXNTBaWE5wSUVkeWIzVndJRU5zYjNWa0lGSnZiM1FnUTBFZ1ZHVnpkREVWTUJNR0ExVUVDZ3dNU1c1MFpYTnBJRWR5YjNWd01Rc3dDUVlEVlFRR0V3SkpWREFlRncweE56QXpNRFl4TmpVNE5UTmFGdzB6TnpBek1ERXhOalU0TlROYU1FNHhLREFtQmdOVkJBTU1IMGx1ZEdWemFTQkhjbTkxY0NCRGJHOTFaQ0JTYjI5MElFTkJJRlJsYzNReEZUQVRCZ05WQkFvTURFbHVkR1Z6YVNCSGNtOTFjREVMTUFrR0ExVUVCaE1DU1ZRd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJS0FvSUNBUUNwZGpCd2l3ZFhRYkRwK2dhREJRclpLSjZkUG9nSFdPS29CbC9QYmJzb0dpZ21QMm5zbyt6b1RuUmt0Si82REZCdnhoVGZ5K3A2TWhrZzNpWDk5Z0VKMHdIeEdBY3ZkZUJmbllQK1ZsaXFENENzV1Foak14VVVSMko5cDJIaWVhTmxSSGpjRklrMWdjSXNGblFmTWxTQTRqUG0wT3NPM2NncHEyQ3FPMmVuNzh0bHpNMUI4empYZHBoNWdSL1hZbUV4OG9veGZxc0N6VE4wZGNGZTlpN0d5cllXVHd5QWd4RlA2aHZocHhhQzFwU2pzQnBUS0ZNdW1GeHIrakx0bzJ6QWRBODU1UFp5UUo2MldyNmlFT2w2OEtJTUdpQW02bkROK3NTNEhkeGRaa2V3WG1SS2EwNGFMcmZxZ1prU2VPdVp5SFBpenQxZ3pnb0pmRDRPWjFYcWNZUmlFS1p4WVVncFRHejJBZDd5b3NjZFdiVGwwK0NPaWh3aHZoZVE2aTBkUG84MXkzYUV6dThHTDFwM1NLY2lGQTFoZFUrNmtEclBIVUVaNVAyT2FjNnMwM25wSFVRbjV4MTZvOFZ0d051L1Z1d1FBVWdnUng0anN6dFErSW5SS0xPYmNWNGdNSDNKaktCaERTWExBY2gyVjViem1GTjl5OHhyYmpwRUh5eTdPTkk2L25rOUVCUHNaanpFc290OTloSitJM082bU1NNEtDQXkwR0QzOWxkTm5oSk1SeVVDRVlzb1l2WUZPSjhxbjJHVFJyMzk1aEpSMng1SGttaHRIRzBCZ3VneG9adVlyOXlzU2ZlVUpuSUxaTEpYRXpTK1lMYUpialB6WWZKdDhaMnl1U25MZ3V0d0hQSk4ybjk4cUZxRjJqSGd3TXhuRFROZ2tTTWlaUUlEQVFBQm8yTXdZVEFkQmdOVkhRNEVGZ1FVNlkvRjltVU9hUU91ank5SStJUVd5R1haMGVzd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZkJnTlZIU01FR0RBV2dCVHBqOFgyWlE1cEE2NlBMMGo0aEJiSVpkblI2ekFPQmdOVkhROEJBZjhFQkFNQ0FRWXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBRkN3NGFpK1Nzc2pWNTJpUUVONElTbDR4c3A0Q2g2Vy9jdkIvTlh3RHNLSDJPaVE3bjFZVXk1RnRIUytxRlBYVituWmNZMmtFNmlQM2EzdG8wWG1Cd0hkeDd4RzM0Rjc2RnNqK1grVlN0ZXllTFFnTmRrcGd2NDU0SVF1Sk5rYjVJZGUyT2lWOVk1SHNoTGJTeVBzZDAwektnY3RGUlFjTCtVTTJYdS9pQld5L3k4VkluT2FHNlNmamJNZzR0Sk8zV2RnUXJhdXVhVnkyYnVxdmpRWFE1YXdQWHhFblRxajV2OHY2dVk4Zkd1eEczR21pZ1djeGRBU0tTL2FaWkZ6aVFVQUNNcnB2M2YwVjJ2aVVSUE1zN0N3Zzd1aXRBZU8rMHhRc01XL1BNNTQ1NWxjMFZpOTdiM1NyQzE1L3ZNOFFxSDI1YXB4Q25sV1hmbWJmaStCdzgyUCtiVnMrczQvbXFJUTQyZW9mSldUWUM3NWdQNU1HaHpHOW5ZTXpTRFRHMlF3cVdDNk4xbGMrSiszVW9UWVpmT3lUMWdtVzNvQXhCSnp4Skc2a0tJYWErUDZmWWNvYnlIa3d0UzNpOHI1R2ZqK1BHbzB0bUhVL0ltTmpvVTQxNGE1L2twUVJIeDdnU3psLy9oVjU5YXE5dGNNZ09mMDZxTUlqa2toT2RDbVArbzJnbGc0ZkE2UWhvNEYxUHVTRUk3b0s0MitXUzR1dnN0SlM2c3lEQnRWUTI2NlE4bU40cUpSd1FQOGJIbVJMSjlqRDhMbHZDd05LV2cwNHY4YzVMTGJYR09pNTRBWEVNa04rMHpXa0RtNkloSzQ0eGhMYkJJUmRIaVNjVjdQUnltUGZqTFdmWVlaWXh0bUNPUGJ6NXJ6dk1qWS9ZbVJ5TTh2RHpQTHQzb20iXSwidHlwIjoidmMrc2Qtand0IiwiYWxnIjoiRVMyNTYifQ.eyJpc28yMzIyMCI6eyJfc2QiOlsiM01vY1M3ZTNMU2I2OC0wVFlNZ3BndFVST2FuU3ZjQmg0YlowRXFkNk9NRSIsIkJCN2xRblBOSkJubVdzcGVPMHR5ekt5ZmZUMXMwZVdlTkVGWE1JNmhDbEEiLCJGMjlHM0lmaXJvNVNJdVh3THNFNzJ4d3NLT1lqNElwa3ZXTnVlc0hLdkV3IiwiRm5faDN5T2NINXg5MHI0R1hXQm45ejRtenRhV2JiODQ3NTY4V1huZHo5SSIsIkxsNTNJWHhZV2tRSEJIN2ZINEctNHpuakFDWXhfdXRqdWM5MlNQQXUzN00iLCJPTmJNMndQQVktaklnUy0wZ2dwNEk0aG55V3pFSjdNV2VCS3dGSnJJTmhJIiwiZFc1NzlnM19ZX0ZDMmVSQzBuNjYxVmZ0eDJuWXgzbVYxTWs1eVBqdTdtOCIsInl5TGhmNTZZZjZTSVQ2MlVlcjFKOTg1blZGVkdQLXJSR08yS1BEbzU3STAiLCJ6dkpucXBrNFctUDZXUWlYdVFFY0JNOVVUSUdGOWFWaDhIbXFhZ1hWaWE4Il19LCJkdGMiOnsiX3NkIjpbIkU3VmVrNjlfR1NQVm00UFplellDUnNYdzRPbS1NU1VtekxabllKZ3doUzAiLCJXNkQxZjlOd2JENGZ4aGhSbXo4X2xmTFk3YkxjRWdaTDkxVFI4Q3dpQXl3IiwiV3FOR1p4WXAybDBLREtiUmV1U2JEeXlFa213WVN0Y3lmWEZJaEJqNUJBVSIsImstd1RYM1B0dWw2b21xWE51WktkRGpsZDduTEpMcDlxOFlBazAzWjRyeGsiLCJ6WGpUSmprMXg2YzMxWjZIdWRWZE1RcFNHTUh3cW5PVVVfVEdzSkJDZl84Il19LCJ2Y3QiOiJld2MtcGhvdG9pZCIsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiaHR0cHM6Ly9kaXAuc2ljcGEuY29tIiwicGhvdG9pZCI6eyJfc2QiOlsiMno0RElxWFBMaXdnN2ZMT0FLMHNIWXpOVkg5YnZmaFlQdHBIcXI3ejBfOCIsIjhFM25rcWtxdF9aQzhTZkgxQjRidWdnTzNwM1BjaGNSeTJUNzduWFBZUE0iLCJEeG1paHg3Y2hfWmFwam43TzBEd0JaM3dzU3Z1bVNIS3FPTzBja3k4Qm9VIiwiUW10RmFyajJvaXg2LVFtbGs3WnpZbVVLVTNjRlI4M2tEWXJFUU5RWGJsYyIsIlktRVZRUGRvTFk2YU1jalNtbl9pWGlsbG53dU1rc2pYV1NVbXVaRVdpRjQiLCJhaTdnWWFoamNMa0luSHR0TWJvbUlMVGZJR2JPQ0JsX25JOE9UaXkxdEFFIiwiakh6T0tCZHQyS1dQdm4yZ0JxTHJfUVVZVkhjZVpuM3dsblFzaXhYSzFTSSIsInIyMlVRWG1tdkhTRzFlelZsZGRTZl9RVjN3WTl3NmdBM1FjcVFFeW5tOXMiLCJ6dkJCZzdyVDE1dTVLQ1RxNU5sWmZOMEVWSFJzRVlsSTZ0SUpGaHVqcmV3Il19LCJpYXQiOjE3MzI4NTkxMTJ9.kLyg0NoujXiNZs0LAcNU9UtS1ORFS8YjayisyWfKTYnVPhodjTBH_4U_pW8VUmJFZ1GXmW8JMkYcSTc3spdw0w~WyI1OE5kRzROTFZSLW5KMGRDQXd1QXNBIiwiZHRjX2RnMSIsIlA8VVNBSk9ITjw8U01JVEg8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDw8PDEyMzQ1Njc4OVVTQTg1MDQyM00zMDAxMTU4VVNBMTIzNDU2Nzg5Nzw8PDw8PDw8PDw8PDw8MDQiXQ~WyJIeVNzeFdPSEdSTWNfaWdYeGUtSkZnIiwiZHRjX2RnMiIsImlWQk9SdzBLR2dvQUFBQU5TVWhFVWdBQUFCUUFBQUFCQ0FZQUFBQXAyTVBwQUFBQUZFbEVRVlI0Mm1KODl1N2RId0FFdndNNUdnTm1PUUFBQUFCSlJVNUVya0pnZ2c9PSJd~WyJ2M3FVR3Bob0sxZ2I5VGVMbnV4ZzB3IiwiZHRjX2RnMyIsImR0Y19kZzNfZGF0YSJd~WyJmZ1EyYnUySVY1ZS1UUDdQSmhOVmJnIiwiZHRjX3ZlcnNpb24iLCIxLjAiXQ~WyJCZGRQVUhrbmdiRmNRSV9XVWdyd013IiwiZGdfY29udGVudF9pbmZvIiwiZGdfY29udGVudF9pbmZvIl0~WyJEOVdyR2gtSmIxc2RjNTVWVU5MRVh3IiwicGVyc29uX2lkIiwiMTIzNDU2Nzg5Il0~WyI1cFNmcXdZM2NhVndfNE1pWWNLWkxRIiwiYmlydGhfY2l0eSIsIkxvcyBBbmdlbGVzIl0~WyJQUDRDX1FxNW96X1Z6S1ZjUXRvQi13IiwiYmlydGhfc3RhdGUiLCJDYWxpZm9ybmlhIl0~WyJPREZUY08zaXRUWXdnaXNLb2xaOUZRIiwiYmlydGhfY291bnRyeSIsIlVTQSJd~WyIyRk5CQUtQdnFBMjd0VGM4S0FxMVpRIiwicmVzaWRlbnRfc3RhdGUiLCJDYWxpZm9ybmlhIl0~WyI0RWlsLTNzMlV6OENEQkFKMl9mRk5RIiwicmVzaWRlbnRfc3RyZWV0IiwiMTIzIE1haW4gU3RyZWV0Il0~WyJhY0FXRk1MNmQxQ1Z0cHJIcGxxS0pRIiwiYWRtaW5pc3RyYXRpdmVfbnVtYmVyIiwiOTg3NjU0MzIxIl0~WyIwQTJ1LXozd0F5V2tMaUdoemdqeUJ3IiwicmVzaWRlbnRfaG91c2VfbnVtYmVyIiwiNDVCIl0~WyJJdloxeE1tNHRGeXBBX3RvR0tCbml3IiwidHJhdmVsX2RvY3VtZW50X251bWJlciIsIlgxMjM0NTY3ODkiXQ~WyJJZUJrcE9vMWVKcGlpeXJralljWGhnIiwicG9ydHJhaXQiLCJpVkJPUncwS0dnb0FBQUFOU1VoRVVnQUFBQlFBQUFBQkNBWUFBQUFwMk1QcEFBQUFGRWxFUVZSNDJtSjg5dTdkSHdBRXZ3TTVHZ05tT1FBQUFBQkpSVTVFcmtKZ2dnPT0iXQ~WyJ4cVA5MzF5R0JHdHJKNjFrb01udXBBIiwiYmlydGhfZGF0ZSIsIjE5ODUtMDQtMjMiXQ~WyJoNzdHSjR2QjIyV0FWcXFOQ0dtaGpRIiwiaXNzdWVfZGF0ZSIsIjIwMjAtMDEtMTUiXQ~WyJzaVBPUFpVS0RrNHBvSWNaczY1T1JnIiwiYWdlX292ZXJfMTgiLHRydWVd~WyI2a2pRQ3JNOV9PWVNkTmtyWkQzbjN3IiwiZXhwaXJ5X2RhdGUiLCIyMDMwLTAxLTE1Il0~WyJxVndzblpzYTNQTGZVdm1hdjR1cGdRIiwiaXNzdWluZ19jb3VudHJ5IiwiVVNBIl0~WyJFRVI3Umk1bDlpQjNUUFh6eXlKM2tBIiwiZ2l2ZW5fbmFtZV91bmljb2RlIiwiSm9obiJd~WyItQWZzTXRCMFVtRkRWY0U3azRCOTB3IiwiZmFtaWx5X25hbWVfdW5pY29kZSIsIlNtaXRoIl0~WyJBN0VnZmI2QktNeUdyZTBiWXc2V0tRIiwiaXNzdWluZ19hdXRob3JpdHlfdW5pY29kZSIsIlVTIERlcGFydG1lbnQgb2YgU3RhdGUiXQ~",
//                    jwksUri = null,
//                    format = null
//
//                )
//
//            }

//            val uri = Uri.parse("openid://?state=3bc35d6f-cf1a-465a-84d3-b2fd854cf2b5&client_id=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock&redirect_uri=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock%2Fid_token_response&response_type=id_token&response_mode=direct_post&scope=openid&nonce=ccb2d567-fb0d-4f7d-a693-d9170bb10767&request_uri=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv3%2Fauth-mock%2Frequest_uri%2F51e96f6a-fa3b-45ae-8272-6cc4e2b162ca")
//            // Extract 'state', 'redirect_uri', and 'nonce' parameters
//            val state = uri.getQueryParameter("state")
//            val redirectUri = uri.getQueryParameter("redirect_uri")
//            val responseType = uri.getQueryParameter("response_type")
//            val nonce = uri.getQueryParameter("nonce")
//
//            val presentationRequest = com.ewc.eudi_wallet_oidc_android.models.PresentationRequest(
//                clientId = "https://api-conformance.ebsi.eu/conformance/v3/auth-mock",
//                redirectUri = redirectUri,
//                responseType = responseType,
//                state = state,
//                nonce = nonce
//            )
//            lifecycleScope.launch {
//                // Create the JSON object from the string representation of the subJwk
//                val subJwkJson = """
//        {
//            "kty": "EC",
//            "d": "SxVz9iyS8aC-geU1JGBpoMVmrw_IontkEJkFfLs-bc4",
//            "crv": "P-256",
//            "x": "E7wCIFcda0xYi26bZiKEN2bc9C6bqlSaJ_1mLOAF6Gw",
//            "y": "vNna20TXusMJjSU62exZU5tEJUiF5YpFi38OV2Vgnm0"
//        }
//    """
//
//                // Convert to a JWK (ECKey in this case)
//                val jwk: JWK = ECKey.parse(subJwkJson)
//                val  response = VerificationService().processAndSendAuthorisationResponse(
//                    subJwk = jwk ,
//                    presentationRequest = presentationRequest,
//                    did ="did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9Kbp27QAiYJHhk7kQwVBk6KJjnrPpDbxcqCUWgH7sDntGDDAs1Upa2woyCvGvU5sRfL4Ec6SgN4wJNgxo5HJzX4mKZNZTQUdPkVLyxFxV1LqP7RNATz9ZFnMobZuoLiWpCsqE" ,
//                )
//                if (response?.errorResponse != null){
//                    println(response.errorResponse?.errorDescription)
//
//                }
//                else{
//                    println(response?.vpTokenResponse?.location)
//                }
//            }
            lifecycleScope.launch {
                val res=     IssueService().resolveCredentialOffer("openid-credential-offer://?credential_offer_uri=https://staging-oid4vc.igrant.io/organisation/4264f05a-e0cd-49cb-bb32-b664e1d0f448/service/credential-offer/b86504a6-13e5-4274-b826-76d01674029f")

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

                    viewModel?.issueCredential(url ?: "",this)
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