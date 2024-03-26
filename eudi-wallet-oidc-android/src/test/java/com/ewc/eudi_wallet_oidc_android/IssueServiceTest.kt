package com.ewc.eudi_wallet_oidc_android

import com.ewc.eudi_wallet_oidc_android.services.issue.IssueService
import junit.framework.TestCase
import org.junit.Assert
import org.junit.Test

class IssueServiceTest {

    private val issueService = IssueService()

    @Test
    fun errorIsNull() {
        val errResponse = null
        Assert.assertNull(issueService.processError(errResponse))
    }

    @Test
    fun errorIsIssuerDoesNotMatchClientId() {
        val errResponse = "Invalid Proof JWT: iss doesn't match the expected client_id"
        val processedError  = issueService.processError(errResponse)
        Assert.assertEquals(1, processedError?.error)
    }

    @Test
    fun errorIsIssuerDoesMatchClientId() {
        val errResponse = "Invalid Proof JWT"
        val processedError  = issueService.processError(errResponse)
        Assert.assertNull(processedError?.error)
    }

    @Test
    fun errorIsJsonObjectWithErrorDescription() {
        val errorMessage = "Invalid Client ID"
        val errResponse = "{\"error\":\"Token request failed\",\"error_description\":\"$errorMessage\"}"
        val processedError  = issueService.processError(errResponse)
        Assert.assertEquals(-1, processedError?.error)
        Assert.assertEquals(errorMessage, processedError?.errorDescription)
    }

    @Test
    fun errorIsJsonObjectWithError() {
        val errorMessage = "Invalid Client ID"
        val errResponse = "{\"error\":\"$errorMessage\"}"
        val processedError = issueService.processError(errResponse)
        Assert.assertEquals(-1, processedError?.error)
        Assert.assertEquals(errorMessage, processedError?.errorDescription)
    }
}
