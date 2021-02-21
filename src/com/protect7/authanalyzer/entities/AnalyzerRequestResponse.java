package com.protect7.authanalyzer.entities;

/**
 * This Entity holds a HTTP Message created by the RequestController. (A repeated request with modified content)
 * 
 * @author Simon Reinhart
 */


import com.protect7.authanalyzer.util.BypassConstants;

import burp.IHttpRequestResponse;

public class AnalyzerRequestResponse {

	private final IHttpRequestResponse requestResponse;
	private final BypassConstants status;
	private final String infoText;
	private final int statusCode;
	private final int responseContentLength;

	public AnalyzerRequestResponse(IHttpRequestResponse requestResponse, BypassConstants status, String infoText,
			int statusCode, int responseContentLength) {
		this.requestResponse = requestResponse;
		this.status = status;
		this.infoText = infoText;
		this.statusCode = statusCode;
		this.responseContentLength = responseContentLength;
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}

	public BypassConstants getStatus() {
		return status;
	}

	public String getInfoText() {
		return infoText;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public int getResponseContentLength() {
		return responseContentLength;
	}
}
