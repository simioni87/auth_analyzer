package com.protect7.authanalyzer.entities;

import com.protect7.authanalyzer.util.BypassConstants;

import burp.IHttpRequestResponse;

public class AnalyzerRequestResponse {

	private final IHttpRequestResponse requestResponse;
	private final BypassConstants status;

	public AnalyzerRequestResponse(IHttpRequestResponse requestResponse, BypassConstants status) {
		this.requestResponse = requestResponse;
		this.status = status;
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}

	public BypassConstants getStatus() {
		return status;
	}
}
