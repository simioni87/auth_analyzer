package com.protect7.authanalyzer.entities;

import burp.IHttpRequestResponse;

public class OriginalRequestResponse {
	
	private final int id;
	private final IHttpRequestResponse requestResponse;
	private final String method;
	private final String host;
	private final String url;
	private final String infoText;
	private boolean marked = false;
	
	public OriginalRequestResponse(int id, IHttpRequestResponse requestResponse, String method,
			String url, String infoText) {
		this.id = id;
		this.requestResponse = requestResponse;
		this.method = method;
		this.host = requestResponse.getHttpService().getHost();
		this.url = url;
		this.infoText = infoText;
	}
	public String getEndpoint() {
		return method + host + url;
	}
	public int getId() {
		return id;
	}
	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}
	public String getMethod() {
		return method;
	}
	public String getHost() {
		return host;
	}
	public String getUrl() {
		return url;
	}
	public boolean isMarked() {
		return marked;
	}
	public void setMarked(boolean marked) {
		this.marked = marked;
	}
	public String getInfoText() {
		return infoText;
	}	
}
