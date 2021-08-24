package com.protect7.authanalyzer.entities;

import burp.IHttpRequestResponse;

public class OriginalRequestResponse implements Comparable<OriginalRequestResponse>{
	
	private final int id;
	private final IHttpRequestResponse requestResponse;
	private final String method;
	private final String host;
	private final String url;
	private final String infoText;
	private String comment = "";
	private final int statusCode;
	private final int responseContentLength;
	private boolean marked = false;
	
	public OriginalRequestResponse(int id, IHttpRequestResponse requestResponse, String method,
			String url, String infoText, int statusCode, int responseContentLength) {
		this.id = id;
		this.requestResponse = requestResponse;
		this.method = method;
		this.host = requestResponse.getHttpService().getHost();
		this.url = url;
		this.infoText = infoText;
		this.statusCode = statusCode;
		this.responseContentLength = responseContentLength;
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
	@Override
	public int compareTo(OriginalRequestResponse o) {
		Integer id = this.getId();
		return id.compareTo(o.getId());
	}
	public int getStatusCode() {
		return statusCode;
	}
	public int getResponseContentLength() {
		return responseContentLength;
	}
	public void setComment(String comment) {
		this.comment = comment;
	}
	public String getComment() {
		return comment;
	}		
}