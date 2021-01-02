package com.protect7.authanalyzer.entities;

import burp.IHttpService;

public class TokenRequest {
	
	private final int id;
	private final byte[] request;
	private final IHttpService httpService;
	private final int priority;
	public TokenRequest(int id, byte[] request, IHttpService httpService, int priority) {
		this.id = id;
		this.request = request;
		this.httpService = httpService;
		this.priority = priority;
	}
	public byte[] getRequest() {
		return request;
	}
	public int getPriority() {
		return priority;
	}
	public IHttpService getHttpService() {
		return httpService;
	}
	public int getId() {
		return id;
	}
}
