package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class StatusCodeFilter extends RequestFilter {

	private String[] filterStringLiterals = { "204", "304" };

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		if (isSelected) {
			String statusCode = String.valueOf(messageInfo.getStatusCode());
			for (String stringLiteral : filterStringLiterals) {
				if (statusCode.equals(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public String[] getFilterStringLiterals() {
		return filterStringLiterals;
	}

	@Override
	public void setFilterStringLiterals(String[] filterStringLiterals) {
		this.filterStringLiterals = filterStringLiterals;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}

}
