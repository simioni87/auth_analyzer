package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class StatusCodeFilter extends RequestFilter {
	
	public StatusCodeFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	private String[] filterStringLiterals = { "304" };

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if (isSelected) {
			String statusCode = String.valueOf(responseInfo.getStatusCode());
			for (String stringLiteral : filterStringLiterals) {
				if (statusCode.equals(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
					incrementFiltered();
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
