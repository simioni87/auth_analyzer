package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class MethodFilter extends RequestFilter {
	
	private String[] filterMethods = {"OPTIONS"};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		
		if(isSelected) {		
			String requestMethod = requestInfo.getMethod();
			for(String method : filterMethods) {
				if(requestMethod.toLowerCase().equals(method.toLowerCase()) && !method.trim().equals("")) {
					incrementFiltered();
					return true;
				}
			}
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return true;
	}

	@Override
	public String[] getFilterStringLiterals() {
		return filterMethods;
	}

	@Override
	public void setFilterStringLiterals(String[] stringLiterals) {
		this.filterMethods = stringLiterals;
	}

}
