package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class MethodFilter extends RequestFilter {
	
	private String[] filterMethods = {"OPTIONS"};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		
		if(isSelected) {		
			String requestMethod = callbacks.getHelpers().analyzeRequest(messageInfo.getRequest()).getMethod();
			for(String method : filterMethods) {
				if(requestMethod.toLowerCase().equals(method.toLowerCase()) && !method.trim().equals("")) {
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
