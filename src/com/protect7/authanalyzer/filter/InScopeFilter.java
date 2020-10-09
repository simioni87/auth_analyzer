package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class InScopeFilter extends RequestFilter {

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		if(isSelected && !callbacks.isInScope(messageInfo.getUrl())) {
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String[] getFilterStringLiterals() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setFilterStringLiterals(String[] stringLiterals) {
		// TODO Auto-generated method stub
		
	}

}
