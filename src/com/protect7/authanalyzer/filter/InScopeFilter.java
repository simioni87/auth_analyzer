package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class InScopeFilter extends RequestFilter {

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(isSelected && !callbacks.isInScope(requestInfo.getUrl())) {
			incrementFiltered();
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}

	@Override
	public String[] getFilterStringLiterals() {
		return null;
	}

	@Override
	public void setFilterStringLiterals(String[] stringLiterals) {
	}

}
