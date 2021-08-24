package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class InScopeFilter extends RequestFilter {

	public InScopeFilter(int filterIndex, String description) {
		super(filterIndex, description);
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo,
			IResponseInfo responseInfo) {
		if (onOffButton.isSelected() && !callbacks.isInScope(requestInfo.getUrl())) {
			incrementFiltered();
			return true;
		}
		return false;
	}

	@Override
	public boolean hasStringLiterals() {
		return false;
	}
}