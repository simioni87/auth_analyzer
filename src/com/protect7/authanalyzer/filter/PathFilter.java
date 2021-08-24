package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class PathFilter extends RequestFilter {

	public PathFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected() && requestInfo.getUrl().getPath() != null) {		
			String url = requestInfo.getUrl().getPath().toString().toLowerCase();	
			for(String stringLiteral : stringLiterals) {
				if(url.contains(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
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

}
