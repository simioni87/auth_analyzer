package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class PathFilter extends RequestFilter {
	
	private String[] filterStringLiterals = {""};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		if(isSelected && messageInfo.getUrl().getPath() != null) {		
			String url = messageInfo.getUrl().getPath().toString().toLowerCase();	
			for(String stringLiteral : filterStringLiterals) {
				if(url.contains(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
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
