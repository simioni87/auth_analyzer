package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public class QueryFilter extends RequestFilter {
	
	private String[] filterStringLiterals = {};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		if(isSelected) {
			if(messageInfo.getUrl().getQuery() != null) {
				String query = messageInfo.getUrl().getQuery().toString().toLowerCase();
				for(String stringLiteral : filterStringLiterals) {
					if(query.contains(stringLiteral.toLowerCase()) && !stringLiteral.trim().equals("")) {
						incrementFiltered();
						return true;
					}
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
