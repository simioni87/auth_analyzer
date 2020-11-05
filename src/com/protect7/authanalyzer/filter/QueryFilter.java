package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class QueryFilter extends RequestFilter {
	
	private String[] filterStringLiterals = {};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(isSelected) {
			if(requestInfo.getUrl().getQuery() != null) {
				String query = requestInfo.getUrl().getQuery().toString().toLowerCase();
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
