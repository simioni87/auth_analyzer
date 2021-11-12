package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class QueryFilter extends RequestFilter {

	public QueryFilter(int filterIndex, String description) {
		super(filterIndex, description);
		setFilterStringLiterals(new String[]{});
	}

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(onOffButton.isSelected()) {
			if(requestInfo.getUrl().getQuery() != null) {
				String query = requestInfo.getUrl().getQuery().toString().toLowerCase();
				for(String stringLiteral : stringLiterals) {
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
	public boolean hasStringLiterals() {
		return true;
	}

}
