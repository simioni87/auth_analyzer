package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;

public class FileTypeFilter extends RequestFilter {
	
	private String[] filterFileTypes = {"js", "script", "css", "png", "jpg", "jpeg", "gif", "svg", "bmp", "woff", "ico"};

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo) {
		if(isSelected) {
			IResponseInfo response = callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
			String url = messageInfo.getUrl().toString().toLowerCase();
			for(String fileType : filterFileTypes) {
				if(url.endsWith(fileType.toLowerCase()) && !fileType.equals("") || 
						(fileType.toLowerCase().equals(response.getInferredMimeType().toLowerCase()) && !fileType.trim().equals(""))) {
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
		return filterFileTypes;
	}

	@Override
	public void setFilterStringLiterals(String[] stringLiterals) {
		this.filterFileTypes = stringLiterals;
	}


}
