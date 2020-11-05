package com.protect7.authanalyzer.filter;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class OnlyProxyFilter extends RequestFilter {

	@Override
	public boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo) {
		if(isSelected) {
			if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
				return false;
			}
			else if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER) {
				incrementFiltered();
			}
		}
		else {
			//Only allow Repeater beside of Proxy
			if(toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER || toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) {
				return false;
			}
		}
		return true;
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
