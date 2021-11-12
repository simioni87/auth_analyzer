package com.protect7.authanalyzer.controller;

/**
 * The HTTPListener does analyze each HTTP Message. If the given message is a response (in this case the IHttpRequestResponse holds
 * the requests as well as the response) it will be checked if the current message should be filtered or not. The message will be passed 
 * to the RequestController for further processing if it is not filtered.
 * 
 * @author Simon Reinhart
 */

import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;
import burp.IInterceptedProxyMessage;
import burp.IProxyListener;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class HttpListener implements IHttpListener, IProxyListener {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if(config.isRunning() && (!messageIsRequest || (messageIsRequest && config.isDropOriginal() && toolFlag == IBurpExtenderCallbacks.TOOL_PROXY))) {		
			boolean isFiltered = false;
			IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo);
			IResponseInfo responseInfo = null;
			if(messageInfo.getResponse() != null) {
				responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
			}
			for(int i=0; i<config.getRequestFilterList().size(); i++) {
				RequestFilter filter = config.getRequestFilterAt(i);
				if(filter.filterRequest(BurpExtender.callbacks, toolFlag, requestInfo, responseInfo)) {
					isFiltered = true;
					break;
				}
			}
			if(!isFiltered) {
				config.performAuthAnalyzerRequest(messageInfo);
			}
		}
	}

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		if(config.isDropOriginal() && messageIsRequest) {
			processHttpMessage(IBurpExtenderCallbacks.TOOL_PROXY, true, message.getMessageInfo());
			message.setInterceptAction(IInterceptedProxyMessage.ACTION_DROP);
		}
	}
}
