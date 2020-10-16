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

import burp.IBurpExtenderCallbacks;
import burp.IHttpListener;
import burp.IHttpRequestResponse;

public class HttpListener implements IHttpListener {

	private final IBurpExtenderCallbacks callbacks;
	private final CurrentConfig config;
	private final RequestController requestController;

	public HttpListener(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.config = CurrentConfig.getCurrentConfig();
		this.requestController = new RequestController(callbacks);
	}

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		//Only responses to have corresponding request
		if(!messageIsRequest && config.isRunning()) {
			boolean isFiltered = false;
			for(int i=0; i<config.getRequestFilterList().size(); i++) {
				RequestFilter filter = config.getRequestFilterAt(i);
				if(filter.filterRequest(callbacks, toolFlag, messageInfo)) {
					System.out.println(i);
					isFiltered = true;
					break;
				}
			}
			if(!isFiltered) {
				requestController.analyze(messageInfo);
			}
		}
	}
}
