package com.protect7.authanalyzer.entities;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;

import com.protect7.authanalyzer.gui.StatusPanel;
import com.protect7.authanalyzer.util.ExtractionHelper;
import com.protect7.authanalyzer.util.RequestModifHelper;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class Token {
	
	private final String name;
	private String value;
	private final String extractName;
	private final String grepFromString;
	private final String grepToString;
	private final boolean remove;
	private final boolean autoExtract;
	private final boolean staticValue;
	private final boolean fromToString;
	private final boolean promptForInput;
	private TokenRequest request = null;
	private final EnumSet<TokenLocation> tokenLocationSet; 
	private final EnumSet<AutoExtractLocation> autoExtractLocationSet;
	private final EnumSet<FromToExtractLocation> fromToExtractLocationSet;	
	
	public Token(String name, EnumSet<TokenLocation> tokenLocationSet, EnumSet<AutoExtractLocation> autoExtractLocationSet, EnumSet<FromToExtractLocation> fromToExtractLocationSet, String value, String extractName, 
			String grepFromString, String grepToString, boolean remove,	boolean autoExtract, boolean staticValue, boolean fromToString, boolean promptForInput) {
		this.name = name;
		this.value = value;
		this.extractName = extractName;
		this.grepFromString = grepFromString;
		this.grepToString = grepToString;
		this.remove = remove;
		this.autoExtract = autoExtract;
		this.staticValue = staticValue;
		this.fromToString = fromToString;
		this.promptForInput = promptForInput;
		this.tokenLocationSet = tokenLocationSet;
		this.autoExtractLocationSet = autoExtractLocationSet;
		this.fromToExtractLocationSet = fromToExtractLocationSet;
	}
	
	public String getName() {
		return name;
	}
	public String getValue() {
		return value;
	}
	public void setValue(String value) {
		this.value = value;
	}
	public String getExtractName() {
		return extractName;
	}
	public String getGrepFromString() {
		return grepFromString;
	}
	public String getGrepToString() {
		return grepToString;
	}
	public boolean isRemove() {
		return remove;
	}
	public boolean isAutoExtract() {
		return autoExtract;
	}
	public boolean isStaticValue() {
		return staticValue;
	}
	public boolean isFromToString() {
		return fromToString;
	}	
	public boolean isPromptForInput() {
		return this.promptForInput;
	}	
	public String getHeaderInsertionPointNameStart() {
		return "§" + name;
	}
	public TokenRequest getRequest() {
		return request;
	}
	public void setRequest(TokenRequest request) {
		this.request = request;
	}
	public boolean renewTokenValue(StatusPanel statusPanel, Session session) {
		if(request != null) {
			// Update oldRequestResponse with current parameter values
			byte[] modifiedRequest = RequestModifHelper.getModifiedRequest(request.getRequest(), session, new TokenPriority());
			IRequestInfo modifiedRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(modifiedRequest);
			byte[] modifiedMessageBody = Arrays.copyOfRange(modifiedRequest, modifiedRequestInfo.getBodyOffset(), modifiedRequest.length);
			List<String> modifiedHeaders = RequestModifHelper.getModifiedHeaders(modifiedRequestInfo.getHeaders(), session);
			byte[] message = BurpExtender.callbacks.getHelpers().buildHttpMessage(modifiedHeaders, modifiedMessageBody);

			IHttpRequestResponse newRequestResponse = BurpExtender.callbacks.makeHttpRequest(request.getHttpService(), message);
			boolean success = extractValue(newRequestResponse);
			if(!success) {
				//Try without modified Request
				newRequestResponse = BurpExtender.callbacks.makeHttpRequest(request.getHttpService(), request.getRequest());
				success = extractValue(newRequestResponse);
			}
			if(success) {
				statusPanel.updateTokenStatus(this);
				return true;
			}
		}
		return false;
	}
	
	private boolean extractValue(IHttpRequestResponse requestResponse) {
		IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
		if (isAutoExtract()) {
			return ExtractionHelper.extractCurrentTokenValue(requestResponse.getResponse(), responseInfo, this);
		}
		if (isFromToString()) {
			return ExtractionHelper.extractTokenWithFromToString(requestResponse.getResponse(), responseInfo, this);
		}
		return false;
	}
	
	public boolean doReplaceAtLocation(TokenLocation tokenLocation) {
		return tokenLocationSet.contains(tokenLocation);
	}

	public boolean doAutoExtractAtLocation(AutoExtractLocation autoExtractLocation) {
		return autoExtractLocationSet.contains(autoExtractLocation);
	}
	
	public boolean doFromToExtractAtLocation(FromToExtractLocation fromToExtractLocation) {
		return fromToExtractLocationSet.contains(fromToExtractLocation);
	}
}