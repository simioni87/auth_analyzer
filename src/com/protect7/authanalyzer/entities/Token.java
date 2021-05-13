package com.protect7.authanalyzer.entities;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.EnumSet;
import burp.IHttpRequestResponse;

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
	private IHttpRequestResponse requestResponse = null;
	private int priority = 0;
	private final EnumSet<TokenLocation> tokenLocationSet; 
	private final EnumSet<AutoExtractLocation> autoExtractLocationSet;
	private final EnumSet<FromToExtractLocation> fromToExtractLocationSet;
	private final boolean caseSensitiveTokenName;
	private final boolean addIfNotExists;
	
	public Token(String name, EnumSet<TokenLocation> tokenLocationSet, EnumSet<AutoExtractLocation> autoExtractLocationSet, 
			EnumSet<FromToExtractLocation> fromToExtractLocationSet, String value, String extractName, String grepFromString, 
			String grepToString, boolean remove, boolean autoExtract, boolean staticValue, boolean fromToString, boolean promptForInput,
			boolean caseSensitiveTokenName, boolean addIfNotExists) {
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
		this.caseSensitiveTokenName = caseSensitiveTokenName;
		this.addIfNotExists = addIfNotExists;
	}
	
	public String getName() {
		return name;
	}
	public String getUrlEncodedName() {
		try {
			return URLEncoder.encode(name, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return name;
	}
	public String getValue() {
		return value;
	}
	public String getUrlEncodedValue() {
		try {
			return URLEncoder.encode(value, StandardCharsets.UTF_8.toString());
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
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
	public boolean doReplaceAtLocation(TokenLocation tokenLocation) {
		return getTokenLocationSet().contains(tokenLocation);
	}

	public boolean doAutoExtractAtLocation(AutoExtractLocation autoExtractLocation) {
		return getAutoExtractLocationSet().contains(autoExtractLocation);
	}
	
	public boolean doFromToExtractAtLocation(FromToExtractLocation fromToExtractLocation) {
		return getFromToExtractLocationSet().contains(fromToExtractLocation);
	}
	public EnumSet<AutoExtractLocation> getAutoExtractLocationSet() {
		return autoExtractLocationSet;
	}

	public EnumSet<TokenLocation> getTokenLocationSet() {
		return tokenLocationSet;
	}

	public EnumSet<FromToExtractLocation> getFromToExtractLocationSet() {
		return fromToExtractLocationSet;
	}

	public boolean isCaseSensitiveTokenName() {
		return caseSensitiveTokenName;
	}

	public boolean isAddIfNotExists() {
		return addIfNotExists;
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}

	public void setRequestResponse(IHttpRequestResponse requestResponse) {
		this.requestResponse = requestResponse;
	}

	public int getPriority() {
		return priority;
	}

	public void setPriority(int priority) {
		this.priority = priority;
	}	
	public String sortString() {
		return "" + autoExtract + staticValue + fromToString + promptForInput + name;
	}
}