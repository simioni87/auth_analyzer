package com.protect7.authanalyzer.entities;

public class Rule {
	
	private final String name;
	
	private final String grepFromString;
	private final String grepToString;
	private boolean isHeader = true;
	private boolean isBody = true;
	
	private String replacementValue = null;
	
	private final String replaceFromString;
	private final String replaceToString;
	
	public Rule(String name, String grepFromString, String grepToString, String replaceFromString, String replaceToString) {
		this.name = name;
		this.grepFromString = grepFromString;
		this.grepToString = grepToString;
		this.replaceFromString = replaceFromString;
		this.replaceToString = replaceToString;
	}
	
	// Returns null if replacement never grepped a value
	public String getReplacementValue() {
		return replacementValue;
	}
	public void setReplacementValue(String replacementValue) {
		this.replacementValue = replacementValue;
	}

	public String getGrepFromString() {
		return grepFromString;
	}

	public String getGrepToString() {
		return grepToString;
	}

	public String getReplaceFromString() {
		return replaceFromString;
	}

	public String getReplaceToString() {
		return replaceToString;
	}

	public String getName() {
		return name;
	}

	public boolean isHeader() {
		return isHeader;
	}

	public void setIsHeader(boolean isHeader) {
		this.isHeader = isHeader;
	}

	public boolean isBody() {
		return isBody;
	}

	public void setIsBody(boolean isBody) {
		this.isBody = isBody;
	}
}