package com.protect7.authanalyzer.entities;

/**
 * This Entity holds a grep and replace Rule including the current grepped value if present.
 * 
 * @author Simon Reinhart
 */


public class Rule {
	
	private final String name;
	
	private final String grepFromString;
	private final String grepToString;
	private boolean grepInHeader = true;
	private boolean grepInBody = true;
	private boolean replaceInHeader = true;
	private boolean replaceInBody = true;
	
	private String replacementValue = null;
	
	private final String replaceFromString;
	private final String replaceToString;
	
	public Rule(String name, String grepFromString, String grepToString, String replaceFromString, String replaceToString,
			boolean grepInHeader, boolean grepInBody, boolean replaceInHeader, boolean replaceInBody) {
		this.name = name;
		this.grepFromString = grepFromString;
		this.grepToString = grepToString;
		this.replaceFromString = replaceFromString;
		this.replaceToString = replaceToString;
		this.grepInHeader = grepInHeader;
		this.grepInBody = grepInBody;
		this.replaceInHeader = replaceInHeader;
		this.replaceInBody = replaceInBody;
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

	public boolean grepInHeader() {
		return grepInHeader;
	}

	public void setGrepInHeader(boolean grepInHeader) {
		this.grepInHeader = grepInHeader;
	}

	public boolean grepInBody() {
		return grepInBody;
	}

	public void setGrepInBody(boolean grepInBody) {
		this.grepInBody = grepInBody;
	}

	public boolean replaceInHeader() {
		return replaceInHeader;
	}

	public void setReplaceInHeader(boolean replaceInHeader) {
		this.replaceInHeader = replaceInHeader;
	}

	public boolean replaceInBody() {
		return replaceInBody;
	}

	public void setReplaceInBody(boolean replaceInBody) {
		this.replaceInBody = replaceInBody;
	}
}