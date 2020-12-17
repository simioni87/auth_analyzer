package com.protect7.authanalyzer.entities;

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
	
	
	public Token(String name, String value, String extractName, String grepFromString, String grepToString, boolean remove,
			boolean autoExtract, boolean staticValue, boolean fromToString, boolean promptForInput) {
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

}
