package com.protect7.authanalyzer.entities;

import java.util.EnumSet;

public class TokenBuilder {
	
	private String name = null;
	private String value = null;
	private String extractName = null;
	private String grepFromString = null;
	private String grepToString = null;
	private boolean remove = false;
	private boolean autoExtract = false;
	private boolean staticValue = false;
	private boolean fromToString = false;
	private boolean promptForInput = false;
	private EnumSet<TokenLocation> tokenLocationSet = EnumSet.allOf(TokenLocation.class); 
	private EnumSet<AutoExtractLocation> autoExtractLocationSet = AutoExtractLocation.getDefaultSet();
	private EnumSet<FromToExtractLocation> fromToExtractLocationSet = FromToExtractLocation.getDefaultSet();
	private boolean caseSensitiveTokenName = true;
	private boolean addIfNotExists = false;
	private boolean urlEncoded = true;
	private boolean urlDecoded = false;
	private String aliases = "";
	
	public Token build() {
		return new Token(this);
	}
	
	public String getName() {
		return name;
	}
	public TokenBuilder setName(String name) {
		this.name = name;
		return this;
	}
	public String getValue() {
		return value;
	}
	public TokenBuilder setValue(String value) {
		this.value = value;
		return this;
	}
	public String getAliases() {
		return this.aliases;
	}
	public TokenBuilder setAliases(String value) {
		this.aliases = value;
		return this;
	}
	public String getExtractName() {
		return extractName;
	}
	public TokenBuilder setExtractName(String extractName) {
		this.extractName = extractName;
		return this;
	}
	public String getGrepFromString() {
		return grepFromString;
	}
	public TokenBuilder setGrepFromString(String grepFromString) {
		this.grepFromString = grepFromString;
		return this;
	}
	public String getGrepToString() {
		return grepToString;
	}
	public TokenBuilder setGrepToString(String grepToString) {
		this.grepToString = grepToString;
		return this;
	}
	public boolean isRemove() {
		return remove;
	}
	public TokenBuilder setIsRemove(boolean remove) {
		this.remove = remove;
		return this;
	}
	public boolean isAutoExtract() {
		return autoExtract;
	}
	public TokenBuilder setIsAutoExtract(boolean autoExtract) {
		this.autoExtract = autoExtract;
		return this;
	}
	public boolean isStaticValue() {
		return staticValue;
	}
	public TokenBuilder setIsStaticValue(boolean staticValue) {
		this.staticValue = staticValue;
		return this;
	}
	public boolean isFromToString() {
		return fromToString;
	}
	public TokenBuilder setIsFromToString(boolean fromToString) {
		this.fromToString = fromToString;
		return this;
	}
	public boolean isPromptForInput() {
		return promptForInput;
	}
	public TokenBuilder setIsPromptForInput(boolean promptForInput) {
		this.promptForInput = promptForInput;
		return this;
	}
	public EnumSet<TokenLocation> getTokenLocationSet() {
		return tokenLocationSet;
	}
	public TokenBuilder setTokenLocationSet(EnumSet<TokenLocation> tokenLocationSet) {
		this.tokenLocationSet = tokenLocationSet;
		return this;
	}
	public EnumSet<AutoExtractLocation> getAutoExtractLocationSet() {
		return autoExtractLocationSet;
	}
	public TokenBuilder setAutoExtractLocationSet(EnumSet<AutoExtractLocation> autoExtractLocationSet) {
		this.autoExtractLocationSet = autoExtractLocationSet;
		return this;
	}
	public EnumSet<FromToExtractLocation> getFromToExtractLocationSet() {
		return fromToExtractLocationSet;
	}
	public TokenBuilder setFromToExtractLocationSet(EnumSet<FromToExtractLocation> fromToExtractLocationSet) {
		this.fromToExtractLocationSet = fromToExtractLocationSet;
		return this;
	}
	public boolean isCaseSensitiveTokenName() {
		return caseSensitiveTokenName;
	}
	public TokenBuilder setIsCaseSensitiveTokenName(boolean caseSensitiveTokenName) {
		this.caseSensitiveTokenName = caseSensitiveTokenName;
		return this;
	}
	public boolean isAddIfNotExists() {
		return addIfNotExists;
	}
	public TokenBuilder setIsAddIfNotExists(boolean addIfNotExists) {
		this.addIfNotExists = addIfNotExists;
		return this;
	}
	public boolean isUrlEncoded() {
		return urlEncoded;
	}
	public TokenBuilder setIsUrlEncoded(boolean urlEncoded) {
		this.urlEncoded = urlEncoded;
		return this;
	}

	public boolean isUrlDecoded() {
		return urlDecoded;
	}
	public TokenBuilder setIsUrlDecoded(boolean urlDecoded) {
		this.urlDecoded = urlDecoded;
		return this;
	}
}
