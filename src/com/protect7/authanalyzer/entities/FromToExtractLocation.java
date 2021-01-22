package com.protect7.authanalyzer.entities;

import java.util.EnumSet;

public enum FromToExtractLocation {

	HEADER("Response Header"), 
	BODY("Response Body"), 
	ALL("All Responses (incl. Binary)"), 
	HTML("HTML Document"), 
	JSON("JSON Object"), 
	XML("XML Document"), 
	TEXT("Plain Text"), 
	SCRIPT("Script"), 
	CSS("CSS");

	private final String name;

	public String getName() {
		return this.name;
	}

	private FromToExtractLocation(String name) {
		this.name = name;
	}
	
	public static EnumSet<FromToExtractLocation> getDefaultSet() {
		return EnumSet.of(HEADER, BODY, HTML, JSON, XML, TEXT);
	}
	
}
