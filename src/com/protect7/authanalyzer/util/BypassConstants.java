package com.protect7.authanalyzer.util;

public enum BypassConstants {

	SAME("SAME"), SIMILAR("SIMILAR"), DIFFERENT("DIFFERENT"), NA("N/A");
	
	
	private final String name;

	public String getName() {
		return this.name;
	}

	private BypassConstants(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return name;
	}
}