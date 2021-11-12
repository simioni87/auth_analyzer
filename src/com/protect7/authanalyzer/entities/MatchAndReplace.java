package com.protect7.authanalyzer.entities;

public class MatchAndReplace {
	
	private final String match;
	private final String replace;
	
	public MatchAndReplace(String match, String replace) {
		this.match = match;
		this.replace = replace;
	}

	public String getMatch() {
		return match;
	}

	public String getReplace() {
		return replace;
	}

}
