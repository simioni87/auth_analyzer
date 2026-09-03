package com.protect7.authanalyzer.entities;

public class MatchAndReplace {
	
	private final String match;
	private final String replace;
	private final boolean regex;
	
	public MatchAndReplace(String match, String replace) {
		this(match, replace, false);
	}
	
	public MatchAndReplace(String match, String replace, boolean regex) {
		this.match = match;
		this.replace = replace;
		this.regex = regex;
	}

	public String getMatch() {
		return match;
	}

	public String getReplace() {
		return replace;
	}

	public boolean isRegex() {
		return regex;
	}

}
