package com.protect7.authanalyzer.entities;

public enum TokenLocation {

	PATH("Path"), COOKIE("Cookie"), URL("URL (GET Parameter)"), BODY("Body (URL-Encoded / Multipart)"), JSON("Body (JSON)");

	private final String name;

	public String getName() {
		return this.name;
	}

	private TokenLocation(String name) {
		this.name = name;
	}
	
}
