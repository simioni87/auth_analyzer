package com.protect7.authanalyzer.entities;

public class Range {
	
	private final int minimum;
	private final int maximum; 
	
	public Range(int minimum, int maximum) {
		this.minimum = minimum;
		this.maximum = maximum;
	}

	public int getMinimum() {
		return minimum;
	}

	public int getMaximum() {
		return maximum;
	}
}