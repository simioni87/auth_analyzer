package com.protect7.authanalyzer.util;

import com.protect7.authanalyzer.entities.Range;

import burp.BurpExtender;

public class Setting {
	
	private final static String DELIMITER = ",";
	
	public static String[] getValueAsArray(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.ARRAY) {
			String[] values = value.split(DELIMITER);
			for(int i=0; i<values.length; i++) {
				values[i] = values[i].trim();
			}
			return values;
		}
		return new String[] {};
	}
	
	public static boolean getValueAsBoolean(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.BOOLEAN) {
			return Boolean.parseBoolean(value);
		}
		return false;
	}
	
	public static int getValueAsInteger(Item settingItem) {
		String value = getPersistentSetting(settingItem.toString());
		if(value == null) {
			value = settingItem.defaultValue;
		}
		if(settingItem.getType() == Type.INTEGER) {
			return Integer.parseInt(value);
		}
		return -1;
	}
	
	public static String getValueAsString(Item settingsItem) {
		String value = getPersistentSetting(settingsItem.toString());
		if(value == null) {
			value = settingsItem.getDefaultValue();
		}
		return value;
	}
	
	public static void setValue(Item settingItem, String value) {
		BurpExtender.callbacks.saveExtensionSetting(settingItem.toString(), value);
	}
	
	private static String getPersistentSetting(String name) {
		return BurpExtender.callbacks.loadExtensionSetting(name);
	}

	
	public enum Item {
		AUTOSET_PARAM_STATIC_PATTERNS("token,code,user,mail,pass,key,csrf,xsrf", 
				Type.ARRAY, "Static Patterns (for Automatically Set Parameters)", null),
		AUTOSET_PARAM_DYNAMIC_PATTERNS("viewstate,eventvalidation,requestverificationtoken", Type.ARRAY,
				"Dynamic Patterns (for Automatically Set Parameters)", null),
		NUMBER_OF_THREADS("5", Type.INTEGER, "Number of Threads (for Request Processing)", new Range(1,50)),
		DELAY_BETWEEN_REQUESTS("0", Type.INTEGER, "Delay between Requests in Milliseconds", new Range(0,60000)),
		ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT("true", Type.BOOLEAN, 
				"One Thread if a Prompt for Input Parameter is present", null),
		APPLY_FILTER_ON_MANUAL_REPEAT("false", Type.BOOLEAN, 
				"Apply Filters on Manual Request Repetition", null),
		STATUS_SAME_RESPONSE_CODE("true", Type.BOOLEAN, 
				"Respect Response Code to flag with Status SAME", null),
		STATUS_SIMILAR_RESPONSE_CODE("true", Type.BOOLEAN, 
				"(Condition 1) Respect Response Code to flag with Status SIMILAR", null),
		STATUS_SIMILAR_RESPONSE_LENGTH("5", Type.INTEGER, 
				"(Condition 2) Deviation of Content-Length in percent to flag with Status SIMILAR", new Range(1,100));
		
		private final String defaultValue;
		private final Type type;
		private final String description;
		private final Range range;
		
		private Item(String defaultValue, Type type, String description, Range range) {
			this.defaultValue = defaultValue;
			this.type = type;
			this.description = description;
			this.range = range;
		}
		
		public String getDefaultValue() {
			return defaultValue;
		}
		
		public Type getType() {
			return type;
		}

		public String getDescription() {
			return description;
		}
		
		public Range getRange() {
			return range;
		}
	}
	
	public enum Type {
		ARRAY(), STRING(), INTEGER(), BOOLEAN();
	}	
}