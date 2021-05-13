package com.protect7.authanalyzer.util;

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
				Type.ARRAY, "Static Patterns (for Automatically Set Parameters)"),
		AUTOSET_PARAM_DYNAMIC_PATTERNS("viewstate,eventvalidation,requestverificationtoken", Type.ARRAY,
				"Dynamic Patterns (for Automatically Set Parameters)"),
		NUMBER_OF_THREADS("20", Type.INTEGER, "Number of Threads (for Request Processing)"),
		ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT("true", Type.BOOLEAN, 
				"One Thread if a Prompt for Input Parameter is present"),
		SHOW_PENDING_REQUEST_INFO("false", Type.BOOLEAN, 
				"Show Pending Request Info (Reload Extension)");
		
		private final String defaultValue;
		private final Type type;
		private final String description;
		
		private Item(String defaultValue, Type type, String description) {
			this.defaultValue = defaultValue;
			this.type = type;
			this.description = description;
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
	}
	
	public enum Type {
		ARRAY(), STRING(), INTEGER(), BOOLEAN();
	}
}