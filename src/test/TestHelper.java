package test;

import burp.IParameter;

public class TestHelper {
	
	public static IParameter getIParameter(String name, String value) {
		IParameter parameter = new IParameter() {
			
			@Override
			public int getValueStart() {
				return 0;
			}
			
			@Override
			public int getValueEnd() {
				return 0;
			}
			
			@Override
			public String getValue() {
				return value;
			}
			
			@Override
			public byte getType() {
				return 0;
			}
			
			@Override
			public int getNameStart() {
				return 0;
			}
			
			@Override
			public int getNameEnd() {
				return 0;
			}
			
			@Override
			public String getName() {
				return name;
			}
		};
		return parameter;
	}	
}
