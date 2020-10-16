package test;

import burp.IParameter;

public class TestHelper {
	
	public static IParameter getIParameter(String name, String value) {
		IParameter parameter = new IParameter() {
			
			@Override
			public int getValueStart() {
				// TODO Auto-generated method stub
				return 0;
			}
			
			@Override
			public int getValueEnd() {
				// TODO Auto-generated method stub
				return 0;
			}
			
			@Override
			public String getValue() {
				// TODO Auto-generated method stub
				return value;
			}
			
			@Override
			public byte getType() {
				// TODO Auto-generated method stub
				return 0;
			}
			
			@Override
			public int getNameStart() {
				// TODO Auto-generated method stub
				return 0;
			}
			
			@Override
			public int getNameEnd() {
				// TODO Auto-generated method stub
				return 0;
			}
			
			@Override
			public String getName() {
				// TODO Auto-generated method stub
				return name;
			}
		};
		return parameter;
	}	
}
