package test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import burp.IParameter;
import burp.IRequestInfo;

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

	public static IRequestInfo getIRequestInfo() {
		IRequestInfo requestInfo = new IRequestInfo() {

			@Override
			public URL getUrl() {
				URL url = null;
				try {
					url = new URL("https://www.protect7.com");
				} catch (MalformedURLException e) {
					e.printStackTrace();
				}
				return url;
			}

			@Override
			public List<IParameter> getParameters() {
				List<IParameter> paramList = new ArrayList<>();
				paramList.add(TestHelper.getIParameter("testparam1", "testvalue1"));
				paramList.add(TestHelper.getIParameter("csrftoken", "orignaltokenvalue"));
				paramList.add(TestHelper.getIParameter("testparam2", "testvalue2"));
				return paramList;
			}

			@Override
			public String getMethod() {
				return "GET";
			}

			@Override
			public List<String> getHeaders() {
				List<String> headerList = new ArrayList<>();
				headerList.add(
						"GET /anysource?testparam1=testvalue1&csrftoken=orignaltokenvalue&testparam2=testvalue2 HTTP/1.1");
				headerList.add("Host: protect7.com");
				headerList.add("Cookie: sessionCookie=sessiontokenvalue");
				headerList.add("Content-Length: 0");
				return headerList;
			}

			@Override
			public byte getContentType() {
				return 0;
			}

			@Override
			public int getBodyOffset() {
				return 0;
			}
		};
		return requestInfo;
	}
}
