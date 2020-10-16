package test;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;
import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.entities.Rule;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.StatusPanel;
import burp.IParameter;
import burp.IRequestInfo;


public class AllTests {

	@Test
    public void testBodyModification() {
		Session session = new Session("session1", "", "csrftoken", "", false, new ArrayList<>(), new StatusPanel());
		session.setCsrfTokenValue("session1tokenvalue");
		RequestController requestController = new RequestController(null);
		//Test Multipart Body
		String originalMessageBodyMultipart = "-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"files[]\"; filename=\"test.php\"\r\n" + 
				"Content-Type: application/octet-stream\r\n" + 
				"\r\n" + 
				"test\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"text\"\r\n" + 
				"\r\n" + 
				"text default\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"csrftoken\"\r\n" + 
				"\r\n" + 
				"orignaltokenvalue\r\n" + 
				"-----------------------------334982301128266646462973140378--";
		String modifiedMessageBodyMultipart = requestController.getModifiedMessageBody(originalMessageBodyMultipart, IRequestInfo.CONTENT_TYPE_MULTIPART, session);		
		Assert.assertEquals(modifiedMessageBodyMultipart, "-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"files[]\"; filename=\"test.php\"\r\n" + 
				"Content-Type: application/octet-stream\r\n" + 
				"\r\n" + 
				"test\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"text\"\r\n" + 
				"\r\n" + 
				"text default\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"csrftoken\"\r\n" + 
				"\r\n" + 
				"session1tokenvalue\r\n" + 
				"-----------------------------334982301128266646462973140378--");
				
		//Test URL Encoded Body
		String originalMessageBodyURLEncoded = "blah=1&anyvar=2&csrftoken=orignaltokenvalue&anyvar2=3";
		String modifiedMessageBodyURLEncoded = requestController.getModifiedMessageBody(originalMessageBodyURLEncoded, IRequestInfo.CONTENT_TYPE_URL_ENCODED, session);		
		Assert.assertEquals("blah=1&anyvar=2&csrftoken=session1tokenvalue&anyvar2=3", modifiedMessageBodyURLEncoded);
		originalMessageBodyURLEncoded = "blah=1&anyvar=2&anyvar2=3&csrftoken=orignaltokenvalue";
		modifiedMessageBodyURLEncoded = requestController.getModifiedMessageBody(originalMessageBodyURLEncoded, IRequestInfo.CONTENT_TYPE_URL_ENCODED, session);		
		Assert.assertEquals("blah=1&anyvar=2&anyvar2=3&csrftoken=session1tokenvalue", modifiedMessageBodyURLEncoded);
		
		//Test JSON Body
		String originalMessageBodyJSON = "{\"param\":\"value\",\"csrftoken\":\"orignaltokenvalue\",\"test\":0}";
		String modifiedMessageBodyJSON = requestController.getModifiedMessageBody(originalMessageBodyJSON, IRequestInfo.CONTENT_TYPE_JSON, session);		
		Assert.assertEquals("{\"param\":\"value\",\"csrftoken\":\"session1tokenvalue\",\"test\":0}", modifiedMessageBodyJSON);
		
		//Test remove token feature
		session = new Session("session1", "", "remove_token#csrftoken", "", false, new ArrayList<>(), new StatusPanel());
		modifiedMessageBodyMultipart = requestController.getModifiedMessageBody(originalMessageBodyMultipart, IRequestInfo.CONTENT_TYPE_MULTIPART, session);
		Assert.assertEquals(modifiedMessageBodyMultipart, "-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"files[]\"; filename=\"test.php\"\r\n" + 
				"Content-Type: application/octet-stream\r\n" + 
				"\r\n" + 
				"test\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"text\"\r\n" + 
				"\r\n" + 
				"text default\r\n" + 
				"-----------------------------334982301128266646462973140378\r\n" + 
				"Content-Disposition: form-data; name=\"dummyparam\"\r\n" + 
				"\r\n" + 
				"orignaltokenvalue\r\n" + 
				"-----------------------------334982301128266646462973140378--");
		modifiedMessageBodyURLEncoded = requestController.getModifiedMessageBody(originalMessageBodyURLEncoded, IRequestInfo.CONTENT_TYPE_URL_ENCODED, session);		
		Assert.assertEquals("blah=1&anyvar=2&anyvar2=3&dummyparam=orignaltokenvalue", modifiedMessageBodyURLEncoded);
		modifiedMessageBodyJSON = requestController.getModifiedMessageBody(originalMessageBodyJSON, IRequestInfo.CONTENT_TYPE_JSON, session);		
		Assert.assertEquals("{\"param\":\"value\",\"dummyparam\":\"orignaltokenvalue\",\"test\":0}", modifiedMessageBodyJSON);	
    }
	
	@Test
	public void testHeaderModification() {
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
				headerList.add("GET /anysource?testparam1=testvalue1&csrftoken=orignaltokenvalue&testparam2=testvalue2 HTTP/1.1");
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
		
		Session session = new Session("session1", "Cookie: sessionCookie=replacedValue \r\n AnyHeader: AdditionalHeader ", "csrftoken", "session1tokenvalue", false, new ArrayList<>(), new StatusPanel());
		RequestController requestController = new RequestController(null);
		ArrayList<String> modifiedHeaders = requestController.getModifiedHeaders(requestInfo, session, 0);
		Assert.assertEquals(modifiedHeaders.get(0),"GET /anysource?testparam1=testvalue1&csrftoken=session1tokenvalue&testparam2=testvalue2 HTTP/1.1");
		Assert.assertEquals(modifiedHeaders.get(1),"Host: protect7.com");
		Assert.assertEquals(modifiedHeaders.get(2),"Cookie: sessionCookie=replacedValue");
		Assert.assertEquals(modifiedHeaders.get(3),"Content-Length: 0");
		Assert.assertEquals(modifiedHeaders.get(4),"AnyHeader: AdditionalHeader");
		
	}
	
	@Test
	public void testExtractCSRFToken() {
		//Test CSRF Token in HTML Body
		String document = "<!DOCTYPE html><html><head><title>Page Title</title></head><body><input type=\"text\" hidden name=\"csrftoken\" value=\"secretCSRFValue\" /></body></html>";
		RequestController requestController = new RequestController(null);
		String csrfTokenValueHTML = requestController.getCsrfTokenValueFromInputField(document, "csrftoken");
		Assert.assertEquals("secretCSRFValue", csrfTokenValueHTML);
		
		//Test CSRF Token in JSON Body
		String json = "{\"param\":\"value\",\"csrftoken\":\"secretCSRFValue\",\"test\":0}";
		String csrfTokenJSON = requestController.getCsrfTokenValueFromJson(json, "csrftoken");
		Assert.assertEquals("secretCSRFValue", csrfTokenJSON);
	}
	
	@Test
	public void testIsSameHeader() {
		ArrayList<String> headers = new ArrayList<String>();
		headers.add("Cookie: session=session1");
		headers.add("Any-Header: session=session1");
		Session session = new Session("session1", "Cookie: session=session1", "csrftoken", "session1tokenvalue", false, new ArrayList<>(), new StatusPanel());
		RequestController requestController = new RequestController(null);
		Assert.assertTrue(requestController.isSameHeader(headers, session));
		Session session2 = new Session("session1", "Cookie: session=session1\r\nAnother-Header: test", "csrftoken", "session1tokenvalue", false, new ArrayList<>(), new StatusPanel());
		Assert.assertFalse(requestController.isSameHeader(headers, session2));
	}
	
	@Test
	public void testExtractResponseRuleValues() {
		Rule rule1 = new Rule("1", "Set-Cookie: xsrftoken=", ";", "", "", true, true, true, true);
		Rule rule2 = new Rule("2", "name=\"csrftoken\" value=\"", "\"", "", "", true, true, true, true);
		Rule rule3 = new Rule("3", "endofdoctoken=", "EOF", "", "", true, true, true, true);
		Rule rule4 = new Rule("4", "My-Secret-Value: ", "\r\n", "", "", true, true, true, true);
		ArrayList<Rule> ruleList = new ArrayList<>();
		ruleList.add(rule1);
		ruleList.add(rule2);
		ruleList.add(rule3);
		ruleList.add(rule4);
		Session session = new Session("session1", "", "", "", false, ruleList, new StatusPanel());
		String response = "HTTP/1.1 200 OK\r\n" + 
				"Server: nginx\r\n" + 
				"Date: Wed, 14 Oct 2020 11:07:06 GMT\r\n" + 
				"Content-Length: 156\r\n" + 
				"Connection: close\r\n" + 
				"Set-Cookie: xsrftoken=supersecret1;\r\n" + 
				"My-Secret-Value: supersecret4\r\n" +
				"Content-Type: application/javascript; charset=UTF-8\r\n" + 
				"\r\n" + 
				"<!DOCTYPE html><html><head><title>Page Title</title></head><body><form><input name=\"csrftoken\" value=\"supersecret2\" /></form></body></html>endofdoctoken=supersecret3";
		RequestController requestController = new RequestController(null);
		requestController.extractResponseRuleValues(session, response.getBytes());
		Assert.assertEquals("supersecret1", rule1.getReplacementValue());
		Assert.assertEquals("supersecret2", rule2.getReplacementValue());
		Assert.assertEquals("supersecret3", rule3.getReplacementValue());
		Assert.assertEquals("supersecret4", rule4.getReplacementValue());
		// Test value can not be grepped
		String response2 = "Set-Cookie: xsrf=;\r\n\n<html></html>";
		rule1.setReplacementValue("replacmentValue");
		requestController.extractResponseRuleValues(session, response2.getBytes());
		Assert.assertEquals("replacmentValue", rule1.getReplacementValue());
		// Test only grep in header
		rule1.setGrepInHeader(false);
		rule1.setReplacementValue("anyvalue");
		requestController.extractResponseRuleValues(session, response.getBytes());
		Assert.assertEquals("anyvalue", rule1.getReplacementValue());
		rule1.setGrepInHeader(true);
		requestController.extractResponseRuleValues(session, response.getBytes());
		Assert.assertEquals("supersecret1", rule1.getReplacementValue());
		// Test only grep in body
		rule3.setGrepInBody(false);
		rule3.setReplacementValue("anyvalue");
		requestController.extractResponseRuleValues(session, response.getBytes());
		Assert.assertEquals("anyvalue", rule3.getReplacementValue());
		rule3.setGrepInBody(true);
		requestController.extractResponseRuleValues(session, response.getBytes());
		Assert.assertEquals("supersecret3", rule3.getReplacementValue());
	}
	
	@Test
	public void testApplyRulesInBody() {
		ArrayList<Rule> ruleList = new ArrayList<>();
		Rule rule1 = new Rule("1", "", "", "&csrftoken=", "&", true, true, true, true);
		rule1.setReplacementValue("csrfValueReplaced");
		ruleList.add(rule1);
		Session session = new Session("session1", "", "", "", false, ruleList, new StatusPanel());
		RequestController requestController = new RequestController(null);
		//Test replace URL Encoded in middle
		String body1 = "test=value&csrftoken=valueToReplace&test=value2";
		String modifiedBody1 = requestController.applyRulesInBody(session, body1);
		Assert.assertEquals("test=value&csrftoken=csrfValueReplaced&test=value2", modifiedBody1);
		//Test replace when charset occurs several times (only first one should be replaced
		String body4 = "test=value&csrftoken=valueToReplace&test=value2&csrftoken=valueToReplace";
		String modifiedBody4 = requestController.applyRulesInBody(session, body4);
		System.out.println(modifiedBody4);
		Assert.assertEquals("test=value&csrftoken=csrfValueReplaced&test=value2&csrftoken=valueToReplace", modifiedBody4);
		//Test do not replace (does not occur)
		String body2 = "test=value&anyvar=anyvalue&test=value2";
		String modifiedBody2 = requestController.applyRulesInBody(session, body2);
		Assert.assertEquals("test=value&anyvar=anyvalue&test=value2", modifiedBody2);
		//Test replace at end
		Rule rule2 = new Rule("2", "", "", "&csrftoken=", "EOF", true, true, true, true);
		rule2.setReplacementValue("csrfValueReplaced");
		ruleList.add(rule2);
		String body3 = "test=value&test=value2&csrftoken=valueToReplace";
		String modifiedBody3 = requestController.applyRulesInBody(session, body3);
		Assert.assertEquals("test=value&test=value2&csrftoken=csrfValueReplaced", modifiedBody3);
	}
	
	@Test
	public void testApplyRulesInHeader() {
		ArrayList<Rule> ruleList = new ArrayList<>();
		Rule rule1 = new Rule("1", "", "", "Cookie: session=", ";", true, true, true, true);
		rule1.setReplacementValue("valueReplaced");
		ruleList.add(rule1);
		Session session = new Session("session1", "", "", "", false, ruleList, new StatusPanel());
		RequestController requestController = new RequestController(null);
		//Test Replace Part in Header
		String header1 = "Cookie: session=valueToReplace;";
		String modifiedHeader1 = requestController.applyRulesInHeader(session, header1);
		Assert.assertEquals("Cookie: session=valueReplaced;", modifiedHeader1);
		//Test Replace no value
		String header2 = "Cookie: session=valueToReplace";
		String modifiedHeader2 = requestController.applyRulesInHeader(session, header2);
		Assert.assertEquals("Cookie: session=valueToReplace", modifiedHeader2);
		//Test Replace at end of Header
		Rule rule2 = new Rule("2", "", "", "Cookie: session=", "\n", true, true, true, true);
		rule2.setReplacementValue("valueReplaced2");
		ruleList.add(rule2);
		String header3 = "Cookie: session=valueToReplace";
		String modifiedHeader3 = requestController.applyRulesInHeader(session, header3);
		Assert.assertEquals("Cookie: session=valueReplaced2", modifiedHeader3);
	}
}