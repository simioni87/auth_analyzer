package com.protect7.authanalyzer.controller;

import java.io.PrintWriter;
import java.util.ArrayList;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class RequestController {

	private final IBurpExtenderCallbacks callbacks;
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private String currentOriginalCsrfValue = "";

	public RequestController(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}

	public synchronized void analyze(IHttpRequestResponse originalMessageInfo) {
		IRequestInfo originalRequestInfo = callbacks.getHelpers().analyzeRequest(originalMessageInfo);
		
		extractOriginalCsrfValue(originalMessageInfo);
	
		String originalMessageBody = getRequestBodyAsString(originalMessageInfo);
		
		int mapId = config.getTableModel().getFullMapSize() + 1;
		boolean success = true;
		boolean filtered = false;
		for(Session session : config.getSessions()) {
			if(session.isFilterRequestsWithSameHeader()) {
				ArrayList<String> headers = (ArrayList<String>) originalRequestInfo.getHeaders();
				String[] headersToReplace = session.getHeadersToReplace().split("\n");
				boolean requestContainsHeader = true;
				for (String headerToReplace : headersToReplace) {
					if(!headers.contains(headerToReplace)) {
						requestContainsHeader = false;
					}
				}
				if(requestContainsHeader) {
					filtered = true;
					success = false;
				}
			}
			if(!filtered) {
				ArrayList<String> modifiedHeaders = getModifiedHeaders(originalRequestInfo, session);
				String modifiedMessageBody = originalMessageBody;
				if(!session.getCsrfTokenName().equals("")) {
					modifiedMessageBody = getModifiedMessageBody(originalMessageBody, originalRequestInfo.getContentType() , session);
				}
				byte[] message = callbacks.getHelpers().buildHttpMessage(modifiedHeaders, modifiedMessageBody.getBytes());
				// Perform modified request
				IHttpRequestResponse modifiedMessageInfo = callbacks.makeHttpRequest(originalMessageInfo.getHttpService(),message);
				
				// Analyse Response of modified Request
				if (originalMessageInfo.getResponse() != null && modifiedMessageInfo.getResponse() != null) {

					if (!session.getCsrfTokenName().equals("") && session.getManuelCsrfTokenValue().equals("")) {
						extractCurrentCsrfValue(modifiedMessageInfo, session);
					}

					BypassConstants bypassConstant = analyzeResponses(originalMessageInfo, modifiedMessageInfo);
					if (bypassConstant != null) {
						AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(modifiedMessageInfo, bypassConstant);
						session.putRequestResponse(mapId, analyzerRequestResponse);
					}
					else {
						success = false;
					}
				}
				else {
					success = false;
				}
			}
		}
		if(success) {
			config.getTableModel().putNewRequestResponse(mapId, originalMessageInfo);
		}
	}

	private ArrayList<String> getModifiedHeaders(IRequestInfo originalRequestInfo, Session session) {
		ArrayList<String> headers = (ArrayList<String>) originalRequestInfo.getHeaders();
		String[] headersToReplace = session.getHeadersToReplace().split("\n");
		for (String headerToReplace : headersToReplace) {
			String[] headerKeyValuePair = headerToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				String headerKey = headerKeyValuePair[0];
				boolean headerReplaced = false;
				for (int i = 0; i < headers.size(); i++) {
					if (headers.get(i).startsWith(headerKey)) {
						headers.set(i, headerToReplace);
						headerReplaced = true;
						break;
					}
				}
				if (!headerReplaced) {
					headers.add(headerToReplace);
				}
			}
		}
		// Check for CSRF Token as Query Parameter
		if (session.getCsrfTokenName().toLowerCase().startsWith("remove_token")) {
			String[] csrfSplit = session.getCsrfTokenName().split("#");
			if (csrfSplit.length > 0) {
				String modifiedHeader = headers.get(0).replace(csrfSplit[1],"dummyparam");
				headers.set(0, modifiedHeader);
			}
		}
		else if(!session.getCsrfTokenName().equals("")){
			for (IParameter param : originalRequestInfo.getParameters()) {
				if (param.getName().equals(session.getCsrfTokenName())) {
					String modifiedHeader = headers.get(0).replace(param.getValue(), session.getCurrentCsrftTokenValue());
					headers.set(0, modifiedHeader);
					break;
				}
			}
		}
		return headers;
	}

	// Sets CSRF Token to Body
	private String getModifiedMessageBody(String originalMessageBody, byte contentType, Session session) {
		String modifiedMessageBody = "";
		// CSRF Remove feature. Syntax remove_token#csrt_token
		if (session.getCsrfTokenName().toLowerCase().startsWith("remove_token")) {
			String[] csrfSplit = session.getCsrfTokenName().split("#");
			if (csrfSplit.length > 0) {
				modifiedMessageBody = originalMessageBody.replace(csrfSplit[1], "dummyparam");
			}
		}
		else {
			if (originalMessageBody.length() > 0) {
				// Check and replace if original csrf value present (request body content type not relevant)
				if(!currentOriginalCsrfValue.equals("") && originalMessageBody.contains(currentOriginalCsrfValue)) {
					modifiedMessageBody = originalMessageBody.replace(currentOriginalCsrfValue, session.getCurrentCsrftTokenValue());
				}
				else if(originalMessageBody.contains(session.getCsrfTokenName())) {
					// Handle Multipart Form Data
					if (contentType == IRequestInfo.CONTENT_TYPE_MULTIPART) {
						String[] splitAtCsrfTokenName = originalMessageBody.split(session.getCsrfTokenName());
						if (splitAtCsrfTokenName.length > 1) {
							String[] csrfTokenValueSplit = splitAtCsrfTokenName[1].split("\\n");
							if (csrfTokenValueSplit.length > 2) {
								String csrfValue = csrfTokenValueSplit[2].split("---")[0].trim();
								modifiedMessageBody = originalMessageBody.replace(csrfValue,
										session.getCurrentCsrftTokenValue());
								;
							}
						}
					} 
					// Handle URL Encoded
					if(contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
						String[] params = originalMessageBody.split("&");
						for (String param : params) {
							if (param.split("=")[0].equals(session.getCsrfTokenName())) {
								modifiedMessageBody = originalMessageBody.replace(param,
										session.getCsrfTokenName() + "=" + session.getCurrentCsrftTokenValue());
							}
						}
					}
					// Handle JSON Body
					if(contentType == IRequestInfo.CONTENT_TYPE_JSON) {
						JsonElement jelement = new JsonParser().parse(originalMessageBody);
						JsonObject jobject = null;
						if(jelement.isJsonObject()) {
							jobject = jelement.getAsJsonObject();
						}
						else if(jelement.isJsonArray()) {
							if(jelement.getAsJsonArray().get(0).isJsonObject()) {
								jobject = jelement.getAsJsonArray().get(0).getAsJsonObject();
							}
						}
					    if(jobject != null) {
					    	String oldCsrfValue = jobject.get(session.getCsrfTokenName()).getAsString();
					    	modifiedMessageBody = originalMessageBody.replace(oldCsrfValue, session.getCurrentCsrftTokenValue());
					    }
					}
				}
			}
		}
		if (modifiedMessageBody.equals("")) {
			modifiedMessageBody = originalMessageBody;
		}
		return modifiedMessageBody;
	}
	
	private void extractOriginalCsrfValue(IHttpRequestResponse messageInfo) {
		String csrfTokenName = config.getSessions().get(0).getCsrfTokenName();
		if (!csrfTokenName.equals("")) {
			IResponseInfo response = callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
			String responseBody = getResponseBodyAsString(messageInfo);
			if(responseBody.contains(csrfTokenName)) {
				if (response.getStatedMimeType().equals("HTML") || response.getInferredMimeType().equals("HTML")) {
					currentOriginalCsrfValue = getCsrfTokenValueFromInputField(responseBody, csrfTokenName);
				}
				else if (response.getStatedMimeType().equals("JSON") || response.getInferredMimeType().equals("JSON")) {
					currentOriginalCsrfValue = getCsrfTokenValueFromJson(responseBody, csrfTokenName);
				}
			}
		}
	}

	private void extractCurrentCsrfValue(IHttpRequestResponse messageInfo, Session session) {
		IResponseInfo response = callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		String responseBody = getResponseBodyAsString(messageInfo);
		if(responseBody.contains(session.getCsrfTokenName())) {
			if (response.getStatedMimeType().equals("HTML") || response.getInferredMimeType().equals("HTML")) {
				session.setCsrfTokenValue(getCsrfTokenValueFromInputField(responseBody, session.getCsrfTokenName()));
			}
			else if (response.getStatedMimeType().equals("JSON") || response.getInferredMimeType().equals("JSON")) {
				session.setCsrfTokenValue(getCsrfTokenValueFromJson(responseBody, session.getCsrfTokenName()));
			}
		}
	}
	
	private String getCsrfTokenValueFromInputField(String document, String csrfName) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", csrfName);
		if (csrfFields.size() > 0) {
			String csrfValue = csrfFields.get(0).attr("value");
			return csrfValue;
		}
		return "";
	}

	private String getCsrfTokenValueFromJson(String json, String csrfName) {
		JsonElement jelement = new JsonParser().parse(json);
		JsonObject jobject = null;
		if(jelement.isJsonObject()) {
			jobject = jelement.getAsJsonObject();
		}
		else if(jelement.isJsonArray()) {
			if(jelement.getAsJsonArray().get(0).isJsonObject()) {
				jobject = jelement.getAsJsonArray().get(0).getAsJsonObject();
			}
		}
	    if(jobject != null) {
	    	String csrfValue = jobject.get(csrfName).getAsString();
	    	return csrfValue;
	    }
	    return "";
	}
	
	/*
	 * Bypass if: 
	 * - Both Responses have same Response Body
	 * 
	 * Potential Bypass if: 
	 * - Both Responses have same Response Code 
	 * - Both Responses have +-5% of response body length 
	 *
	 */
	private BypassConstants analyzeResponses(IHttpRequestResponse originalMessageInfo,
			IHttpRequestResponse modifiedMessageInfo) {
		try {
			String originalMessageBody = getResponseBodyAsString(originalMessageInfo);
			String modifiedMessageBody = getResponseBodyAsString(modifiedMessageInfo);
			if (originalMessageBody.equals(modifiedMessageBody)) {
				return BypassConstants.BYPASSED;
			}
			if (originalMessageInfo.getStatusCode() == modifiedMessageInfo.getStatusCode()) {
				int range = originalMessageBody.length() / 20; // calc 5% of response length
				int difference = originalMessageBody.length() - modifiedMessageBody.length();
				// Check if difference is in range
				if (difference < range && difference > -range) {
					return BypassConstants.POTENTIAL_BYPASSED;
				}
			}

			return BypassConstants.NOT_BYPASSED;
		} catch (Exception e) {
			PrintWriter stderr = new PrintWriter(callbacks.getStderr(), true);
			stderr.println("Failed to analyze Response");
			e.printStackTrace();
			return null;
		}
	}
	
	private String getRequestHeaderAsString(IHttpRequestResponse messageInfo) {
		IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
		String requestString = new String(messageInfo.getRequest());
		String messageHeader = requestString.substring(0, requestInfo.getBodyOffset());
		return messageHeader;
	}
	
	private String getRequestBodyAsString(IHttpRequestResponse messageInfo) {
		IRequestInfo requestInfo = callbacks.getHelpers().analyzeRequest(messageInfo);
		String requestString = new String(messageInfo.getRequest());
		String messageBody = requestString.substring(requestInfo.getBodyOffset());
		return messageBody;
	}
	
	private String getResponseBodyAsString(IHttpRequestResponse messageInfo) {
		IResponseInfo response = callbacks.getHelpers().analyzeResponse(messageInfo.getResponse());
		String currentResponse = new String(messageInfo.getResponse());
		String responseBody = currentResponse.substring(response.getBodyOffset());
		return responseBody;
	}
}
