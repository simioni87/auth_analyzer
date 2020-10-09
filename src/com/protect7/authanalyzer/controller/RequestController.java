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
import com.protect7.authanalyzer.entities.Rule;
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
	private final PrintWriter stdout;

	public RequestController(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
		this.stdout = new PrintWriter(callbacks.getStdout(), true);
	}

	public synchronized void analyze(IHttpRequestResponse originalMessageInfo) {
		if (originalMessageInfo == null || originalMessageInfo.getRequest() == null || originalMessageInfo.getResponse() == null) {
			stdout.println("WARNING: Cannot analyze request with null values.");
		}
		else {
			IRequestInfo originalRequestInfo = callbacks.getHelpers().analyzeRequest(originalMessageInfo);
			stdout.println("INFO: Handle New Request: " + originalRequestInfo.getUrl());
			
			extractOriginalCsrfValue(originalMessageInfo);
		
			String originalMessageBody = getRequestBodyAsString(originalMessageInfo);
			
			int mapId = config.getTableModel().getFullMapSize() + 1;
			boolean filtered = false;
			boolean success = true;
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
						stdout.println("INFO: Request filtered due to same header");
						// Update Session Panel
						session.getStatusPanel().incrementAmountOfFitleredRequests();
					}
				}
				if(!filtered) {
					stdout.println("INFO: Handle Session: " + session.getName());
					stdout.println("INFO: Modify Request Body");
					String modifiedMessageBody = getModifiedMessageBody(originalMessageBody, originalRequestInfo.getContentType() , session);
					stdout.println("INFO: Modify Request Header");
					// Headers must be modified after Message Body for proper Content-Length update
					ArrayList<String> modifiedHeaders = getModifiedHeaders(originalRequestInfo, session, modifiedMessageBody.length());
					stdout.println("INFO: Create bytestream");
					byte[] message = callbacks.getHelpers().buildHttpMessage(modifiedHeaders, modifiedMessageBody.getBytes());
					// Perform modified request
					stdout.println("INFO: Perform modified request");
					IHttpRequestResponse modifiedMessageInfo = callbacks.makeHttpRequest(originalMessageInfo.getHttpService(), message);
					
					// Analyse Response of modified Request
					if (modifiedMessageInfo.getRequest() != null && modifiedMessageInfo.getResponse() != null) {
						stdout.println("INFO: Verify Response");
						// Extract CSRF Token
						if (!session.getCsrfTokenName().equals("") && session.getManuelCsrfTokenValue().equals("")) {
							stdout.println("INFO: Extract CSRF Token");
							extractCurrentCsrfValue(modifiedMessageInfo, session);
						}
						
						//Extract Rules Values
						extractResponseRuleValues(session, modifiedMessageInfo.getResponse());

						stdout.println("INFO: Analyze if BYPASSED");
						BypassConstants bypassConstant = analyzeResponses(originalMessageInfo, modifiedMessageInfo);
						if (bypassConstant != null) {
							AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(modifiedMessageInfo, bypassConstant);
							session.putRequestResponse(mapId, analyzerRequestResponse);
						}
						else {
							success = false;
							stdout.println("WARNING: Cannot analyze if BYPASSED.");
						}
					}
					else {
						success = false;
						stdout.println("WARNING: Modified Request / Response has null value");
					}
				}
			}
			if(success) {
				config.getTableModel().putNewRequestResponse(mapId, originalMessageInfo);
				stdout.println("INFO: Analyze finished. Request added to Table.");
			}
		}
	}

	//need content-length, header as string
	private ArrayList<String> getModifiedHeaders(IRequestInfo originalRequestInfo, Session session, int bodyLength) {
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
				//Set new header if it not occurs
				if (!headerReplaced) {
					headers.add(headerToReplace);
				}
			}
		}
		//Apply Rules and Update Content-Length
		for (int i = 0; i < headers.size(); i++) {
			if(session.getRules().size() > 0) {
				headers.set(i, applyRulesInHeader(session, headers.get(i)));
			}
			if(headers.get(i).startsWith("Content-Length:")) {
				headers.set(i, "Content-Length: "+ bodyLength);
			}
		}		
		
		// Check for CSRF Token as Query Parameter
		if (session.getCsrfTokenName().toLowerCase().startsWith("remove_token")) {
			String[] csrfSplit = session.getCsrfTokenName().split("#");
			if (csrfSplit.length > 0) {
				//TODO replace in other headers as well
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
		String messageBodyWithAppliedRules = applyRulesInBody(session, originalMessageBody); 
		if(session.getCsrfTokenName().equals("")) {
			return messageBodyWithAppliedRules;
		}
		else {
			String modifiedMessageBody = "";
			// CSRF Remove feature. Syntax remove_token#csrt_token
			if (session.getCsrfTokenName().toLowerCase().startsWith("remove_token")) {
				String[] csrfSplit = session.getCsrfTokenName().split("#");
				if (csrfSplit.length > 0) {
					modifiedMessageBody = messageBodyWithAppliedRules.replace(csrfSplit[1], "dummyparam");
				}
			}
			else {
				if (messageBodyWithAppliedRules.length() > 0) {
					// Check and replace if original csrf value present (request body content type not relevant)
					if(!currentOriginalCsrfValue.equals("") && messageBodyWithAppliedRules.contains(currentOriginalCsrfValue)) {
						modifiedMessageBody = messageBodyWithAppliedRules.replace(currentOriginalCsrfValue, session.getCurrentCsrftTokenValue());
					}
					else if(messageBodyWithAppliedRules.contains(session.getCsrfTokenName())) {
						// Handle Multipart Form Data
						if (contentType == IRequestInfo.CONTENT_TYPE_MULTIPART) {
							String[] splitAtCsrfTokenName = messageBodyWithAppliedRules.split(session.getCsrfTokenName());
							if (splitAtCsrfTokenName.length > 1) {
								String[] csrfTokenValueSplit = splitAtCsrfTokenName[1].split("\\n");
								if (csrfTokenValueSplit.length > 2) {
									String csrfValue = csrfTokenValueSplit[2].split("---")[0].trim();
									modifiedMessageBody = messageBodyWithAppliedRules.replace(csrfValue,
											session.getCurrentCsrftTokenValue());
									;
								}
							}
						} 
						// Handle URL Encoded
						if(contentType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
							String[] params = messageBodyWithAppliedRules.split("&");
							for (String param : params) {
								if (param.split("=")[0].equals(session.getCsrfTokenName())) {
									modifiedMessageBody = messageBodyWithAppliedRules.replace(param,
											session.getCsrfTokenName() + "=" + session.getCurrentCsrftTokenValue());
								}
							}
						}
						// Handle JSON Body
						if(contentType == IRequestInfo.CONTENT_TYPE_JSON) {
							JsonElement jelement = new JsonParser().parse(messageBodyWithAppliedRules);
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
						    	modifiedMessageBody = messageBodyWithAppliedRules.replace(oldCsrfValue, session.getCurrentCsrftTokenValue());
						    }
						}
					}
				}
			}
			if (modifiedMessageBody.equals("")) {
				modifiedMessageBody = messageBodyWithAppliedRules;
			}
			return modifiedMessageBody;
		}
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
				String value = getCsrfTokenValueFromInputField(responseBody, session.getCsrfTokenName());
				session.setCsrfTokenValue(value);
				session.getStatusPanel().updateCsrfTokenValue(value);
			}
			else if (response.getStatedMimeType().equals("JSON") || response.getInferredMimeType().equals("JSON")) {
				String value = getCsrfTokenValueFromJson(responseBody, session.getCsrfTokenName());
				session.setCsrfTokenValue(value);
				session.getStatusPanel().updateCsrfTokenValue(value);
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
	
	private String applyRulesInBody(Session session, String body) {
		if(session.getRules().size() > 0) {
			String messageAsString = body;
			for(Rule rule : session.getRules()) {
				if(rule.getReplacementValue() != null) {
					int beginIndex = messageAsString.indexOf(rule.getReplaceFromString());
					int endIndex = messageAsString.length();
					if(!rule.getReplaceToString().equals("\\n")) {
						endIndex = messageAsString.indexOf(rule.getReplaceToString(), beginIndex);
					}
					if(beginIndex != -1 && endIndex != -1) {
						beginIndex = beginIndex + rule.getReplaceFromString().length();
						messageAsString = messageAsString.substring(0, beginIndex) + rule.getReplacementValue() + messageAsString.substring(endIndex, messageAsString.length());
					}				
				}
			}
			return messageAsString;
		}
		return body;
	}
	
	private String applyRulesInHeader(Session session, String header) {
		if(session.getRules().size() > 0) {
			String messageAsString = header;
			for(Rule rule : session.getRules()) {
				if(rule.getReplacementValue() != null) {
					int beginIndex = messageAsString.indexOf(rule.getReplaceFromString());
					//Apply for every single header. Treat System.lineSeparator() as 'end of string'
					int endIndex = messageAsString.length();
					if(!rule.getReplaceToString().equals("\\n")) {
						endIndex = messageAsString.indexOf(rule.getReplaceToString(), beginIndex);
					}
					if(beginIndex != -1 && endIndex != -1) {
						beginIndex = beginIndex + rule.getReplaceFromString().length();
						messageAsString = messageAsString.substring(0, beginIndex) + rule.getReplacementValue() + messageAsString.substring(endIndex, messageAsString.length());
					}				
				}
			}
			return messageAsString;
		}
		return header;
	}

	private void extractResponseRuleValues(Session session, byte[] response) {
		if(session.getRules().size() > 0) {
			stdout.println("INFO: Extract rule values");
			String messageAsString = new String(response);
			for(Rule rule : session.getRules()) {
				int beginIndex = messageAsString.indexOf(rule.getGrepFromString());
				int endIndex;
				if(rule.getGrepToString().equals("\\n")) {
					endIndex = messageAsString.indexOf("\n", beginIndex);
				}
				else {
					endIndex = messageAsString.indexOf(rule.getGrepToString(), beginIndex);
				}
				if(beginIndex != -1 && endIndex != -1) {
					beginIndex = beginIndex + rule.getGrepFromString().length();
					String value = messageAsString.substring(beginIndex, endIndex);
					rule.setReplacementValue(value);
					session.getStatusPanel().setRuleValue(rule, value);
				}
			}
		}
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
