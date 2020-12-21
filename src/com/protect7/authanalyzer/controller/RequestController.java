package com.protect7.authanalyzer.controller;

import java.io.StringReader;

/**
 * The RequestController processes each HTTP message which is not previously rejected due to filter specification. The RequestController
 * extracts the defined values (CSRF Token and Grep Rules) and modifies the given HTTP Message for each session. Furthermore, the
 * RequestController is responsible for analyzing the response and declare the BYPASS status according to the specified definitions.
 * 
 * @author Simon Reinhart
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import javax.swing.JOptionPane;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class RequestController {

	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final IBurpExtenderCallbacks callbacks = BurpExtender.callbacks;

	public synchronized void analyze(IHttpRequestResponse originalRequestResponse) {
		
		// Fail-Safe - Check if messageInfo can be processed
		if (originalRequestResponse == null || originalRequestResponse.getRequest() == null
				|| originalRequestResponse.getResponse() == null) {
			callbacks.printError("Cannot analyze request with null values.");
		} else {
			int mapId = config.getNextMapId();
			boolean success = true;
			IRequestInfo originalRequestInfo = callbacks.getHelpers().analyzeRequest(originalRequestResponse);
			for (Session session : config.getSessions()) {
				if (session.isFilterRequestsWithSameHeader()
						&& isSameHeader(originalRequestInfo.getHeaders(), session)) {
					// No other session will be analyzed if one session has same header. The
					// assumption is that the given request was send
					// automatically by the application the user was navigating through. We do not
					// want to
					// analyze such a request.
					success = false;
					break;
				} else {
					// Handle Session
					byte[] modifiedRequest = originalRequestResponse.getRequest();
					for (Token token : session.getTokens()) {
						if (token.getValue() != null || token.isRemove() || token.isPromptForInput()) {
							modifiedRequest = getModifiedRequest(modifiedRequest, originalRequestInfo, session, token);
						}
					}
					// Analyze modifiedRequest
					IRequestInfo modifiedRequestInfo = callbacks.getHelpers().analyzeRequest(modifiedRequest);
					byte[] modifiedMessageBody = Arrays.copyOfRange(modifiedRequest,
							modifiedRequestInfo.getBodyOffset(), modifiedRequest.length);

					List<String> modifiedHeaders = getModifiedHeaders(modifiedRequestInfo.getHeaders(), session);

					byte[] message = callbacks.getHelpers().buildHttpMessage(modifiedHeaders, modifiedMessageBody);

					// Perform modified request
					IHttpRequestResponse sessionRequestResponse = callbacks
							.makeHttpRequest(originalRequestResponse.getHttpService(), message);

					IResponseInfo sessionResponseInfo = callbacks.getHelpers()
							.analyzeResponse(sessionRequestResponse.getResponse());
					// Analyze Response of modified Request
					if (sessionRequestResponse.getRequest() != null && sessionRequestResponse.getResponse() != null) {
						// Extract Token Values if applicable
						for (Token token : session.getTokens()) {
							if (token.isAutoExtract()) {
								extractCurrentTokenValue(sessionRequestResponse.getResponse(), sessionResponseInfo,
										token);
								session.getStatusPanel().updateTokenStatus(token);
							}
							if (token.isFromToString()) {
								extractTokenWithFromToString(sessionRequestResponse.getResponse(), token);
								session.getStatusPanel().updateTokenStatus(token);
							}
						}
						IResponseInfo originalResponseInfo = callbacks.getHelpers()
								.analyzeResponse(originalRequestResponse.getResponse());
						BypassConstants bypassConstant = analyzeResponse(originalRequestResponse.getResponse(),
								sessionRequestResponse.getResponse(), originalResponseInfo, sessionResponseInfo);
						AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
								sessionRequestResponse, bypassConstant);
						session.putRequestResponse(mapId, analyzerRequestResponse);
					} else {
						// Fail-Safe
						success = false;
						callbacks.printError("Modified Request / Response has null value");
						break;
					}
				}
			}
			if (success) {
				String url = "";
				if(originalRequestInfo.getUrl().getQuery() == null) {
					url = originalRequestInfo.getUrl().getPath();
				}
				else {
					url = originalRequestInfo.getUrl().getPath() + "?" + originalRequestInfo.getUrl().getQuery();
				}
				OriginalRequestResponse requestResponse = new OriginalRequestResponse(mapId, originalRequestResponse, originalRequestInfo.getMethod(), url);
				config.getTableModel().addNewRequestResponse(requestResponse);
			}
		}
	}

	public boolean isSameHeader(List<String> headers, Session session) {
		String[] headersToReplace = session.getHeadersToReplace().split("\n");
		boolean requestContainsHeader = true;
		for (String headerToReplace : headersToReplace) {
			if (!headers.contains(headerToReplace)) {
				requestContainsHeader = false;
			}
		}
		if (requestContainsHeader) {
			// Update Session Panel
			session.getStatusPanel().incrementAmountOfFitleredRequests();
			return true;
		}
		return false;
	}

	// need content-length, header as string
	public List<String> getModifiedHeaders(List<String> headers, Session session) {
		for (String headerToReplace : getHeaderToReplaceList(session)) {
			String trimmedHeaderToReplace = headerToReplace.trim();
			String[] headerKeyValuePair = trimmedHeaderToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				String headerKey = headerKeyValuePair[0].trim();
				boolean headerReplaced = false;
				for (int i = 0; i < headers.size(); i++) {
					if (headers.get(i).startsWith(headerKey)) {
						headers.set(i, trimmedHeaderToReplace);
						headerReplaced = true;
						break;
					}
				}
				// Set new header if it not occurs
				if (!headerReplaced) {
					headers.add(trimmedHeaderToReplace);
				}
			}
		}
		return headers;
	}

	private ArrayList<String> getHeaderToReplaceList(Session session) {
		ArrayList<String> headerToReplaceList = new ArrayList<String>();
		String[] headersToReplace = session.getHeadersToReplace().replace("\r", "").split("\n");
		for (String headerToReplace : headersToReplace) {
			String trimmedHeaderToReplace = headerToReplace.trim();
			String[] headerKeyValuePair = trimmedHeaderToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				for (Token token : session.getTokens()) {
					if (trimmedHeaderToReplace.contains(token.getHeaderInsertionPointNameStart())) {
						int startIndex = trimmedHeaderToReplace.indexOf(token.getHeaderInsertionPointNameStart());
						int endIndex = trimmedHeaderToReplace.indexOf("]§", startIndex) + 2;
						if (startIndex != -1 && endIndex != -1) {
							if (token.getValue() != null) {
								trimmedHeaderToReplace = trimmedHeaderToReplace.substring(0, startIndex)
										+ token.getValue() + trimmedHeaderToReplace.substring(endIndex);
								//headerToReplaceList.add(modifiedHeader);
							} else {
								String defaultValue = trimmedHeaderToReplace.substring(
										startIndex + token.getHeaderInsertionPointNameStart().length() + 1,
										endIndex - 2);
								trimmedHeaderToReplace = trimmedHeaderToReplace.substring(0, startIndex) + defaultValue
										+ trimmedHeaderToReplace.substring(endIndex);
								//headerToReplaceList.add(modifiedHeader);
							}
						}
					}
				}
				headerToReplaceList.add(trimmedHeaderToReplace);
			}
		}
		return headerToReplaceList;
	}

	public byte[] getModifiedRequest(byte[] request, IRequestInfo originalRequestInfo, Session session, Token token) {
		byte[] modifiedRequest = request;
		for (IParameter parameter : originalRequestInfo.getParameters()) {
			if (parameter.getName().equals(token.getName())) {
				String paramLocationText = null;
				// Helper can only handle URL, COOKIE and BODY Parameters
				if (parameter.getType() == IParameter.PARAM_URL) {
					paramLocationText = "URL";
				}
				if (parameter.getType() == IParameter.PARAM_COOKIE) {
					paramLocationText = "Cookie";
				}
				if (parameter.getType() == IParameter.PARAM_BODY) {
					paramLocationText = "Body";
				}
				// Handle JSON as well (self implemented)
				if (parameter.getType() == IParameter.PARAM_JSON) {
					paramLocationText = "Json";
				}
				if (paramLocationText != null) {
					if (token.isPromptForInput()) {
						String paramValue = JOptionPane.showInputDialog(session.getStatusPanel(),
								"<html><strong>Auth Analyzer</strong><br>" + "Enter Parameter Value<br>Session: "
										+ session.getName() + "<br>Parameter Name: " + token.getName() + "<br>"
										+ "Parameter Location: " + paramLocationText + "<br></html>");
						if (paramValue != null) {
							token.setValue(paramValue);
							session.getStatusPanel().updateTokenStatus(token);
						} else {
							token.setValue("");
						}
					}
					if (token.isRemove()) {
						if (parameter.getType() == IParameter.PARAM_JSON) {
							modifiedRequest = getModifiedJsonRequest(request, originalRequestInfo, token);
						} else {
							modifiedRequest = callbacks.getHelpers().removeParameter(modifiedRequest, parameter);
						}
					} else if (token.getValue() != null) {
						if (parameter.getType() == IParameter.PARAM_JSON) {
							modifiedRequest = getModifiedJsonRequest(request, originalRequestInfo, token);
						} else {
							IParameter modifiedParameter = callbacks.getHelpers().buildParameter(token.getName(),
									token.getValue(), parameter.getType());
							modifiedRequest = callbacks.getHelpers().updateParameter(modifiedRequest,
									modifiedParameter);
						}
					}
				}
			}
		}
		return modifiedRequest;
	}

	private byte[] getModifiedJsonRequest(byte[] request, IRequestInfo originalRequestInfo, Token token) {
		if (!token.isRemove() && token.getValue() == null) {
			return request;
		}
		JsonElement jsonElement = null;
		try {
			String bodyAsString = new String(
					Arrays.copyOfRange(request, originalRequestInfo.getBodyOffset(), request.length));
			JsonReader reader = new JsonReader(new StringReader(bodyAsString));
			reader.setLenient(true);
			jsonElement = JsonParser.parseReader(reader);
		} catch (Exception e) {
			callbacks.printError("Can not parse JSON Request Body. Error Message: " + e.getMessage());
			return request;
		}
		modifyJsonTokenValue(jsonElement, token);
		String jsonBody = jsonElement.toString();
		List<String> headers = originalRequestInfo.getHeaders();
		for (int i = 0; i < headers.size(); i++) {
			if (headers.get(i).startsWith("Content-Length:")) {
				headers.set(i, "Content-Length: " + jsonBody.length());
			}
		}
		byte[] modifiedRequest = callbacks.getHelpers().buildHttpMessage(headers, jsonBody.getBytes());
		return modifiedRequest;
	}

	private void modifyJsonTokenValue(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			Iterator<Map.Entry<String, JsonElement>> it = jsonObject.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, JsonElement> entry = it.next();
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					modifyJsonTokenValue(entry.getValue(), token);
				}
				if (entry.getValue().isJsonPrimitive()) {
					if (entry.getKey().equals(token.getName())) {
						if (token.isRemove()) {
							jsonObject.remove(entry.getKey());
						} else {
							jsonObject.addProperty(entry.getKey(), token.getValue());
						}
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonObject()) {
					modifyJsonTokenValue(arrayJsonEl.getAsJsonObject(), token);
				}
			}
		}
	}

	private String getJsonTokenValue(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					return getJsonTokenValue(entry.getValue(), token);
				}
				if (entry.getValue().isJsonPrimitive()) {
					if (entry.getKey().equals(token.getExtractName())) {
						return entry.getValue().getAsString();
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonObject()) {
					return getJsonTokenValue(arrayJsonEl.getAsJsonObject(), token);
				}
			}
		}
		return null;
	}

	public void extractCurrentTokenValue(byte[] sessionResponse, IResponseInfo sessionResponseInfo, Token token) {
		boolean extractedFromCookie = false;
		for (ICookie cookie : sessionResponseInfo.getCookies()) {
			if (cookie.getName().equals(token.getExtractName())) {
				token.setValue(cookie.getValue());
				extractedFromCookie = true;
				break;
			}
		}
		if (!extractedFromCookie) {
			if (sessionResponseInfo.getStatedMimeType().equals("HTML")
					|| sessionResponseInfo.getInferredMimeType().equals("HTML")) {
				try {
					String bodyAsString = new String(Arrays.copyOfRange(sessionResponse,
							sessionResponseInfo.getBodyOffset(), sessionResponse.length));
					String value = getTokenValueFromInputField(bodyAsString, token.getExtractName());
					if (value != null) {
						token.setValue(value);
					}
				} catch (Exception e) {
					callbacks.printError("Can not parse HTML Response. Error Message: " + e.getMessage());
				}
			}
			if (sessionResponseInfo.getStatedMimeType().equals("JSON")
					|| sessionResponseInfo.getInferredMimeType().equals("JSON")) {
				try {
					String bodyAsString = new String(Arrays.copyOfRange(sessionResponse,
							sessionResponseInfo.getBodyOffset(), sessionResponse.length));
					JsonReader reader = new JsonReader(new StringReader(bodyAsString));
					reader.setLenient(true);
					JsonElement jsonElement = JsonParser.parseReader(reader);
					String value = getJsonTokenValue(jsonElement, token);
					if (value != null) {
						token.setValue(value);
					}
				} catch (Exception e) {
					callbacks.printError("Can not parse JSON Response. Error Message: " + e.getMessage());
				}
			}
		}
	}

	public String getTokenValueFromInputField(String document, String name) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", name);
		if (csrfFields.size() > 0) {
			String csrfValue = csrfFields.get(0).attr("value");
			return csrfValue;
		}
		return null;
	}

	public void extractTokenWithFromToString(byte[] sessionResponse, Token token) {
		try {
			String responseAsString = new String(sessionResponse);
			int beginIndex = responseAsString.indexOf(token.getGrepFromString());
			if (beginIndex != -1) {
				beginIndex = beginIndex + token.getGrepFromString().length();
				// Only single lines in extraction scope
				String lineWithValue = responseAsString.substring(beginIndex).split("\n")[0];
				String value = null;
				if (token.getGrepToString().equals("")) {
					value = lineWithValue;
				} else {
					if (lineWithValue.contains(token.getGrepToString())) {
						value = lineWithValue.substring(0, lineWithValue.indexOf(token.getGrepToString()));
					}
				}
				if (value != null) {
					token.setValue(value);
				}
			}
		} catch (Exception e) {
			callbacks.printError("Can not extract from to value. Error Message: " + e.getMessage());
		}
	}

	/*
	 * Bypass if: - Both Responses have same Response Body and Status Code
	 * 
	 * Potential Bypass if: - Both Responses have same Response Code - Both
	 * Responses have +-5% of response body length
	 *
	 */
	public BypassConstants analyzeResponse(byte[] originalResponse, byte[] sessionResponse,
			IResponseInfo originalResponseInfo, IResponseInfo sessionResponseInfo) {
		byte[] originalResponseBody = Arrays.copyOfRange(originalResponse, originalResponseInfo.getBodyOffset(),
				originalResponse.length);
		byte[] sessionResponseBody = Arrays.copyOfRange(sessionResponse, sessionResponseInfo.getBodyOffset(),
				sessionResponse.length);
		if (Arrays.equals(originalResponseBody, sessionResponseBody)
				&& (originalResponseInfo.getStatusCode() == sessionResponseInfo.getStatusCode())) {
			return BypassConstants.BYPASSED;
		}
		if (originalResponseInfo.getStatusCode() == sessionResponseInfo.getStatusCode()) {
			int range = originalResponseBody.length / 20; // calc 5% of response length
			int difference = originalResponseBody.length - sessionResponseBody.length;
			// Check if difference is in range
			if (difference <= range && difference >= -range) {
				return BypassConstants.POTENTIAL_BYPASSED;
			}
		}
		return BypassConstants.NOT_BYPASSED;
	}
}
