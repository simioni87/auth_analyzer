package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.swing.JOptionPane;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.entities.TokenPriority;

import burp.BurpExtender;
import burp.IParameter;
import burp.IRequestInfo;

public class RequestModifHelper {
	
	public static List<String> getModifiedHeaders(List<String> currentHeaders, Session session) {
		List<String> headers = currentHeaders;
		// Check for Parameter Replacement in Path
		replaceParamInPath(headers, session);
		
		if(session.isRemoveHeaders()) {
			String[] headersToRemoveSplit = session.getHeadersToRemove().replace("\r", "").split("\n");
			Iterator<String> iterator = headers.iterator();
			while(iterator.hasNext()) {
				String header = iterator.next();
				for(int i=0; i<headersToRemoveSplit.length; i++) {
					if(header.split(":")[0].equals(headersToRemoveSplit[i].split(":")[0])) {
						iterator.remove();
					}
				}
			}
		}
		for (String headerToReplace : getHeaderToReplaceList(session)) {
			int keyIndex = headerToReplace.indexOf(":");
			if (keyIndex != -1) {
				String headerKey = headerToReplace.substring(0, keyIndex+1);
				boolean headerReplaced = false;
				for (int i = 0; i < headers.size(); i++) {
					if (headers.get(i).startsWith(headerKey)) {
						headers.set(i, headerToReplace);
						headerReplaced = true;
						break;
					}
				}
				// Set new header if it not occurs
				if (!headerReplaced) {
					headers.add(headerToReplace);
				}
			}
		}
		return headers;
	}
	
	private static List<String> replaceParamInPath(List<String> headers, Session session) {
		String pathHeader = headers.get(0);
		for(Token token : session.getTokens()) {
			if(token.getValue() != null && !token.isRemove() && token.doReplaceAtLocation(TokenLocation.PATH)) {
				String tokenInPathName = "/"+token.getName()+"/";
				int startIndex = pathHeader.indexOf(tokenInPathName);
				if(startIndex != -1) {
					startIndex = startIndex + tokenInPathName.length();
					int endIndex = pathHeader.indexOf("/", startIndex);
					if(endIndex != -1) {
						pathHeader = pathHeader.substring(0, startIndex) + token.getValue() + pathHeader.substring(endIndex);
						headers.set(0, pathHeader);
					}
				}
			}
		}
		return headers;
	}
	
	private static ArrayList<String> getHeaderToReplaceList(Session session) {
		ArrayList<String> headerToReplaceList = new ArrayList<String>();
		String[] headersToReplace = session.getHeadersToReplace().replace("\r", "").split("\n");
		for (String headerToReplace : headersToReplace) {
			String[] headerKeyValuePair = headerToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				for (Token token : session.getTokens()) {
					if (headerToReplace.contains(token.getHeaderInsertionPointNameStart())) {
						int startIndex = headerToReplace.indexOf(token.getHeaderInsertionPointNameStart());
						int endIndex = headerToReplace.indexOf("]§", startIndex) + 2;
						if (startIndex != -1 && endIndex != -1) {
							if (token.getValue() != null) {
								headerToReplace = headerToReplace.substring(0, startIndex)
										+ token.getValue() + headerToReplace.substring(endIndex);
							} else {
								String defaultValue = headerToReplace.substring(
										startIndex + token.getHeaderInsertionPointNameStart().length() + 1,
										endIndex - 2);
								headerToReplace = headerToReplace.substring(0, startIndex) + defaultValue
										+ headerToReplace.substring(endIndex);
							}
						}
					}
				}
				headerToReplaceList.add(headerToReplace);
			}
		}
		return headerToReplaceList;
	}
	
	public static byte[] getModifiedRequest(byte[] originalRequest, Session session, TokenPriority tokenPriority) {
		IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequest);
		byte[] modifiedRequest = originalRequest;
		for (Token token : session.getTokens()) {
			if (token.getValue() != null || token.isRemove() || token.isPromptForInput()) {
				modifiedRequest = getModifiedRequest(modifiedRequest, originalRequestInfo, session, token, tokenPriority);
			}
		}
		return modifiedRequest;
	}
	
	private static byte[] getModifiedRequest(byte[] request, IRequestInfo originalRequestInfo, Session session, Token token, TokenPriority tokenPriority) {
		byte[] modifiedRequest = request;
		for (IParameter parameter : originalRequestInfo.getParameters()) {
			if (parameter.getName().equals(token.getName())) {
				String paramLocation = null;
				// Helper can only handle URL, COOKIE and BODY Parameters
				if (parameter.getType() == IParameter.PARAM_URL) {
					if(token.doReplaceAtLocation(TokenLocation.URL)) {
						paramLocation = "URL";
					}
				}
				if (parameter.getType() == IParameter.PARAM_COOKIE) {
					if(token.doReplaceAtLocation(TokenLocation.COOKIE)) {
						paramLocation = "Cookie";
					}
				}
				if (parameter.getType() == IParameter.PARAM_BODY) {
					if(token.doReplaceAtLocation(TokenLocation.BODY)) {
						paramLocation = "Body";
					}
				}
				// Handle JSON as well (self implemented)
				if (parameter.getType() == IParameter.PARAM_JSON) {
					if(token.doReplaceAtLocation(TokenLocation.JSON)) {
						paramLocation = "Json";
					}
				}
				if (paramLocation != null) {
					if (token.isPromptForInput()) {
						String paramValue = JOptionPane.showInputDialog(session.getStatusPanel(),
								"<html><strong>Auth Analyzer</strong><br>" + "Enter Parameter Value<br>Session: "
										+ session.getName() + "<br>Parameter Name: " + token.getName() + "<br>"
										+ "Parameter Location: " + paramLocation + "<br></html>");
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
							modifiedRequest = BurpExtender.callbacks.getHelpers().removeParameter(modifiedRequest, parameter);
						}
					} else if (token.getValue() != null) {
						tokenPriority.setPriority(tokenPriority.getPriority() + 1);;
						if (parameter.getType() == IParameter.PARAM_JSON) {
							modifiedRequest = getModifiedJsonRequest(request, originalRequestInfo, token);
						} else {
							IParameter modifiedParameter = BurpExtender.callbacks.getHelpers().buildParameter(token.getName(),
									token.getValue(), parameter.getType());
							modifiedRequest = BurpExtender.callbacks.getHelpers().updateParameter(modifiedRequest,
									modifiedParameter);
						}
					}
				}
			}
		}
		return modifiedRequest;
	}
	
	private static byte[] getModifiedJsonRequest(byte[] request, IRequestInfo originalRequestInfo, Token token) {
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
			BurpExtender.callbacks.printError("Can not parse JSON Request Body. Error Message: " + e.getMessage());
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
		byte[] modifiedRequest = BurpExtender.callbacks.getHelpers().buildHttpMessage(headers, jsonBody.getBytes());
		return modifiedRequest;
	}
	
	private static void modifyJsonTokenValue(JsonElement jsonElement, Token token) {
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
}
