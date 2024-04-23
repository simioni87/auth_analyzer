package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.swing.JLabel;
import javax.swing.JOptionPane;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.MatchAndReplace;
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
		
		if(session.isTestCors()) {
			setOptionsMethod(headers);
		}
			
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
	
	private static void replaceParamInPath(List<String> headers, Session session) {
		int paramIndex = headers.get(0).indexOf("?");
		String pathHeader;
		String appendix = "";
		if(paramIndex != -1) {
			pathHeader = headers.get(0).substring(0, paramIndex);
			appendix = headers.get(0).substring(paramIndex);
		}
		else {
			pathHeader = headers.get(0);
		}
		for(Token token : session.getTokens()) {
			if(token.getValue() != null && !token.isRemove() && token.doReplaceAtLocation(TokenLocation.PATH)) {
				String tokenInPathName = "/"+token.getName()+"/";
				int startIndex;
				if(token.isCaseSensitiveTokenName()) {
					startIndex = pathHeader.indexOf(tokenInPathName);
				}
				else {
					startIndex = pathHeader.toLowerCase().indexOf(tokenInPathName.toLowerCase());
				}
				if(startIndex != -1) {
					startIndex = startIndex + tokenInPathName.length();
					int endIndex = 99999;
					String[] delims = {"/", " ", ";"};
					for(String delim : delims) {
						int delimIndex = pathHeader.indexOf(delim, startIndex);
						if(delimIndex != -1 && (delimIndex < endIndex)) {
							endIndex = delimIndex;
						}
					}
					if(endIndex == 99999 && !appendix.equals("")) {
						endIndex = pathHeader.length();
					}
					if(endIndex != 99999) {
						pathHeader = pathHeader.substring(0, startIndex) + token.getValue() + pathHeader.substring(endIndex);
						headers.set(0, pathHeader + appendix);
					}
				}
				// Check for URL path parameters (semicolon syntax)
				String urlPathParameter = ";" + token.getName() + "=";
				int startIndex1 = pathHeader.indexOf(urlPathParameter);
				if(token.isCaseSensitiveTokenName()) {
					startIndex1 = pathHeader.indexOf(urlPathParameter);
				}
				else {
					startIndex1 = pathHeader.toLowerCase().indexOf(urlPathParameter.toLowerCase());
				}
				if(startIndex1 != -1) {
					startIndex1 = startIndex1 + urlPathParameter.length();
					int endIndex1 = pathHeader.indexOf(";", startIndex1);
					if(endIndex1 == -1) {
						// Path Header was divided at '?' therefore endIndex is end of string of path header
						endIndex1 = pathHeader.length();
					}
					if(endIndex1 != -1) {
						pathHeader = pathHeader.substring(0, startIndex1) + token.getValue() + pathHeader.substring(endIndex1);
						headers.set(0, pathHeader + appendix);
					}
				}
				
			}
		}
	}
	
	private static void setOptionsMethod(List<String> headers) {
		int methodIndex = headers.get(0).indexOf(" ");
		if(methodIndex != -1) {
			String header = "OPTIONS" + headers.get(0).substring(methodIndex);
			headers.set(0, header);
		}
	}
	
	private static ArrayList<String> getHeaderToReplaceList(Session session) {
		HashMap<String, String> headerToReplaceMap = new HashMap<String, String>();
		String[] headersToReplace = session.getHeadersToReplace().replace("\r", "").split("\n");
		for (String headerToReplace : headersToReplace) {
			String[] headerKeyValuePair = headerToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				headerToReplaceMap.put(headerKeyValuePair[0], headerToReplace);
			}
		}
		
		for (String headerToReplace : headersToReplace) {
			String[] headerKeyValuePair = headerToReplace.split(":");
			if (headerKeyValuePair.length > 1) {
				String headerKey = headerKeyValuePair[0];
				for (Token token : session.getTokens()) {
					if (headerToReplace.contains(token.getHeaderInsertionPointName())) {
						int startIndex = headerToReplace.indexOf(token.getHeaderInsertionPointName());
						int endIndex = headerToReplace.indexOf(Globals.INSERTION_POINT_IDENTIFIER, startIndex + Globals.INSERTION_POINT_IDENTIFIER.length()) 
								+ Globals.INSERTION_POINT_IDENTIFIER.length();
						if (startIndex != -1 && endIndex != -1) {
							if (token.getValue() != null) {
								headerToReplace = headerToReplace.substring(0, startIndex)
										+ token.getValue() + headerToReplace.substring(endIndex);
								headerToReplaceMap.put(headerKey, headerToReplace);
							}
						}
					}
				}
				if(!headerToReplaceMap.containsKey(headerKey)) {
					headerToReplaceMap.put(headerKey, headerToReplace);
				}
			}
		}
		ArrayList<String> headerToReplaceList = new ArrayList<String>();
		for(String headerKey : headerToReplaceMap.keySet()) {
			headerToReplaceList.add(headerToReplaceMap.get(headerKey));
		}
		return headerToReplaceList;
	}
	
	public static byte[] getModifiedRequest(byte[] originalRequest, Session session, TokenPriority tokenPriority) {
		IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequest);
		byte[] modifiedRequest = applyMatchesAndReplaces(session, originalRequest);
		for (Token token : session.getTokens()) {
			if (token.getValue() != null || token.isRemove() || token.isPromptForInput()) {
				modifiedRequest = getModifiedRequest(modifiedRequest, originalRequestInfo, session, token, tokenPriority);
			}
		}
		return modifiedRequest;
	}
	
	private static byte[] applyMatchesAndReplaces(Session session, byte[] request) {
		if(session.getMatchAndReplaceList().size() > 0) {
			try {
				String requestAsString = new String(request);
				for(MatchAndReplace matchAndReplace : session.getMatchAndReplaceList()) {
					int endIndex = requestAsString.indexOf(matchAndReplace.getMatch());
					while(endIndex != -1) {
						requestAsString = requestAsString.substring(0, endIndex) + matchAndReplace.getReplace() 
						+ requestAsString.substring(endIndex + matchAndReplace.getMatch().length(), requestAsString.length());
						endIndex = requestAsString.indexOf(matchAndReplace.getMatch(), endIndex);
					}
				}
				return requestAsString.getBytes();
			}
			catch (Exception e) {
				BurpExtender.callbacks.printError("Cannot apply match and replaces");
			}
		}	
		return request; 
	}
	
	private static byte[] getModifiedRequest(byte[] request, IRequestInfo originalRequestInfo, Session session, Token token, TokenPriority tokenPriority) {
		byte[] modifiedRequest = request;
		boolean tokenExists = false;
		for (IParameter parameter : originalRequestInfo.getParameters()) {
			// check if alias
			boolean isAlias = false;
			String[] aliases = token.getAliases().split(",");
			for(String alias : aliases){
				if(parameter.getName().equals(alias.trim())){
					isAlias = true;
					break;
				}
			}

			//Wildcard Replace for standard GET and POST if token name equals '*' and has static replace
			if(token.getName().equals("*") && token.isStaticValue() && (parameter.getType() == IParameter.PARAM_URL || parameter.getType() == IParameter.PARAM_BODY)) {
				IParameter modifiedParameter = BurpExtender.callbacks.getHelpers().buildParameter(parameter.getName(),
						token.getValue(), parameter.getType());
				modifiedRequest = BurpExtender.callbacks.getHelpers().updateParameter(modifiedRequest,
						modifiedParameter);
			}
			//Continue with standard procedure
			if (parameter.getName().equals(token.getName()) || parameter.getName().equals(token.getUrlEncodedName()) ||
					(!token.isCaseSensitiveTokenName() && parameter.getName().toLowerCase().equals(token.getName().toLowerCase())) || isAlias) {
				tokenExists = true;
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
				// Handle JSON as well (self implemented --> Burp API update parameter does not work for JSON)
				if (parameter.getType() == IParameter.PARAM_JSON) {
					if(token.doReplaceAtLocation(TokenLocation.JSON)) {
						paramLocation = "Json";
					}
				}
				if (paramLocation != null) {
					if (token.isPromptForInput()) {
						JLabel message = new JLabel("<html><strong>"+Globals.EXTENSION_NAME+"</strong><br>" + "Enter Parameter Value<br>Session: "
								+ session.getName() + "<br>Parameter Name: " + token.getName() + "<br>"
								+ "Parameter Location: " + paramLocation + "<br></html>");
						message.putClientProperty("html.disable", null);
						String paramValue = JOptionPane.showInputDialog(session.getStatusPanel(), message);
						token.setValue(paramValue);
						session.getStatusPanel().updateTokenStatus(token);
					}
					if (token.isRemove()) {
						if (parameter.getType() == IParameter.PARAM_JSON) {
							modifiedRequest = getModifiedJsonRequest(request, originalRequestInfo, token);
						} else {
							modifiedRequest = BurpExtender.callbacks.getHelpers().removeParameter(modifiedRequest, parameter);
						}
					} else if (token.getValue() != null) {
						tokenPriority.setPriority(tokenPriority.getPriority() + 1);
						if (parameter.getType() == IParameter.PARAM_JSON) {
							modifiedRequest = getModifiedJsonRequest(request, originalRequestInfo, token);
						} else {
							String parameterValue = token.getValue();
							IParameter modifiedParameter = BurpExtender.callbacks.getHelpers().buildParameter(parameter.getName(),
									parameterValue, parameter.getType());
							modifiedRequest = BurpExtender.callbacks.getHelpers().updateParameter(modifiedRequest,
									modifiedParameter);
						}
					}
				}
			}
		}
		if(!tokenExists && token.isAddIfNotExists()) {
			//Check type
			byte requestType = originalRequestInfo.getContentType();
			Byte parameterType = IParameter.PARAM_URL;
			if(requestType == IRequestInfo.CONTENT_TYPE_NONE || requestType == IRequestInfo.CONTENT_TYPE_UNKNOWN) {
				parameterType = IParameter.PARAM_URL;
			}
			else if(requestType == IRequestInfo.CONTENT_TYPE_MULTIPART || requestType == IRequestInfo.CONTENT_TYPE_URL_ENCODED) {
				parameterType = IParameter.PARAM_BODY;
			}
			else if(requestType == IRequestInfo.CONTENT_TYPE_JSON) {
				return getModifiedJsonRequest(modifiedRequest, originalRequestInfo, token);
			}
			IParameter newParameter = BurpExtender.callbacks.getHelpers().buildParameter(token.getUrlEncodedName(),
					token.getValue(), parameterType);
			modifiedRequest = BurpExtender.callbacks.getHelpers().addParameter(modifiedRequest, newParameter);
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
		boolean modified = modifyJsonTokenValue(jsonElement, token);
		if(!modified && token.isAddIfNotExists()) {
			addJsonToken(jsonElement, token);
		}
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
	
	private static boolean modifyJsonTokenValue(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			Iterator<Map.Entry<String, JsonElement>> it = jsonObject.entrySet().iterator();
			while (it.hasNext()) {
				Map.Entry<String, JsonElement> entry = it.next();
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					modifyJsonTokenValue(entry.getValue(), token);
				}
				if (entry.getValue().isJsonPrimitive()) {
					if (entry.getKey().equals(token.getName()) || 
							(!token.isCaseSensitiveTokenName() && entry.getKey().toLowerCase().equals(token.getName().toLowerCase()))) {
						if (token.isRemove()) {
							jsonObject.remove(entry.getKey());
						} else {
							putJsonValue(jsonObject, entry.getKey(), token);
						}
						return true;
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
		return false;
	}
	
	private static void addJsonToken(JsonElement jsonElement, Token token) {
		if (jsonElement.isJsonObject()) {
			putJsonValue(jsonElement.getAsJsonObject(), token.getName(), token);
		}
	}
	
	private static void putJsonValue(JsonObject jsonObject, String key, Token token) {
		if(token.getValue().toLowerCase().equals("true") || token.getValue().toLowerCase().equals("false")) {
			jsonObject.addProperty(key, Boolean.parseBoolean(token.getValue().toLowerCase()));
		}
		else if(token.getValue().toLowerCase().equals("null")) {
			jsonObject.add(key, JsonNull.INSTANCE);
		}
		else if(isInt(token.getValue())) {
			jsonObject.addProperty(key, Integer.parseInt(token.getValue()));
		}
		else {
			jsonObject.addProperty(key, token.getValue());
		}
	}
	
	private static boolean isInt(String value) {
		try {
			Integer.parseInt(value);
			return true;
		}
		catch (Exception e) {
			return false;
		}
	}
}
