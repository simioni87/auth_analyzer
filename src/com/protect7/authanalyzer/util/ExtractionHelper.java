package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenBuilder;
import com.protect7.authanalyzer.entities.TokenLocation;
import burp.BurpExtender;
import burp.ICookie;
import burp.IHttpRequestResponse;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class ExtractionHelper {

	public static boolean extractCurrentTokenValue(byte[] sessionResponse, IResponseInfo sessionResponseInfo, Token token) {
		if(token.doAutoExtractAtLocation(AutoExtractLocation.COOKIE)) {
			for (ICookie cookie : sessionResponseInfo.getCookies()) {
				if (cookie.getName().equals(token.getExtractName())) {
					token.setValue(cookie.getValue());
					return true;
				}
			}
		}
		if (token.doAutoExtractAtLocation(AutoExtractLocation.HTML) && (sessionResponseInfo.getStatedMimeType().equals("HTML")
				|| sessionResponseInfo.getInferredMimeType().equals("HTML"))) {
			try {
				String bodyAsString = new String(Arrays.copyOfRange(sessionResponse,
						sessionResponseInfo.getBodyOffset(), sessionResponse.length));
				String value = getTokenValueFromInputField(bodyAsString, token.getExtractName());
				if (value != null) {
					token.setValue(value);
					return true;
				}
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Can not parse HTML Response. Error Message: " + e.getMessage());
			}
		}
		if (token.doAutoExtractAtLocation(AutoExtractLocation.JSON) && (sessionResponseInfo.getStatedMimeType().equals("JSON")
				|| sessionResponseInfo.getInferredMimeType().equals("JSON"))) {
			JsonElement jsonElement = getBodyAsJson(sessionResponse, sessionResponseInfo);
			if(jsonElement != null) {
				String value = getJsonTokenValue(jsonElement, token);
				if (value != null) {
					token.setValue(value);
					return true;
				}
			}
		}
		return false;
	}

	public static String getTokenValueFromInputField(String document, String name) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", name);
		for(Element element : csrfFields) {
			String csrfValue = element.attr("value");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
			csrfValue = element.attr("content");
			if(csrfValue != null && !csrfValue.equals("")) {
				return csrfValue;
			}
		}
		return null;
	}

	public static boolean extractTokenWithFromToString(byte[] sessionResponse, IResponseInfo responseInfo, Token token) {
		try {
			boolean doExtract = token.doFromToExtractAtLocation(FromToExtractLocation.ALL);
			for(FromToExtractLocation locationType : FromToExtractLocation.values()) {
				if(locationType != FromToExtractLocation.ALL && locationType != FromToExtractLocation.HEADER && locationType != FromToExtractLocation.BODY) {
					if (token.doFromToExtractAtLocation(locationType) && (responseInfo.getStatedMimeType().toUpperCase().equals(locationType.toString())
							|| responseInfo.getInferredMimeType().toUpperCase().equals(locationType.toString()))) {
						doExtract = true;
						break;
					}
				}
			}
			//Do extract per default if stated and interfered MIME Type can not be evaluated (e.g. redirect response without body content)
			if(responseInfo.getInferredMimeType().equals("") && responseInfo.getStatedMimeType().equals("")) {
				doExtract = true;
			}
			if(doExtract) {
				String responseAsString = null;
				if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = new String(sessionResponse);
				}
				else if(token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && !token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = new String(Arrays.copyOfRange(sessionResponse, 0, responseInfo.getBodyOffset()));
				}
				else if(!token.doFromToExtractAtLocation(FromToExtractLocation.HEADER) && token.doFromToExtractAtLocation(FromToExtractLocation.BODY)) {
					responseAsString = new String(Arrays.copyOfRange(sessionResponse, responseInfo.getBodyOffset(), sessionResponse.length));
				}
				if(responseAsString != null) {
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
							return true;
						}
					}
				}
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Can not extract from to value. Error Message: " + e.getMessage());
		}
		return false;
	}
	
	private static String getJsonTokenValue(JsonElement jsonElement, Token token) {
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
	
	private static JsonElement getBodyAsJson(byte[] response, IResponseInfo responseInfo) {
		try {
			String bodyAsString = new String(Arrays.copyOfRange(response,
					responseInfo.getBodyOffset(), response.length));
			JsonReader reader = new JsonReader(new StringReader(bodyAsString));
			reader.setLenient(true);
			JsonElement jsonElement = JsonParser.parseReader(reader);
			return jsonElement;
		} catch (Exception e) {
			BurpExtender.callbacks.printError("Can not parse JSON Response. Error Message: " + e.getMessage());
		}
		return null;
	}
	
	public static ArrayList<Token> extractTokensFromMessages(IHttpRequestResponse[] messages) {
		HashMap<String, Token> tokenMap = new HashMap<String, Token>();
		String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
		String[] dynamicPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_DYNAMIC_PATTERNS);
		for(IHttpRequestResponse message : messages) {
			if(message.getRequest() != null) {
				IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message.getRequest());
				for(IParameter param : requestInfo.getParameters()) {
					boolean process = false;
					boolean isDynamic = false;
					for(String pattern : staticPatterns) {
						if(param.getName().toLowerCase().contains(pattern)) {
							process = true;
							break;
						}
					}
					for(String pattern : dynamicPatterns) {
						if(param.getName().toLowerCase().contains(pattern)) {
							process = true;
							isDynamic = true;
							break;
						}
					}
					if(process) {
						boolean autoExtract = isDynamic;
						if(tokenMap.containsKey(param.getName())) {
							autoExtract = tokenMap.get(param.getName()).isAutoExtract();
						}
						Token token = null;
						String urlDecodedName;
						try {
							urlDecodedName = URLDecoder.decode(param.getName(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedName = param.getName();
						}
						String urlDecodedValue;
						try {
							urlDecodedValue = URLDecoder.decode(param.getValue(), StandardCharsets.UTF_8.toString());
						} catch (UnsupportedEncodingException e) {
							urlDecodedValue = param.getValue();
						}
						if(param.getType() == IParameter.PARAM_COOKIE) {
							// Create Token with dynamic value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
									.setValue(param.getValue())
									.setExtractName(param.getName())
									.setIsAutoExtract(true)
									.build();
						}
						if(param.getType() == IParameter.PARAM_URL) {
							// Create Token with static value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.URL))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(param.getType() == IParameter.PARAM_BODY) {
							// Create Token with static value
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.BODY))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.HTML))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(param.getType() == IParameter.PARAM_JSON) {
							token = new TokenBuilder()
									.setName(urlDecodedName)
									.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
									.setValue(urlDecodedValue)
									.setExtractName(urlDecodedName)
									.setIsAutoExtract(autoExtract)
									.setIsStaticValue(!autoExtract)
									.build();
						}
						if(token != null) {
							tokenMap.put(token.getName(), token);
						}
					}
				}
			}
			if(message.getResponse() != null) {
				IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(message.getResponse());
				for(ICookie cookie : responseInfo.getCookies()) {
					Token token = new TokenBuilder()
							.setName(cookie.getName())
							.setTokenLocationSet(EnumSet.of(TokenLocation.COOKIE))
							.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.COOKIE))
							.setExtractName(cookie.getName())
							.setIsAutoExtract(true)
							.build();
					tokenMap.put(token.getName(), token);
				}
				if(responseInfo.getStatedMimeType().equals("JSON")	|| responseInfo.getInferredMimeType().equals("JSON")) {
					JsonElement jsonElement = getBodyAsJson(message.getResponse(), responseInfo);
					if(jsonElement != null) {
						createTokensFromJson(jsonElement, tokenMap);
					}
				}
			}
		}
		ArrayList<Token> tokenList = new ArrayList<Token>(tokenMap.values());
		tokenList.sort(Comparator.comparing(Token::sortString));
		return tokenList;
	}
	
	private static void createTokensFromJson(JsonElement jsonElement, HashMap<String, Token> tokenMap) {
		if (jsonElement.isJsonObject()) {
			JsonObject jsonObject = jsonElement.getAsJsonObject();
			for (Map.Entry<String, JsonElement> entry : jsonObject.entrySet()) {
				if (entry.getValue().isJsonArray() || entry.getValue().isJsonObject()) {
					createTokensFromJson(jsonElement, tokenMap);
				}
				if (entry.getValue().isJsonPrimitive()) {
					String[] staticPatterns = Setting.getValueAsArray(Setting.Item.AUTOSET_PARAM_STATIC_PATTERNS);
					for(String pattern : staticPatterns) {
						if(entry.getKey().toLowerCase().contains(pattern)) {
							Token token = new TokenBuilder()
									.setName(entry.getKey())
									.setTokenLocationSet(EnumSet.of(TokenLocation.JSON))
									.setAutoExtractLocationSet(EnumSet.of(AutoExtractLocation.JSON))
									.setExtractName(entry.getKey())
									.setIsAutoExtract(true)
									.build();
							tokenMap.put(token.getName(), token);
							break;
						}
					}
				}
			}
		}
		if (jsonElement.isJsonArray()) {
			for (JsonElement arrayJsonEl : jsonElement.getAsJsonArray()) {
				if (arrayJsonEl.isJsonObject()) {
					createTokensFromJson(jsonElement, tokenMap);
				}
			}
		}
	}
}
