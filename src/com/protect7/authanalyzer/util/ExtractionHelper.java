package com.protect7.authanalyzer.util;

import java.io.StringReader;
import java.util.Arrays;
import java.util.Map;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.select.Elements;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.stream.JsonReader;
import com.protect7.authanalyzer.entities.Token;

import burp.BurpExtender;
import burp.ICookie;
import burp.IResponseInfo;

public class ExtractionHelper {

	public static boolean extractCurrentTokenValue(byte[] sessionResponse, IResponseInfo sessionResponseInfo, Token token) {
		for (ICookie cookie : sessionResponseInfo.getCookies()) {
			if (cookie.getName().equals(token.getExtractName())) {
				token.setValue(cookie.getValue());
				return true;
			}
		}
		if (sessionResponseInfo.getStatedMimeType().equals("HTML")
				|| sessionResponseInfo.getInferredMimeType().equals("HTML")) {
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
					return true;
				}
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Can not parse JSON Response. Error Message: " + e.getMessage());
			}
		}
		return false;
	}

	public static String getTokenValueFromInputField(String document, String name) {
		Document doc = Jsoup.parse(document);
		Elements csrfFields = doc.getElementsByAttributeValue("name", name);
		if (csrfFields.size() > 0) {
			String csrfValue = csrfFields.get(0).attr("value");
			return csrfValue;
		}
		return null;
	}

	public static boolean extractTokenWithFromToString(byte[] sessionResponse, Token token) {
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
					return true;
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
}
