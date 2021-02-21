package com.protect7.authanalyzer.util;

import java.net.MalformedURLException;
import java.net.URL;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.RequestFilter;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

public class DataStorageProvider {

	private static final String SITEMAP_HOST = "authanalyzer.storage.local";
	private static final String SETTINGS_PATH = "/settings";
	private static final IHttpService HTTPSERVICE = BurpExtender.callbacks.getHelpers().buildHttpService(SITEMAP_HOST, 443, true);
	
	public static String getSetupAsJsonString() {
		JsonArray sessionArray = new JsonArray();
		for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
			Gson gson = new GsonBuilder().setExclusionStrategies(session.getExclusionStrategy()).create();
			String sessionJsonAsString = gson.toJson(session);
			JsonObject sessionElement = JsonParser.parseString(sessionJsonAsString).getAsJsonObject();
			sessionElement.addProperty("name", session.getName());
			sessionArray.add(sessionElement);
		}

		JsonObject sessionsObject = new JsonObject();
		sessionsObject.add("sessions", sessionArray);

		JsonArray filterArray = new JsonArray();
		for (RequestFilter filter : CurrentConfig.getCurrentConfig().getRequestFilterList()) {
			JsonObject filterElement = JsonParser.parseString(filter.toJson()).getAsJsonObject();
			filterArray.add(filterElement);
		}
		sessionsObject.add("filters", filterArray);
		return sessionsObject.toString();
	}
	
	public static void saveSetup() {	
		BurpExtender.callbacks.addToSiteMap(getSettingsMessage());
	}
	
	public static String loadSetup() {
		IHttpRequestResponse[] messages = BurpExtender.callbacks.getSiteMap(HTTPSERVICE.toString() + SETTINGS_PATH);
		if(messages.length > 0) {
			try {
				String setup = new String(messages[0].getResponse());
				return setup;
			}
			catch (Exception e) {
				return null;
			}
		}
		return null;
	}
	
	public static void saveMessage(int id, String session, IHttpRequestResponse message) {
		
	}
	
	public IHttpRequestResponse loadMessage(int id, String session) {
		return null;
	}
	
	private static IHttpRequestResponse getSettingsMessage() {
		URL url = null;
		try {
			url = new URL(HTTPSERVICE.getProtocol(), HTTPSERVICE.getHost(), HTTPSERVICE.getPort(), SETTINGS_PATH);
		} catch (MalformedURLException e) {
			return null;
		}
		byte[] request = BurpExtender.callbacks.getHelpers().buildHttpRequest(url);
		IHttpRequestResponse message = new IHttpRequestResponse() {
			
			@Override
			public void setResponse(byte[] message) {}
			
			@Override
			public void setRequest(byte[] message) {}
			
			@Override
			public void setHttpService(IHttpService httpService) {}
			
			@Override
			public void setHighlight(String color) {}
			
			@Override
			public void setComment(String comment) {}
			
			@Override
			public byte[] getResponse() {
				return getSetupAsJsonString().getBytes();
			}
			
			@Override
			public byte[] getRequest() {
				return request;
			}
			
			@Override
			public IHttpService getHttpService() {
				return HTTPSERVICE;
			}
			
			@Override
			public String getHighlight() {
				return null;
			}
			
			@Override
			public String getComment() {
				return null;
			}
		};
		return message;
	}
}