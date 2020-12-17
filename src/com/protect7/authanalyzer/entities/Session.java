 package com.protect7.authanalyzer.entities;

/**
 * This Entity holds a session.
 * 
 * @author Simon Reinhart
 */

import java.util.ArrayList;
import java.util.HashMap;

import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.protect7.authanalyzer.gui.StatusPanel;

public class Session {

	private final String name;
	private String headersToReplace;
	private boolean filterRequestsWithSameHeader;
	private int tabbedPaneRequestIndex;
	private int tabbedPaneResponseIndex;
	private HashMap<Integer, AnalyzerRequestResponse> requestResponseMap = new HashMap<>();
	private ArrayList<Token> tokens = new ArrayList<Token>();
	private final StatusPanel statusPanel;

	public Session(String name, String headersToReplace, boolean filterRequestsWithSameHeader, ArrayList<Token> tokens, StatusPanel statusPanel) {
		this.name = name;
		this.headersToReplace = headersToReplace;
		this.filterRequestsWithSameHeader = filterRequestsWithSameHeader;
		this.setTokens(tokens);
		this.statusPanel = statusPanel;
	}

	public String getName() {
		return name;
	}

	public String getHeadersToReplace() {
		return headersToReplace;
	}
	
	public void setHeadersToReplace(String headersToReplace) {
		this.headersToReplace = headersToReplace;
	}

	public HashMap<Integer, AnalyzerRequestResponse> getRequestResponseMap() {
		return requestResponseMap;
	}

	public void putRequestResponse(int key, AnalyzerRequestResponse requestResponse) {
		requestResponseMap.put(key, requestResponse);
	}

	public void clearRequestResponseMap() {
		requestResponseMap.clear();
	}

	public int getTabbedPaneRequestIndex() {
		return tabbedPaneRequestIndex;
	}

	public void setTabbedPaneRequestIndex(int tabbedPaneRequestIndex) {
		this.tabbedPaneRequestIndex = tabbedPaneRequestIndex;
	}

	public int getTabbedPaneResponseIndex() {
		return tabbedPaneResponseIndex;
	}

	public void setTabbedPaneResponseIndex(int tabbedPaneResponseIndex) {
		this.tabbedPaneResponseIndex = tabbedPaneResponseIndex;
	}

	public boolean isFilterRequestsWithSameHeader() {
		return filterRequestsWithSameHeader;
	}
	
	public void setFilterRequestsWithSameHeader(boolean filterRequestsWithSameHeader) {
		this.filterRequestsWithSameHeader = filterRequestsWithSameHeader;
	}

	public StatusPanel getStatusPanel() {
		return statusPanel;
	}

	public ArrayList<Token> getTokens() {
		return tokens;
	}

	public void setTokens(ArrayList<Token> tokens) {
		this.tokens = tokens;
	}
	
	public ExclusionStrategy getExclusionStrategy() {
		ExclusionStrategy strategy = new ExclusionStrategy() {
			
			@Override
			public boolean shouldSkipField(FieldAttributes field) {
				if(field.getDeclaringClass() == Session.class && field.getName().equals("tabbedPaneRequestIndex")) {
					return true;
				}
				if(field.getDeclaringClass() == Session.class && field.getName().equals("tabbedPaneResponseIndex")) {
					return true;
				}
				if(field.getDeclaringClass() == Session.class && field.getName().equals("requestResponseMap")) {
					return true;
				}
				if(field.getDeclaringClass() == Session.class && field.getName().equals("statusPanel")) {
					return true;
				}
				return false;
			}
			
			@Override
			public boolean shouldSkipClass(Class<?> clazz) {
				return false;
			}
		};
		return strategy;
	}
}
