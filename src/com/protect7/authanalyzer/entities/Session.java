 package com.protect7.authanalyzer.entities;

import java.net.URL;

/**
 * This Entity holds a session.
 * 
 * @author Simon Reinhart
 */

import java.util.ArrayList;
import java.util.HashMap;
import com.google.gson.ExclusionStrategy;
import com.google.gson.FieldAttributes;
import com.protect7.authanalyzer.gui.entity.StatusPanel;

public class Session {

	private final String name;
	private String headersToReplace;
	private String headersToRemove;
	private boolean removeHeaders;
	private boolean filterRequestsWithSameHeader;
	private boolean restrictToScope = false;
	private boolean testCors = false;
	private URL scopeUrl;
	private int tabbedPaneRequestIndex;
	private int tabbedPaneResponseIndex;
	private final HashMap<Integer, AnalyzerRequestResponse> requestResponseMap = new HashMap<>();
	private ArrayList<Token> tokens = new ArrayList<Token>();
	private ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
	private final StatusPanel statusPanel;

	public Session(String name, String headersToReplace, boolean removeHeaders, String headersToRemove, boolean filterRequestsWithSameHeader, boolean restrictToScope, 
			URL scopeUrl, boolean testCors, ArrayList<Token> tokens, ArrayList<MatchAndReplace> matchAndReplaceList, StatusPanel statusPanel) {
		this.name = name;
		this.removeHeaders = removeHeaders;
		this.headersToReplace = headersToReplace;
		this.filterRequestsWithSameHeader = filterRequestsWithSameHeader;
		this.setRestrictToScope(restrictToScope);
		this.setTestCors(testCors);
		this.headersToRemove = headersToRemove;
		this.setScopeUrl(scopeUrl);
		this.setTokens(tokens);
		this.matchAndReplaceList = matchAndReplaceList;
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
				if(field.getDeclaringClass() == Token.class && field.getName().equals("request")) {
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

	public boolean isRestrictToScope() {
		return restrictToScope;
	}

	public void setRestrictToScope(boolean restrictToScope) {
		this.restrictToScope = restrictToScope;
	}

	public URL getScopeUrl() {
		return scopeUrl;
	}

	public void setScopeUrl(URL scopeUrl) {
		this.scopeUrl = scopeUrl;
	}
	
	public Token getTokenByName(String tokenName) {
		for(Token token : tokens) {
			if(token.getName().equals(tokenName)) {
				return token;
			}
		}
		return null;
	}

	public boolean isRemoveHeaders() {
		return removeHeaders;
	}

	public void setRemoveHeaders(boolean removeHeaders) {
		this.removeHeaders = removeHeaders;
	}

	public String getHeadersToRemove() {
		return headersToRemove;
	}

	public void setHeadersToRemove(String headersToRemove) {
		this.headersToRemove = headersToRemove;
	}

	public boolean isTestCors() {
		return testCors;
	}

	public void setTestCors(boolean testCors) {
		this.testCors = testCors;
	}

	public ArrayList<MatchAndReplace> getMatchAndReplaceList() {
		return matchAndReplaceList;
	}
	
	public void setMatchAndReplaceList(ArrayList<MatchAndReplace> matchAndReplaceList) {
		this.matchAndReplaceList = matchAndReplaceList;
	}
}
