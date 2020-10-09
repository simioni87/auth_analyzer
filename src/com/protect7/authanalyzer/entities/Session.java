package com.protect7.authanalyzer.entities;

import java.util.ArrayList;
import java.util.HashMap;

import com.protect7.authanalyzer.gui.StatusPanel;

public class Session {

	private final String name;
	private final String headersToReplace;
	private final String csrfTokenName;
	private final String manuelCsrfTokenValue;
	private int tabbedPaneRequestIndex;
	private int tabbedPaneResponseIndex;
	private String csrfTokenValue = "";
	private final boolean filterRequestsWithSameHeader;
	private final ArrayList<Rule> rules;
	private HashMap<Integer, AnalyzerRequestResponse> requestResponseMap = new HashMap<>();
	private final StatusPanel statusPanel;

	public Session(String name, String headersToReplace, String csrfTokenToReplace, String csrfTokenValue, 
			boolean filterRequestsWithSameHeader, ArrayList<Rule> rules, StatusPanel statusPanel) {
		this.name = name;
		this.headersToReplace = headersToReplace;
		this.csrfTokenName = csrfTokenToReplace;
		this.manuelCsrfTokenValue = csrfTokenValue;
		this.filterRequestsWithSameHeader = filterRequestsWithSameHeader;
		this.rules = rules;
		this.statusPanel = statusPanel;
	}

	public String getName() {
		return name;
	}

	public String getHeadersToReplace() {
		return headersToReplace;
	}

	public String getCsrfTokenName() {
		return csrfTokenName;
	}

	public String getCurrentCsrftTokenValue() {
		if (!getManuelCsrfTokenValue().equals("")) {
			return getManuelCsrfTokenValue();
		} else {
			return csrfTokenValue;
		}
	}

	public void setCsrfTokenValue(String csrfTokenValue) {
		this.csrfTokenValue = csrfTokenValue;
	}

	public String getManuelCsrfTokenValue() {
		return manuelCsrfTokenValue;
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

	public ArrayList<Rule> getRules() {
		return rules;
	}

	public StatusPanel getStatusPanel() {
		return statusPanel;
	}
}
