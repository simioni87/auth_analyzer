package com.protect7.authanalyzer.entities;

/**
 * This Entity holds a session.
 * 
 * @author Simon Reinhart
 */

import java.util.ArrayList;
import java.util.HashMap;

import com.protect7.authanalyzer.gui.StatusPanel;

public class Session {

	private final String name;
	private String headersToReplace;
	private String csrfTokenName;
	private String staticCsrfTokenValue;
	private int tabbedPaneRequestIndex;
	private int tabbedPaneResponseIndex;
	private String csrfTokenValue = "";
	private boolean filterRequestsWithSameHeader;
	private ArrayList<Rule> rules;
	private HashMap<Integer, AnalyzerRequestResponse> requestResponseMap = new HashMap<>();
	private final StatusPanel statusPanel;

	public Session(String name, String headersToReplace, String csrfTokenToReplace, String csrfTokenValue, 
			boolean filterRequestsWithSameHeader, ArrayList<Rule> rules, StatusPanel statusPanel) {
		this.name = name;
		this.headersToReplace = headersToReplace;
		this.csrfTokenName = csrfTokenToReplace;
		this.staticCsrfTokenValue = csrfTokenValue;
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
	
	public void setHeadersToReplace(String headersToReplace) {
		this.headersToReplace = headersToReplace;
	}

	public String getCsrfTokenName() {
		return csrfTokenName;
	}

	public void setCsrfTokenName(String csrfTokenName) {
		this.csrfTokenName = csrfTokenName;
	}
	
	public String getCurrentCsrftTokenValue() {
		if (!getStaticCsrfTokenValue().equals("")) {
			return getStaticCsrfTokenValue();
		} else {
			return csrfTokenValue;
		}
	}

	public void setCsrfTokenValue(String csrfTokenValue) {
		this.csrfTokenValue = csrfTokenValue;
	}

	public String getStaticCsrfTokenValue() {
		return staticCsrfTokenValue;
	}
	
	public void setStaticCsrfTokenValue(String staticCsrfTokenValue) {
		this.staticCsrfTokenValue = staticCsrfTokenValue;
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

	public ArrayList<Rule> getRules() {
		return rules;
	}
	
	public void setRules(ArrayList<Rule> rules) {
		this.rules = rules;
	}

	public StatusPanel getStatusPanel() {
		return statusPanel;
	}
}
