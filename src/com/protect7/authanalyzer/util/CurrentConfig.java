package com.protect7.authanalyzer.util;

import java.util.ArrayList;

import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.RequestTableModel;

public class CurrentConfig {

	private static CurrentConfig mInstance = new CurrentConfig();
	private ArrayList<RequestFilter> requestFilterList = new ArrayList<>();
	private ArrayList<Session> sessions = new ArrayList<>();
	private RequestTableModel tableModel = null;
	private boolean running = false;
	

	public static synchronized CurrentConfig getCurrentConfig(){
		  return mInstance;
	}
	
	public void addRequestFilter(RequestFilter requestFilter) {
		getRequestFilterList().add(requestFilter);
	}

	public boolean isRunning() {
		return running;
	}

	public void setRunning(boolean running) {
		this.running = running;
	}


	public ArrayList<RequestFilter> getRequestFilterList() {
		return requestFilterList;
	}
	
	public RequestFilter getRequestFilterAt(int index) {
		return requestFilterList.get(index);
	}

	public ArrayList<Session> getSessions() {
		return sessions;
	}

	public void addSession(Session session) {
		sessions.add(session);
	}

	public void clearSessionList() {
		sessions.clear();
	}

	public RequestTableModel getTableModel() {
		return tableModel;
	}

	public void setTableModel(RequestTableModel tableModel) {
		this.tableModel = tableModel;
	}
	
	public void clearSessionRequestMaps() {
		for(Session session : getSessions()) {
			session.clearRequestResponseMap();
		}
	}

}
