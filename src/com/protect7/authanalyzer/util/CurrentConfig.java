package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.RequestTableModel;

import burp.IHttpRequestResponse;

public class CurrentConfig {

	private static CurrentConfig mInstance = new CurrentConfig();
	private final RequestController requestController = new RequestController();
	private ThreadPoolExecutor analyzerThreadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);
	private ArrayList<RequestFilter> requestFilterList = new ArrayList<>();
	private ArrayList<Session> sessions = new ArrayList<>();
	private RequestTableModel tableModel = null;
	private boolean running = false;
	private boolean dropOriginal = false;
	private volatile int mapId = 0;

	private CurrentConfig() {
	}
	
	public void performAuthAnalyzerRequest(IHttpRequestResponse messageInfo) {
		analyzerThreadExecutor.execute(new Runnable() {				
			@Override
			public void run() {
				getRequestController().analyze(messageInfo);
			}
		});
	}
	
	public static CurrentConfig getCurrentConfig(){
		  return mInstance;
	}
	
	public void addRequestFilter(RequestFilter requestFilter) {
		getRequestFilterList().add(requestFilter);
	}

	public boolean isRunning() {
		return running;
	}

	public void setRunning(boolean running) {
		if(running) {		
			analyzerThreadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(10);
		}
		else {
			analyzerThreadExecutor.shutdownNow();
		}
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
	
	public int getNextMapId() {
		mapId++;
		return mapId;
	}
	
	public void setDropOriginal(boolean dropOriginal) {
		this.dropOriginal = dropOriginal;
	}
	
	public boolean isDropOriginal() {
		return dropOriginal;
	}
	
	//Returns session with corresponding name. Returns null if session not exists
	public Session getSessionByName(String name) {
		for(Session session : sessions) {
			if(session.getName().equals(name)) {
				return session;
			}
		}
		return null;
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

	public ThreadPoolExecutor getAnalyzerThreadExecutor() {
		return analyzerThreadExecutor;
	}

	public RequestController getRequestController() {
		return requestController;
	}	
}
