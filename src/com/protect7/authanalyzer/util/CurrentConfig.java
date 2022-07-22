package com.protect7.authanalyzer.util;

import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import com.protect7.authanalyzer.controller.RequestController;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.util.RequestTableModel;

import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class CurrentConfig {

	private static CurrentConfig mInstance = new CurrentConfig();
	//private final String[] patternsStatic = {"token", "code", "user", "mail", "pass", "key", "csrf", "xsrf"};
	//private final String[] patternsDynamic = {"viewstate", "eventvalidation"};
	private final int POOL_SIZE_MIN = 1; 
	private final RequestController requestController = new RequestController();
	private ThreadPoolExecutor analyzerThreadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(POOL_SIZE_MIN);
	private ArrayList<RequestFilter> requestFilterList = new ArrayList<>();
	private ArrayList<Session> sessions = new ArrayList<>();
	private RequestTableModel tableModel = null;
	private boolean running = false;
	private boolean dropOriginal = false;
	private volatile int mapId = 0;
	private boolean respectResponseCodeForSameStatus = true;
	private boolean respectResponseCodeForSimilarStatus = true; 
	private int deviationForSimilarStatus = 5;
	private long delayBetweenRequestsInMilliseconds = 0;

	private CurrentConfig() {
	}
	
	public void performAuthAnalyzerRequest(IHttpRequestResponse messageInfo) {
		analyzerThreadExecutor.execute(new Runnable() {				
			@Override
			public void run() {
				BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(
						analyzerThreadExecutor.getQueue().size());
				getRequestController().analyze(messageInfo);
				try {
					Thread.sleep(delayBetweenRequestsInMilliseconds);
				} catch (InterruptedException e) {
					e.printStackTrace();
				}
			}
		});
		BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(
				analyzerThreadExecutor.getQueue().size());
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
			respectResponseCodeForSameStatus = Setting.getValueAsBoolean(Setting.Item.STATUS_SAME_RESPONSE_CODE);
			respectResponseCodeForSimilarStatus = Setting.getValueAsBoolean(Setting.Item.STATUS_SIMILAR_RESPONSE_CODE);
			deviationForSimilarStatus = Setting.getValueAsInteger(Setting.Item.STATUS_SIMILAR_RESPONSE_LENGTH);
			delayBetweenRequestsInMilliseconds = Setting.getValueAsInteger(Setting.Item.DELAY_BETWEEN_REQUESTS);
			if(hasPromptForInput() && Setting.getValueAsBoolean(Setting.Item.ONLY_ONE_THREAD_IF_PROMT_FOR_INPUT)) {
				//Set POOL Size to 1 --> if prompt for input dialog appears no further requests will be repeated until dialog is closed
				analyzerThreadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(POOL_SIZE_MIN);
			}
			else {
				int numberOfThreads = Setting.getValueAsInteger(Setting.Item.NUMBER_OF_THREADS);
				analyzerThreadExecutor = (ThreadPoolExecutor) Executors.newFixedThreadPool(numberOfThreads);
			}
		}
		else {
			analyzerThreadExecutor.shutdownNow();
			BurpExtender.mainPanel.getCenterPanel().updateAmountOfPendingRequests(0);
		}
		this.running = running;
	}

	private boolean hasPromptForInput() {
		for(Session session : sessions) {
			for(Token token : session.getTokens()) {
				if(token.isPromptForInput()) {
					return true;
				}
			}
		}
		return false;
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

	public boolean isRespectResponseCodeForSameStatus() {
		return respectResponseCodeForSameStatus;
	}

	public void setRespectResponseCodeForSameStatus(boolean respectResponseCodeForSameStatus) {
		this.respectResponseCodeForSameStatus = respectResponseCodeForSameStatus;
	}

	public boolean isRespectResponseCodeForSimilarStatus() {
		return respectResponseCodeForSimilarStatus;
	}

	public void setRespectResponseCodeForSimilarFlag(boolean respectResponseCodeForSimilarStatus) {
		this.respectResponseCodeForSimilarStatus = respectResponseCodeForSimilarStatus;
	}

	public int getDerivationForSimilarStatus() {
		return deviationForSimilarStatus;
	}

	public void setDerivationForSimilarStatus(int derivationForSimilarStatus) {
		this.deviationForSimilarStatus = derivationForSimilarStatus;
	}	
}