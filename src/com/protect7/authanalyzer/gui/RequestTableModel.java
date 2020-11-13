package com.protect7.authanalyzer.gui;

import java.io.PrintWriter;
import java.util.HashMap;
import javax.swing.table.AbstractTableModel;

import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.Logger;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final IBurpExtenderCallbacks callbacks;
	private HashMap<Integer, IHttpRequestResponse> originalRequestResponseMap = new HashMap<>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 4;

	public RequestTableModel(IBurpExtenderCallbacks callbacks) {
		this.callbacks = callbacks;
	}
	
	public void putNewRequestResponse(int key, IHttpRequestResponse requestResponse) {
		originalRequestResponseMap.put(key, requestResponse);
		//fireTableRowsInserted(getRowCount(), getRowCount());
		fireTableDataChanged();
	}
	
	public void clearRequestMap() {
		originalRequestResponseMap.clear();
		fireTableDataChanged();
	}
	
	public IHttpRequestResponse getOriginalRequestResponse(int value) {
		return originalRequestResponseMap.get(value);
	}

	@Override
	public int getColumnCount() {
		return STATIC_COLUMN_COUNT + config.getSessions().size();
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseMap.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		int mapKey = getMapKeyByIndex(row);
		if(!originalRequestResponseMap.containsKey(mapKey)) {
			PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
			Logger.getLogInstance(stdout).writeLog(Logger.SEVERITY.INFO, "Cannot find map key!");
			stdout.close();
			return null;
		}
		else {
			IHttpRequestResponse messageInfoOriginal = originalRequestResponseMap.get(mapKey);
			
			IRequestInfo request = callbacks.getHelpers().analyzeRequest(messageInfoOriginal);
			if(column == 0) {
				return mapKey;
			}
			if(column == 1) {
				return  request.getMethod();
			}
			if(column == 2) {
				return messageInfoOriginal.getHttpService().getHost();
			}
			if(column == 3) {
				if(request.getUrl().getQuery() == null) {
					return request.getUrl().getPath();
				}
				else {
					return request.getUrl().getPath() + "?" + request.getUrl().getQuery();
				}
			}
			for(int i=0; i<config.getSessions().size(); i++) {
				int tempColunmIndex = STATIC_COLUMN_COUNT+i;
				if(column == tempColunmIndex) {
					return config.getSessions().get(i).getRequestResponseMap().get(mapKey).getStatus();
				}
			}
			throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
		}
	}
	
	private Integer getMapKeyByIndex(int index) {
		Object[] keyArray = originalRequestResponseMap.keySet().toArray();
		if(keyArray.length > index) {
			return (Integer) keyArray[index];
		}
		else {
			return -1;
		}
	}

	@Override
	public String getColumnName(int column) {
		if(column == 0) {
			return "ID";
		}
		if(column == 1) {
			return  "Method";
		}
		if(column == 2) {
			return "Host";
		}
		if(column == 3) {
			return "Path";
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			int tempColunmIndex = STATIC_COLUMN_COUNT+i;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName();
			}
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		if(columnIndex == 0) {
			return Integer.class;
		}
		if(columnIndex == 1) {
			return String.class;
		}
		if(columnIndex == 2) {
			return String.class;
		}
		if(columnIndex == 3) {
			return String.class;
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			int tempColunmIndex = STATIC_COLUMN_COUNT+i;
			if(columnIndex == tempColunmIndex) {
				return BypassConstants.class;
			}
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
	}
}
