package com.protect7.authanalyzer.gui;

import java.io.PrintWriter;
import java.util.HashMap;
import javax.swing.table.AbstractTableModel;

import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.st;

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
		fireTableDataChanged();
	}
	
	public int getFullMapSize() {
		return originalRequestResponseMap.size();
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
		if (originalRequestResponseMap.size() > row) {
			IHttpRequestResponse messageInfoOriginal = originalRequestResponseMap.get(row+1);
			IRequestInfo request = null;
			if(messageInfoOriginal != null) {
				request = callbacks.getHelpers().analyzeRequest(messageInfoOriginal.getRequest());
			}
			else {
				PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
				stdout.println("ERROR: Cannot find map key: " + row+1 + ". Avaliable Key Sets: ");
				for(Integer key :originalRequestResponseMap.keySet()) {
					stdout.println(key);
				}
				stdout.close();
				return null;
			}
			if(column == 0) {
				return row + 1;
			}
			if(column == 1) {
				return  request.getMethod();
			}
			if(column == 2) {
				return messageInfoOriginal.getHost();
			}
			if(column == 3) {
				if(messageInfoOriginal.getUrl().getQuery() == null) {
					return messageInfoOriginal.getUrl().getPath();
				}
				else {
					return messageInfoOriginal.getUrl().getPath()+"?"+messageInfoOriginal.getUrl().getQuery();
				}
			}
			for(int i=0; i<config.getSessions().size(); i++) {
				int tempColunmIndex = STATIC_COLUMN_COUNT+i;
				if(column == tempColunmIndex) {
					return config.getSessions().get(i).getRequestResponseMap().get(row+1).getStatus();
				}
			}
			throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
		}
		throw new IndexOutOfBoundsException("Row index out of bounds: " + row);
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
				return config.getSessions().get(i).getName() + " Status";
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
