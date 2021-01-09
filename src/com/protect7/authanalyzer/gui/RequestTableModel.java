package com.protect7.authanalyzer.gui;

import java.util.ArrayList;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 4;
	
	public ArrayList<OriginalRequestResponse> getOriginalRequestResponseList() {
		return originalRequestResponseList;
	}
	
	public synchronized void addNewRequestResponse(OriginalRequestResponse requestResponse) {
		originalRequestResponseList.add(requestResponse);
		final int index = originalRequestResponseList.size()-1;
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				fireTableRowsInserted(index, index);
			}
		});
	}
	
	public boolean isDuplicate(int id, String endpoint) {

		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getEndpoint().equals(endpoint) && requestResponse.getId() < id) {
				return true;
			}
		}
		return false;
	}
	
	public void deleteRequestResponse(final int listIndex) {
		originalRequestResponseList.remove(listIndex);
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				fireTableRowsDeleted(listIndex, listIndex);
			}
		});
	}
	
	public void clearRequestMap() {
		originalRequestResponseList.clear();
		fireTableDataChanged();
	}
	
	public OriginalRequestResponse getOriginalRequestResponse(int listIndex) {
		if(listIndex < originalRequestResponseList.size()) {
			return originalRequestResponseList.get(listIndex);
		}
		else {
			return null;
		}
	}
	
	public OriginalRequestResponse getOriginalRequestResponseById(int id) {
		for(OriginalRequestResponse requestResponse : originalRequestResponseList) {
			if(requestResponse.getId() == id) {
				return requestResponse;
			}
		}
		return null;
	}
	
	@Override
	public int getColumnCount() {
		return STATIC_COLUMN_COUNT + config.getSessions().size();
	}

	@Override
	public int getRowCount() {
		return originalRequestResponseList.size();
	}

	@Override
	public Object getValueAt(int row, int column) {
		if(row >= originalRequestResponseList.size()) {
			return null;
		}
		OriginalRequestResponse originalRequestResponse = originalRequestResponseList.get(row);
		if(column == 0) {
			return originalRequestResponse.getId();
		}
		if(column == 1) {
			return  originalRequestResponse.getMethod();
		}
		if(column == 2) {
			return originalRequestResponse.getHost();
		}
		if(column == 3) {
			return originalRequestResponse.getUrl();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			int tempColunmIndex = STATIC_COLUMN_COUNT+i;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getStatus();
			}
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
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
