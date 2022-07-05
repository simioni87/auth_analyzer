package com.protect7.authanalyzer.gui.util;

import java.util.ArrayList;
import java.util.EnumSet;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

public class RequestTableModel extends AbstractTableModel {

	private static final long serialVersionUID = 1L;
	private final ArrayList<OriginalRequestResponse> originalRequestResponseList = new ArrayList<OriginalRequestResponse>();
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final int STATIC_COLUMN_COUNT = 7;
	
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
	
	public void deleteRequestResponse(OriginalRequestResponse requestResponse) {
		originalRequestResponseList.remove(requestResponse);
		SwingUtilities.invokeLater(new Runnable() {			
			@Override
			public void run() {
				fireTableDataChanged();
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
		return STATIC_COLUMN_COUNT + (config.getSessions().size()*4);
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
		int tempColunmIndex = 4;
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
		if(column == 4) {
			return originalRequestResponse.getStatusCode();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getStatusCode();
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getResponseContentLength();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getResponseContentLength();
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				int lengthDiff = originalRequestResponse.getResponseContentLength() - 
				config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getResponseContentLength();
				return lengthDiff;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getRequestResponseMap().get(originalRequestResponse.getId()).getStatus();
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return originalRequestResponse.getComment();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public String getColumnName(int column) {
		int tempColunmIndex = 4;
		if(column == 0) {
			return Column.ID.toString();
		}
		if(column == 1) {
			return  Column.Method.toString();
		}
		if(column == 2) {
			return Column.Host.toString();
		}
		if(column == 3) {
			return Column.Path.toString();
		}
		if(column == 4) {
			return Column.Code.toString();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Code;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Length.toString();
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Length;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Diff;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(column == tempColunmIndex) {
				return config.getSessions().get(i).getName() + " " + Column.Status;
			}
		}
		tempColunmIndex++;
		if(column == tempColunmIndex) {
			return Column.Comment.toString();
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + column);
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		int tempColunmIndex = 4;
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
		if(columnIndex == 4) {
			return Integer.class;
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return Integer.class;
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return Integer.class;
			}
		}
		for(int i=0; i<config.getSessions().size(); i++) {
			tempColunmIndex++;
			if(columnIndex == tempColunmIndex) {
				return BypassConstants.class;
			}
		}
		tempColunmIndex++;
		if(columnIndex == tempColunmIndex) {
			return String.class;
		}
		throw new IndexOutOfBoundsException("Column index out of bounds: " + columnIndex);
	}
	
	public enum Column {
		ID, Method, Host, Path, Code, Length, Diff, Status, Comment;
		
		public static EnumSet<Column> getDefaultSet() {
			return EnumSet.of(ID, Method, Host, Path, Status);
		}
		
	}
}
