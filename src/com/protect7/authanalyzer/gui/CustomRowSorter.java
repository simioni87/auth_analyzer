package com.protect7.authanalyzer.gui;

import java.util.ArrayList;
import java.util.Collections;
import javax.swing.JCheckBox;
import javax.swing.RowFilter;
import javax.swing.RowSorter;
import javax.swing.SortOrder;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.RowSorterListener;
import javax.swing.table.TableRowSorter;

import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;

public class CustomRowSorter extends TableRowSorter<RequestTableModel> {
	
	private final ArrayList<String> entryList = new ArrayList<String>();

	public CustomRowSorter(RequestTableModel tableModel, JCheckBox showOnlyMarked, JCheckBox showDuplicates, JCheckBox showBypassed, 
			JCheckBox showPotentialBypassed, JCheckBox showNotBypassed) {
		super(tableModel);
		showOnlyMarked.addActionListener(e -> tableModel.fireTableDataChanged());
		showDuplicates.addActionListener(e -> tableModel.fireTableDataChanged());
		showBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showPotentialBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		showNotBypassed.addActionListener(e -> tableModel.fireTableDataChanged());
		setMaxSortKeys(1);
        setSortKeys(Collections.singletonList(new RowSorter.SortKey(0, SortOrder.DESCENDING)));
		
		
		RowFilter<Object, Object> filter = new RowFilter<Object, Object>() {
			
			public boolean include(Entry<?, ?> entry) {
				if(showOnlyMarked.isSelected()) {
					OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponseById(Integer.parseInt(entry.getStringValue(0)));
					if(requestResponse != null && !requestResponse.isMarked()) {
						return false;
					}
				}
				if(!showDuplicates.isSelected()) {
					String endpoint = entry.getStringValue(1).toString() + entry.getStringValue(2).toString() 
							+ entry.getStringValue(3).toString();	
					if(tableModel.isDuplicate(Integer.parseInt(entry.getStringValue(0)), endpoint)) {
						return false;
					}
				}
				if(showBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getValue(i).equals(BypassConstants.BYPASSED)) {
							return true;
						}
					}
				}
				if(showPotentialBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getValue(i).equals(BypassConstants.POTENTIAL_BYPASSED)) {
							return true;
						}
					}
				}
				if(showNotBypassed.isSelected()) {
					for(int i = entry.getValueCount()-1; i>3; i--) {
						if(entry.getValue(i).equals(BypassConstants.NOT_BYPASSED)) {
							return true;
						}
					}
				}
				return false;
			}
		};
		
		setRowFilter(filter);
		
		addRowSorterListener(new RowSorterListener() {
			
			@Override
			public void sorterChanged(RowSorterEvent e) {
				if((tableModel.getRowCount()-e.getPreviousRowCount())>1) {
					entryList.clear();
				}
			}
		});
	}
}
