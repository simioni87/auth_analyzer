package com.protect7.authanalyzer.gui.dialog;

import java.io.File;
import java.util.ArrayList;
import java.util.EnumSet;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JSeparator;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.gui.main.CenterPanel;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DataExporter;

public class DataExportDialog {

	public DataExportDialog(CenterPanel centerPanel) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		
		inputPanel.add(new JLabel("Choose the format of the export."));
    	JRadioButton htmlReport = new JRadioButton("HTML Export", true);
    	JRadioButton xmlReport = new JRadioButton("XML Export");
    	ButtonGroup group = new ButtonGroup();
    	group.add(htmlReport);
    	group.add(xmlReport);
    	inputPanel.add(htmlReport);
    	inputPanel.add(xmlReport);
    	JCheckBox doBase64Encode = new JCheckBox("Base64-encode requests and responses", true);
    	doBase64Encode.setEnabled(false);
    	htmlReport.addActionListener(e -> doBase64Encode.setEnabled(false));
    	xmlReport.addActionListener(e -> doBase64Encode.setEnabled(true));
    	inputPanel.add(doBase64Encode);
    	inputPanel.add(new JLabel(" "));
    	inputPanel.add(new JSeparator(JSeparator.HORIZONTAL));
    	inputPanel.add(new JLabel(" "));
    	
    	inputPanel.add(new JLabel("Select Columns to include in export."));
    	
    	EnumSet<DataExporter.MainColumn> mainColumns = EnumSet.allOf(DataExporter.MainColumn.class); 
    	for(DataExporter.MainColumn mainColumn : DataExporter.MainColumn.values()) {
    		JCheckBox checkBox = new JCheckBox(mainColumn.getName(), true);
    		checkBox.addActionListener(e -> {
    			if(checkBox.isSelected()) {
    				mainColumns.add(mainColumn);
    			}
    			else {
    				mainColumns.remove(mainColumn);
    			}
    		});
    		inputPanel.add(checkBox);
    	}
    	EnumSet<DataExporter.SessionColumn> sessionColumns = EnumSet.allOf(DataExporter.SessionColumn.class); 
    	for(DataExporter.SessionColumn sessionColumn : DataExporter.SessionColumn.values()) {
    		JCheckBox checkBox;
    		if(sessionColumn == DataExporter.SessionColumn.REQUEST || sessionColumn == DataExporter.SessionColumn.RESPONSE) {
    			checkBox = new JCheckBox(sessionColumn.getName(), false);
    			sessionColumns.remove(sessionColumn);
    		}
    		else {
    			checkBox = new JCheckBox(sessionColumn.getName(), true);
    		}
    		checkBox.addActionListener(e -> {
    			if(checkBox.isSelected()) {
    				sessionColumns.add(sessionColumn);
    			}
    			else {
    				sessionColumns.remove(sessionColumn);
    			}
    		});
    		inputPanel.add(checkBox);
    	}
    	inputPanel.add(new JLabel(" "));

		int result = JOptionPane.showConfirmDialog(centerPanel, inputPanel, "Export Table Data",
				JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.OK_OPTION) {
			JFileChooser chooser = new JFileChooser();
			if(htmlReport.isSelected()) {
				chooser.setSelectedFile(new File("Auth_Analyzer_Report.html"));
			}
			else {
				chooser.setSelectedFile(new File("Auth_Analyzer_Report.xml"));
			}
			int status = chooser.showSaveDialog(centerPanel);
			if(status == JFileChooser.APPROVE_OPTION) {
				File file = chooser.getSelectedFile();
				if(!file.getName().endsWith(".html") || !file.getName().endsWith(".xml")) {
					String newFileName;
					if(file.getName().lastIndexOf(".") != -1) {
						int index = file.getAbsolutePath().lastIndexOf(".");
						newFileName = file.getAbsolutePath().substring(0, index);
					}
					else {
						newFileName = file.getAbsolutePath();
					}
					if(htmlReport.isSelected()) {
						newFileName = newFileName + ".html";
					}
					else {
						newFileName = newFileName + ".xml";
					}
					file = new File(newFileName);
				}
				ArrayList<OriginalRequestResponse> filteredRequestResponseList = centerPanel.getFilteredRequestResponseList();
				boolean success = false;
				if(htmlReport.isSelected()) {
					success = DataExporter.getDataExporter().createHTML(file, filteredRequestResponseList, CurrentConfig.getCurrentConfig().getSessions(), 
							mainColumns, sessionColumns);
				}
				else {
					success = DataExporter.getDataExporter().createXML(file, filteredRequestResponseList, CurrentConfig.getCurrentConfig().getSessions(), 
							mainColumns, sessionColumns, doBase64Encode.isSelected());
				}
				if(success) {
					JOptionPane.showMessageDialog(centerPanel, "Successfully exported to\n" + file.getAbsolutePath());
				}
				else {
					JOptionPane.showMessageDialog(centerPanel, "Failed to export data");
				}
			}
		}
	}
}