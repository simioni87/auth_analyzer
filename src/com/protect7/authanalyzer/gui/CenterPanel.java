package com.protect7.authanalyzer.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.FlowLayout;
import java.awt.Point;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.util.EnumSet;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DataExporter;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

public class CenterPanel extends JPanel {

	private static final long serialVersionUID = 8472627619821851125L;
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final JTable table;
	private final ListSelectionModel selectionModel;
	private RequestTableModel tableModel;
	private CustomRowSorter sorter;
	private final JTabbedPane tabbedPane = new JTabbedPane();
	private final JButton clearTableButton;
	private final JCheckBox showOnlyMarked;
	private final JCheckBox showDuplicates;
	private final JCheckBox showBypassed;
	private final JCheckBox showPotentialBypassed;
	private final JCheckBox showNotBypassed;
	private int selectedId = -1;

	public CenterPanel() {
		setLayout(new BorderLayout());
		table = new JTable();
		JPanel tablePanel = new JPanel(new BorderLayout());
		tablePanel.setBorder(BorderFactory.createLineBorder(Color.gray));
		
		JPanel tableFilterPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 30, 10));
		showOnlyMarked = new JCheckBox("Marked", false);
		tableFilterPanel.add(showOnlyMarked);
		showDuplicates = new JCheckBox("Duplicates", true);
		tableFilterPanel.add(showDuplicates);
		showBypassed = new JCheckBox(BypassConstants.BYPASSED.toString(), true);
		tableFilterPanel.add(showBypassed);
		showPotentialBypassed = new JCheckBox(BypassConstants.POTENTIAL_BYPASSED.toString(), true);
		tableFilterPanel.add(showPotentialBypassed);
		showNotBypassed = new JCheckBox(BypassConstants.NOT_BYPASSED.toString(), true);
		tableFilterPanel.add(showNotBypassed);
		tablePanel.add(new JScrollPane(tableFilterPanel), BorderLayout.NORTH);
		
		initTableWithModel();		
		table.setDefaultRenderer(Integer.class, new BypassCellRenderer());
		table.setDefaultRenderer(String.class, new BypassCellRenderer());
		table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());	
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
		
		JPanel tableConfigPanel = new JPanel();
		clearTableButton = new JButton("Clear Table");
		clearTableButton.addActionListener(e -> clearTable());
		tableConfigPanel.add(clearTableButton);
		JButton exportDataButton = new JButton("Export Table Data");
		exportDataButton.addActionListener(e -> exportData());
		tableConfigPanel.add(exportDataButton);
		tablePanel.add(tableConfigPanel, BorderLayout.SOUTH);
		
		initTabbedPane();
		
		tabbedPane.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		JSplitPane  splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, tabbedPane);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);

		selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) { 
				changeRequestResponseView(table, tableModel);
			}
			
		});
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {	
				if (event.getButton() == MouseEvent.BUTTON3) {
					Point point = event.getPoint();
				    int row = table.rowAtPoint(point);
				    if(row != -1) {
				    	JPopupMenu contextMenu = new JPopupMenu();
				    	final OriginalRequestResponse requestResponse = tableModel.getOriginalRequestResponse(table.convertRowIndexToModel(row));
				    	if(requestResponse.isMarked())  {
				    		JMenuItem item = new JMenuItem("Unmark Row");
					    	contextMenu.add(item);
					    	item.addActionListener(e -> {
						    	requestResponse.setMarked(false);
					    	});
				    	}
				    	else {
				    		JMenuItem item = new JMenuItem("Mark Row");
					    	contextMenu.add(item);
					    	item.addActionListener(e -> {
						    	requestResponse.setMarked(true);
					    	});
				    	}
				    	contextMenu.show(event.getComponent(), event.getX(), event.getY());
				    }
				}				
			}
		});
	}
	
	//Paint center panel according to session list
	public void initCenterPanel(boolean sessionListChanged) {
		if(sessionListChanged) {
			initTableWithModel();
		}
		initTabbedPane();
		for(Session session : config.getSessions()) {
			tabbedPane.add(session.getName() + " Request", new JPanel());
			session.setTabbedPaneRequestIndex(tabbedPane.getTabCount() - 1);
			tabbedPane.add(session.getName() + " Response", new JPanel());
			session.setTabbedPaneResponseIndex(tabbedPane.getTabCount() - 1);
		}
		selectedId = -1;
	}
	
	public void clearTable() {
		clearTableButton.setText("Wait for Clearing");
		config.getAnalyzerThreadExecutor().execute(new Runnable() {
			
			@Override
			public void run() {
				config.clearSessionRequestMaps();
				tableModel.clearRequestMap();
				selectedId = -1;
				clearTableButton.setText("Clear Table");
			}
		});
	}
	
	private void exportData() {
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
    	inputPanel.add(new JLabel(" "));
    	inputPanel.add(new JSeparator(JSeparator.HORIZONTAL));
    	inputPanel.add(new JLabel(" "));
    	
    	inputPanel.add(new JLabel("Select Columns to include in export."));
    	//HashSet<DataExporter.MainColumn> mainColumns = new HashSet<DataExporter.MainColumn>();
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
    		JCheckBox checkBox = new JCheckBox(sessionColumn.getName(), true);
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

		int result = JOptionPane.showConfirmDialog(this, inputPanel, "Export Table Data",
				JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.OK_OPTION) {
			JFileChooser chooser = new JFileChooser();
			int status = chooser.showSaveDialog(this);
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
				
				if(htmlReport.isSelected()) {
					DataExporter.getDataExporter().createHTML(file, tableModel.getOriginalRequestResponseList(), config.getSessions(), 
							mainColumns, sessionColumns);
				}
				else {
					DataExporter.getDataExporter().createXML(file, tableModel.getOriginalRequestResponseList(), config.getSessions(), 
							mainColumns, sessionColumns);
				}
				JOptionPane.showMessageDialog(this, "Successfully exported to\n" + file.getAbsolutePath());
			}
		}
	}
	
	private void initTabbedPane() {
		tabbedPane.removeAll();
		tabbedPane.add("Original Request", new JPanel());		
		tabbedPane.add("Original Response", new JPanel());
	}
	
	private void initTableWithModel() {
		tableModel = new RequestTableModel();
		table.setModel(tableModel);
		config.setTableModel(tableModel);
		sorter = new CustomRowSorter(tableModel, showOnlyMarked, showDuplicates, showBypassed, 
				showPotentialBypassed, showNotBypassed);
        table.setRowSorter(sorter);
		table.getColumnModel().getColumn(0).setMaxWidth(40);
		table.getColumnModel().getColumn(1).setMaxWidth(90);
		table.getColumnModel().getColumn(2).setPreferredWidth(200);
		table.getColumnModel().getColumn(3).setPreferredWidth(400);
	}

	private void changeRequestResponseView(JTable table, RequestTableModel tableModel) {
		if(table.getSelectedRow() != -1) {
			int modelRowIndex = table.convertRowIndexToModel(table.getSelectedRow());
			OriginalRequestResponse originalRequestResponse = tableModel.getOriginalRequestResponse(modelRowIndex);
			if(originalRequestResponse != null && selectedId != originalRequestResponse.getId()) {
				selectedId = originalRequestResponse.getId();
				IMessageEditorController controllerOriginal = new CustomIMessageEditorController(originalRequestResponse.getRequestResponse().getHttpService(), 
						originalRequestResponse.getRequestResponse().getRequest(), originalRequestResponse.getRequestResponse().getResponse());
				IMessageEditor requestMessageEditorOriginal = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
				requestMessageEditorOriginal.setMessage(originalRequestResponse.getRequestResponse().getRequest(), true);
				tabbedPane.setComponentAt(0, requestMessageEditorOriginal.getComponent());
				
				IMessageEditor responseMessageEditorOriginal = BurpExtender.callbacks.createMessageEditor(controllerOriginal, false);
				responseMessageEditorOriginal.setMessage(originalRequestResponse.getRequestResponse().getResponse(), false);
				tabbedPane.setComponentAt(1, responseMessageEditorOriginal.getComponent());
							
				for(Session session : config.getSessions()) {
					IHttpRequestResponse sessionRequestResponse = session.getRequestResponseMap().get(originalRequestResponse.getId()).getRequestResponse();
					IMessageEditorController controller = new CustomIMessageEditorController(sessionRequestResponse.getHttpService(), 
							sessionRequestResponse.getRequest(), sessionRequestResponse.getResponse());
					
					IMessageEditor requestMessageEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
					requestMessageEditor.setMessage(sessionRequestResponse.getRequest(), true);
					tabbedPane.setComponentAt(session.getTabbedPaneRequestIndex(), requestMessageEditor.getComponent());
					
					IMessageEditor responseMessageEditor = BurpExtender.callbacks.createMessageEditor(controller, false);
					responseMessageEditor.setMessage(sessionRequestResponse.getResponse(), false);
					tabbedPane.setComponentAt(session.getTabbedPaneResponseIndex(), responseMessageEditor.getComponent());
					
				}
			}
		}
	}
	
	private class CustomIMessageEditorController implements IMessageEditorController {
		
		private final IHttpService httpService;
		private final byte[] request;
		private final byte[] response;
		
		public CustomIMessageEditorController(IHttpService httpService, byte[] request, byte[] response) {
			this.httpService = httpService;
			this.request = request;
			this.response = response;		
		}

		@Override
		public IHttpService getHttpService() {
			return httpService;
		}

		@Override
		public byte[] getRequest() {
			return request;
		}

		@Override
		public byte[] getResponse() {
			return response;
		}		
	}
}