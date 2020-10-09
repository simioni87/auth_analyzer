package com.protect7.authanalyzer.gui;

import java.awt.BorderLayout;
import java.awt.Color;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

public class CenterPanel extends JPanel {

	private static final long serialVersionUID = 8472627619821851125L;
	private CurrentConfig config = CurrentConfig.getCurrentConfig();
	private JTable table;
	private RequestTableModel tableModel;
	private IBurpExtenderCallbacks callbacks;
	private JTabbedPane tabbedPane = new JTabbedPane();
	private int currentRequestResponseKey = -1;
	private int currentRow = -1;

	public CenterPanel(IBurpExtenderCallbacks callbacks) {
		setLayout(new BorderLayout());
		table = new JTable();
		this.callbacks = callbacks;
		initTableWithModel();
		table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());
		table.setAutoCreateRowSorter(true);
		JPanel tablePanel = new JPanel(new BorderLayout());
		tablePanel.setBorder(BorderFactory.createLineBorder(Color.gray));
		JPanel tableConfigPanel = new JPanel();
		JButton clearTableButton = new JButton("Clear Table");
		clearTableButton.addActionListener(e -> {
			config.clearSessionRequestMaps();
			tableModel.clearRequestMap();
		});
		tableConfigPanel.add(clearTableButton);
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
		tablePanel.add(tableConfigPanel, BorderLayout.SOUTH);
		
		initTabbedPane();

		JSplitPane  splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, tabbedPane);
		splitPane.setResizeWeight(0.5);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);
				
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) {
				if (table.getSelectedRow() != -1) {
					if(table.getSelectedRow() != currentRow) {
						currentRow = table.getSelectedRow();
						changeRequestResponseView(table, tableModel);
					}
				}
			}
		});
	}
	
	//Paint center panel according to session list
	public void initCenterPanel() {
		config.clearSessionRequestMaps();
		tableModel.clearRequestMap();
		initTableWithModel();
		initTabbedPane();
		for(Session session : config.getSessions()) {
			tabbedPane.add(session.getName() + " Request", new JPanel());
			session.setTabbedPaneRequestIndex(tabbedPane.getTabCount() - 1);

			tabbedPane.add(session.getName() + " Response", new JPanel());
			session.setTabbedPaneResponseIndex(tabbedPane.getTabCount() - 1);
		}
	}
	
	private void initTabbedPane() {
		tabbedPane.removeAll();
		currentRequestResponseKey = -1;
		tabbedPane.add("Original Request", new JPanel());		
		tabbedPane.add("Original Response", new JPanel());
	}
	
	private void initTableWithModel() {
		this.tableModel = new RequestTableModel(callbacks);
		table.setModel(tableModel);
		config.setTableModel(tableModel);
		table.getColumnModel().getColumn(0).setMaxWidth(40);
		table.getColumnModel().getColumn(1).setMaxWidth(90);
		table.getColumnModel().getColumn(2).setPreferredWidth(200);
		table.getColumnModel().getColumn(3).setPreferredWidth(400);
	}

	private void changeRequestResponseView(JTable table, RequestTableModel tableModel) {
		System.out.println(table.getSelectedRow());
		if(table.getSelectedRow() != -1) {
			currentRequestResponseKey = (int) tableModel.getValueAt(table.convertRowIndexToModel(table.getSelectedRow()), 0);			
			
			IMessageEditorController controllerOriginal = new CustomIMessageEditorController(tableModel.getOriginalRequestResponse(currentRequestResponseKey).getHttpService(), 
					tableModel.getOriginalRequestResponse(currentRequestResponseKey).getRequest(), tableModel.getOriginalRequestResponse(currentRequestResponseKey).getResponse());
			IMessageEditor requestMessageEditorOriginal = callbacks.createMessageEditor(controllerOriginal, false);
			requestMessageEditorOriginal.setMessage(tableModel.getOriginalRequestResponse(currentRequestResponseKey).getRequest(), true);
			tabbedPane.setComponentAt(0, requestMessageEditorOriginal.getComponent());
			
			IMessageEditor responseMessageEditorOriginal = callbacks.createMessageEditor(controllerOriginal, false);
			responseMessageEditorOriginal.setMessage(tableModel.getOriginalRequestResponse(currentRequestResponseKey).getResponse(), false);
			tabbedPane.setComponentAt(1, responseMessageEditorOriginal.getComponent());
			
			
			for(Session session : config.getSessions()) {
				IHttpRequestResponse sessionRequestResponse = session.getRequestResponseMap().get(currentRequestResponseKey).getRequestResponse();
				IMessageEditorController controller = new CustomIMessageEditorController(sessionRequestResponse.getHttpService(), 
						sessionRequestResponse.getRequest(), sessionRequestResponse.getResponse());
				
				IMessageEditor requestMessageEditor = callbacks.createMessageEditor(controller, false);
				requestMessageEditor.setMessage(sessionRequestResponse.getRequest(), true);
				tabbedPane.setComponentAt(session.getTabbedPaneRequestIndex(), requestMessageEditor.getComponent());
				
				IMessageEditor responseMessageEditor = callbacks.createMessageEditor(controller, false);
				responseMessageEditor.setMessage(sessionRequestResponse.getResponse(), false);
				tabbedPane.setComponentAt(session.getTabbedPaneResponseIndex(), responseMessageEditor.getComponent());
				
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
