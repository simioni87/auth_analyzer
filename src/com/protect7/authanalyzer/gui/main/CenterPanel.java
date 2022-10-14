package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JEditorPane;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTable;
import javax.swing.JTextArea;
import javax.swing.ListSelectionModel;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.event.RowSorterEvent;
import javax.swing.event.RowSorterListener;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.dialog.DataExportDialog;
import com.protect7.authanalyzer.gui.util.BypassCellRenderer;
import com.protect7.authanalyzer.gui.util.CustomRowSorter;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.gui.util.RequestTableModel;
import com.protect7.authanalyzer.gui.util.RequestTableModel.Column;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.Diff_match_patch;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Diff_match_patch.Diff;
import com.protect7.authanalyzer.util.Diff_match_patch.LinesToCharsResult;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;

public class CenterPanel extends JPanel {

	private static final long serialVersionUID = 8472627619821851125L;
	private final MainPanel mainPanel;
	private final String TABLE_SETTINGS = "TABLE_SETTINGS";
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final ImageIcon loaderImageIcon = new ImageIcon(this.getClass().getClassLoader().getResource("loader.gif"));
	private final JTable table;
	private final JPanel tablePanel = new JPanel(new BorderLayout());
	private final ListSelectionModel selectionModel;
	private final HashSet<Column> columnSet = new HashSet<Column>();
	private RequestTableModel tableModel;
	private final JPanel messageViewPanel;
	private CustomRowSorter sorter;
	private final String BUTTON_TEXT_COMPARE_VIEW = "Compare View  \u29C9";
	private final String BUTTON_TEXT_SINGLE_VIEW = "Single View  \u25A2";
	private final String BUTTON_TEXT_EXPAND_DIFF = "Expand Diff View  \u25B7";
	private final String BUTTON_TEXT_COLLAPSE_DIFF = "Collapse Diff View  \u25BD";
	private final RequestResponsePanel tabbedPanel1;
	private final RequestResponsePanel tabbedPanel2;
	private final String TEXT_DIFF_VIEW_DEFAULT = "<strong>Diff View</strong>";
	private final JEditorPane diffPane = new JEditorPane("text/html", TEXT_DIFF_VIEW_DEFAULT);
	private final JButton changeMessageViewButton = new JButton(BUTTON_TEXT_COMPARE_VIEW);
	private final JButton expandDiffButton = new JButton(BUTTON_TEXT_EXPAND_DIFF);
	private final JCheckBox syncTabCheckBox = new JCheckBox("Sync Tabs      ", true);
	private final JCheckBox showDiffCheckBox = new JCheckBox("Show Diff", false);
	private final JScrollPane comparisonScrollPane = new JScrollPane(diffPane);
	private final JSplitPane splitPane;
	private final JButton clearTableButton;
	private final JCheckBox showOnlyMarked = new JCheckBox("Marked", false);
	private final JCheckBox showDuplicates = new JCheckBox("Duplicates", true);
	private final JCheckBox showBypassed = new JCheckBox("Status " + BypassConstants.SAME.getName(), true);
	private final JCheckBox showPotentialBypassed = new JCheckBox("Status " + BypassConstants.SIMILAR.getName(), true);
	private final JCheckBox showNotBypassed = new JCheckBox("Status " + BypassConstants.DIFFERENT.getName(), true);
	private final JCheckBox showNA = new JCheckBox("Status " + BypassConstants.NA.getName(), true);
	private final PlaceholderTextField filterText;
	private final JPanel topPanel = new JPanel(new BorderLayout());
	private final JLabel tableFilterInfoLabel = new JLabel("", SwingConstants.CENTER);
	private final JLabel pendingRequestsLabel = new JLabel("", SwingConstants.CENTER);
	private final JCheckBox searchInPath = new JCheckBox("Search in Path", true);
	private final JCheckBox searchInRequest = new JCheckBox("Search in Request", false);
	private final JCheckBox searchInResponse = new JCheckBox("Search in Response", false);
	private final JCheckBox negativeSearch = new JCheckBox("Negative Search", false);
	private final JButton searchButton = new JButton("Search");
	private int selectedId = -1;

	public CenterPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;
		setLayout(new BorderLayout());
		table = new JTable();
		tablePanel.setBorder(BorderFactory.createLineBorder(Color.gray));
		JPanel tableControlPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 30, 5));
		JButton filterButton = new JButton();
		filterButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("filter.png")));
		filterButton.addActionListener(e -> showTableFilterDialog(tableControlPanel));
		filterText = new PlaceholderTextField(20);
		filterText.setPlaceholder("Enter Search Pattern...");
		searchButton.addActionListener(e -> tableModel.fireTableDataChanged());
		JPanel searchPanel = new JPanel();
		searchPanel.add(filterText);
		searchPanel.add(searchButton);
		tableControlPanel.add(searchPanel);
		tableControlPanel.add(filterButton);
		JButton settingsButton = new JButton();
		settingsButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("settings.png")));
		settingsButton.addActionListener(e -> showTableSettingsDialog(tableControlPanel));
		tableControlPanel.add(settingsButton);
		topPanel.add(tableControlPanel, BorderLayout.NORTH);
		tableFilterInfoLabel.putClientProperty("html.disable", null);
		topPanel.add(tableFilterInfoLabel, BorderLayout.CENTER);
		pendingRequestsLabel.setForeground(new Color(240, 110, 0));
		pendingRequestsLabel.setVisible(false);
		topPanel.add(pendingRequestsLabel, BorderLayout.SOUTH);
		
		tablePanel.add(new JScrollPane(topPanel, JScrollPane.VERTICAL_SCROLLBAR_NEVER, JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED), BorderLayout.NORTH);
	
		loadTableSettings();
		initTableWithModel();		
		table.setDefaultRenderer(Integer.class, new BypassCellRenderer());
		table.setDefaultRenderer(String.class, new BypassCellRenderer());
		table.setDefaultRenderer(BypassConstants.class, new BypassCellRenderer());	
		tablePanel.add(new JScrollPane(table), BorderLayout.CENTER);
		
		JPanel tableConfigPanel = new JPanel();
		clearTableButton = new JButton("Clear Table");
		clearTableButton.addActionListener(e -> clearTablePressed());
		tableConfigPanel.add(clearTableButton);
		JButton exportDataButton = new JButton("Export Table Data");
		exportDataButton.addActionListener(e -> { 
			exportDataButton.setIcon(loaderImageIcon);
			new Thread(new Runnable() {
				
				@Override
				public void run() {
					new DataExportDialog(CenterPanel.this);
					exportDataButton.setIcon(null);
				}
			}).start();			
			});
		tableConfigPanel.add(exportDataButton);
		tablePanel.add(tableConfigPanel, BorderLayout.SOUTH);
		
		tabbedPanel1 = new RequestResponsePanel(0, this);
		tabbedPanel2 = new RequestResponsePanel(1, this);
		JPanel messageViewButtons = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
		messageViewButtons.add(changeMessageViewButton);
		syncTabCheckBox.setEnabled(false);
		messageViewButtons.add(syncTabCheckBox);
		showDiffCheckBox.setEnabled(false);
		messageViewButtons.add(showDiffCheckBox);
		messageViewButtons.add(expandDiffButton);
		messageViewPanel = new JPanel(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.HORIZONTAL;
		messageViewPanel.add(messageViewButtons, c);
		c.fill = GridBagConstraints.BOTH;
		c.weightx = 1.0;
		c.weighty = 1.0;
		c.gridy++;
		messageViewPanel.add(tabbedPanel1, c);
		c.gridy++;
		messageViewPanel.add(tabbedPanel2, c);
		tabbedPanel2.setVisible(false);
		c.gridy++;
		diffPane.setEditable(false);
		diffPane.putClientProperty("html.disable", null);
		comparisonScrollPane.setVisible(false);
		messageViewPanel.add(comparisonScrollPane, c);
		expandDiffButton.setEnabled(false);
		changeMessageViewButton.addActionListener(e -> {
			if(changeMessageViewButton.getText().equals(BUTTON_TEXT_COMPARE_VIEW)) {
				changeMessageViewButton.setText(BUTTON_TEXT_SINGLE_VIEW);
				tabbedPanel2.setVisible(true);
				if(showDiffCheckBox.isSelected()) {
					comparisonScrollPane.setVisible(true);
					expandDiffButton.setEnabled(true);
				}
				syncTabCheckBox.setEnabled(true);
				showDiffCheckBox.setEnabled(true);
				changeRequestResponseView(true);
				updateDiffPane();
			}
			else {
				changeMessageViewButton.setText(BUTTON_TEXT_COMPARE_VIEW);
				tabbedPanel1.setVisible(true);
				tabbedPanel2.setVisible(false);
				comparisonScrollPane.setVisible(false);
				syncTabCheckBox.setEnabled(false);
				showDiffCheckBox.setEnabled(false);
				expandDiffButton.setText(BUTTON_TEXT_EXPAND_DIFF);
				expandDiffButton.setEnabled(false);
			}
		});
		expandDiffButton.addActionListener(e -> {
			if(expandDiffButton.getText().equals(BUTTON_TEXT_EXPAND_DIFF)) {
				expandDiffButton.setText(BUTTON_TEXT_COLLAPSE_DIFF);
				tabbedPanel1.setVisible(false);
				tabbedPanel2.setVisible(false);
				syncTabCheckBox.setEnabled(false);
				showDiffCheckBox.setEnabled(false);
				showDiffCheckBox.setSelected(true);
				comparisonScrollPane.setVisible(true);
			}
			else {
				expandDiffButton.setText(BUTTON_TEXT_EXPAND_DIFF);
				tabbedPanel1.setVisible(true);
				tabbedPanel2.setVisible(true);
				syncTabCheckBox.setEnabled(true);
				showDiffCheckBox.setEnabled(true);
			}
		});
		showDiffCheckBox.addActionListener(e -> {
			if(showDiffCheckBox.isSelected()) {
				comparisonScrollPane.setVisible(true);
				expandDiffButton.setEnabled(true);
				updateDiffPane();
			}
			else {
				comparisonScrollPane.setVisible(false);
				expandDiffButton.setEnabled(false);
			}
			SwingUtilities.invokeLater(new Runnable() {
				
				@Override
				public void run() {
					messageViewPanel.revalidate();
				}
			});
		});
		
		
		messageViewPanel.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tabbedPanel1.setBorder(BorderFactory.createLineBorder(Color.GRAY));
		tabbedPanel2.setBorder(BorderFactory.createLineBorder(Color.GRAY));

		splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, tablePanel, messageViewPanel);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);

		selectionModel = table.getSelectionModel();
		selectionModel.addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) { 
				changeRequestResponseView(false);
			}
			
		});
		setupTableContextMenu();
	}

	private void loadTableSettings() {
		String savedSettings = BurpExtender.callbacks.loadExtensionSetting(TABLE_SETTINGS);
		if (savedSettings != null) {
			String[] split = savedSettings.split(",");
			for (String columnAsString : split) {
				for (Column column : Column.values()) {
					if (columnAsString.equals(column.toString())) {
						columnSet.add(column);
					}
				}
			}
		} else {
			for (Column column : Column.getDefaultSet()) {
				columnSet.add(column);
			}
		}
	}

	public void updateOtherTabbedPane(int tabbedPaneId, int index) {
		if (syncTabCheckBox.isSelected()) {
			boolean pending = false;
			if (tabbedPaneId == 0) {
				pending = tabbedPanel2.setTabbedPaneIndex(index);
			}
			if (tabbedPaneId == 1) {
				pending = tabbedPanel1.setTabbedPaneIndex(index);
			}
			if (!pending) {
				updateDiffPane();
			}
		} else {
			updateDiffPane();
		}
	}

	public void updateDiffPane() {
		if (changeMessageViewButton.getText().equals(BUTTON_TEXT_SINGLE_VIEW) && showDiffCheckBox.isSelected()) {
			String msg1 = tabbedPanel1.getCurrentMessageString();
			String msg2 = tabbedPanel2.getCurrentMessageString();
			if (msg1 == null || msg2 == null) {
				diffPane.setText(TEXT_DIFF_VIEW_DEFAULT);
			} else {
				// On test machine it took approx. 3s to calc two msg with 200KB
				if (msg1.length() > 200000 || msg2.length() > 200000) {
					diffPane.setText(getHTMLCenterText("Message is too big. Can not calculate differences."));
				} else {
					diffPane.setText(getHTMLCenterText("Calculating differences..."));
					new Thread(new Runnable() {

						@Override
						public void run() {
							Diff_match_patch dmp = new Diff_match_patch();
							LinesToCharsResult a = dmp.diff_linesToChars(msg1, msg2);
							String lineText1 = a.getChars1();
							String lineText2 = a.getChars2();
							List<String> lineArray = a.getLineArray();
							LinkedList<Diff> diffs = dmp.diff_main(lineText1, lineText2, false);
							dmp.diff_charsToLines(diffs, lineArray);
							final String diffPaneText = getHTMLfromDiff(diffs);
							diffPane.setText(diffPaneText);
							SwingUtilities.invokeLater(new Runnable() {

								@Override
								public void run() {
									comparisonScrollPane.getVerticalScrollBar().setValue(0);
									comparisonScrollPane.getHorizontalScrollBar().setValue(0);
									messageViewPanel.revalidate();
								}
							});
						}
					}).start();
				}
			}
		}
	}

	private String getHTMLfromDiff(LinkedList<Diff_match_patch.Diff> diff) {
		int inserts = 0;
		int deletes = 0;
		StringBuilder document = new StringBuilder();
		for (Diff_match_patch.Diff currentDiff : diff) {
			String text = currentDiff.text.replace("<", "&lt;").replace("\n", "<br>");
			if (currentDiff.operation == Diff_match_patch.Operation.INSERT) {
				document.append("<span style='background-color:#c2f9c2;color:#000000;'>").append(text)
						.append("</span>");
				inserts++;
			}
			if (currentDiff.operation == Diff_match_patch.Operation.DELETE) {
				document.append("<span style='background-color:#ffb2b2;color:#000000;'>").append(text)
						.append("</span>");
				deletes++;
			}
			if (currentDiff.operation == Diff_match_patch.Operation.EQUAL) {
				document.append("<span>").append(text).append("</span>");
			}
		}
		String headerText = "";
		String selectedSession1 = tabbedPanel1.getSelectedSession();
		String selectedMsg1 = tabbedPanel1.getSelectedMessage();
		String selectedSession2 = tabbedPanel2.getSelectedSession();
		String selectedMsg2 = tabbedPanel2.getSelectedMessage();
		if (selectedSession1 != null && selectedSession2 != null && selectedMsg1 != null && selectedMsg2 != null) {
			headerText = "<span><strong>Diff: " + selectedSession1 + " (" + selectedMsg1 + ") &#x2794; "
					+ selectedSession2 + " (" + selectedMsg2 + ")</strong></span>";
			headerText += "<p><span style='background-color:#c2f9c2;color:#000000;'>Inserts: " + inserts
					+ "</span>&nbsp;&nbsp;&nbsp;<span style='background:#ffb2b2;color:#000000;'>Deletes: " + deletes
					+ "</span></p>";
		}
		return headerText + "<p style ='font-family: Courier New,font-size:13pt;'>" + document.toString() + "</p>";
	}

	private String getHTMLCenterText(String content) {
		return "<br><br><br><center>" + content + "</center>";
	}

	private void setupTableContextMenu() {
		table.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.getButton() == MouseEvent.BUTTON3) {
					int[] rows = table.getSelectedRows();
					if (rows.length > 0) {
						JPopupMenu contextMenu = new JPopupMenu();
						final ArrayList<OriginalRequestResponse> requestResponseList = new ArrayList<OriginalRequestResponse>();
						String appendix = "";
						if (rows.length > 1) {
							appendix = "s";
						}
						for (int row : rows) {
							requestResponseList
									.add(tableModel.getOriginalRequestResponse(table.convertRowIndexToModel(row)));
						}
						JMenuItem unmarkRowItem = new JMenuItem("Unmark Row" + appendix);
						unmarkRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(false);
							}
						});
						JMenuItem markRowItem = new JMenuItem("Mark Row" + appendix);
						markRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								requestResponse.setMarked(true);
							}
						});
						JMenuItem repeatRequestItem = new JMenuItem("Repeat Request" + appendix);
						repeatRequestItem.addActionListener(e -> {
							Collections.sort(requestResponseList);
							IHttpRequestResponse[] messages = new IHttpRequestResponse[requestResponseList.size()];
							for (int i=0; i<requestResponseList.size(); i++) {
								messages[i] = requestResponseList.get(i).getRequestResponse();
							}
							GenericHelper.repeatRequests(messages, mainPanel.getConfigurationPanel());
						});
						JMenuItem deleteRowItem = new JMenuItem("Delete Row" + appendix);
						deleteRowItem.addActionListener(e -> {
							for (OriginalRequestResponse requestResponse : requestResponseList) {
								tableModel.deleteRequestResponse(requestResponse);
							}
						});
						JMenuItem commentItem = new JMenuItem("Comment");
						commentItem.addActionListener(e -> {
							if (requestResponseList.size() > 0) {
								JTextArea commentTextArea = new JTextArea(requestResponseList.get(0).getComment(), 2,
										8);
								JOptionPane.showMessageDialog(commentItem, new JScrollPane(commentTextArea), "Comment",
										JOptionPane.INFORMATION_MESSAGE);
								for (OriginalRequestResponse requestResponse : requestResponseList) {
									requestResponse.setComment(commentTextArea.getText());
								}
							}
						});
						if (rows.length == 1) {
							if (requestResponseList.get(0).isMarked()) {
								contextMenu.add(unmarkRowItem);
							} else {
								contextMenu.add(markRowItem);
							}
						} else {
							contextMenu.add(markRowItem);
							contextMenu.add(unmarkRowItem);
						}
						contextMenu.add(repeatRequestItem);
						contextMenu.add(deleteRowItem);
						contextMenu.add(commentItem);
						contextMenu.show(event.getComponent(), event.getX(), event.getY());
					}
				}
			}
		});
	}

	// Paint center panel according to session list
	public void initCenterPanel() {
		initTableWithModel();
		tabbedPanel1.init();
		tabbedPanel2.init();
		selectedId = -1;
		diffPane.setText(TEXT_DIFF_VIEW_DEFAULT);
		splitPane.setResizeWeight(0.5d);
	}

	public void clearTablePressed() {
		clearTableButton.setIcon(loaderImageIcon);
		if (config.isRunning()) {
			config.getAnalyzerThreadExecutor().execute(new Runnable() {

				@Override
				public void run() {
					clearTable();
					clearTableButton.setIcon(null);
				}
			});
		} else {
			clearTable();
			clearTableButton.setIcon(null);
		}
	}

	public void clearTable() {
		config.clearSessionRequestMaps();
		tableModel.clearRequestMap();
		selectedId = -1;
		diffPane.setText(TEXT_DIFF_VIEW_DEFAULT);
	}

	public ArrayList<OriginalRequestResponse> getFilteredRequestResponseList() {
		ArrayList<OriginalRequestResponse> list = new ArrayList<OriginalRequestResponse>();
		for (int row = 0; row < table.getRowCount(); row++) {
			OriginalRequestResponse requestResponse = tableModel
					.getOriginalRequestResponse(table.convertRowIndexToModel(row));
			list.add(requestResponse);
		}
		return list;
	}
	
	public void toggleSearchButtonText() {
		if(searchButton.getIcon() == null) {
			searchButton.setIcon(loaderImageIcon);
		}
		else {
			searchButton.setIcon(null);
		}
	}

	private void initTableWithModel() {
		tableModel = new RequestTableModel();
		table.setModel(tableModel);
		config.setTableModel(tableModel);
		sorter = new CustomRowSorter(this, tableModel, showOnlyMarked, showDuplicates, showBypassed, 
				showPotentialBypassed, showNotBypassed, showNA, filterText, searchInPath, searchInRequest, searchInResponse, negativeSearch);
		sorter.addRowSorterListener(new RowSorterListener() {
			@Override
			public void sorterChanged(RowSorterEvent e) {
				updateTableFilterInfo();
			}
		});
        table.setRowSorter(sorter);
        updateColumnWidths();
	}

	private void updateTableFilterInfo() {
		if(table.getRowCount() < tableModel.getRowCount()) {
			String text = "<html><h3 style='color:red;'>Table Filtered: " + table.getRowCount() + "/"+
					tableModel.getRowCount()+" Entries Visible...</h3></html>";
			tableFilterInfoLabel.setText(text);
			tableFilterInfoLabel.setVisible(true);
		}
		else {
			tableFilterInfoLabel.setVisible(false);
		}
		tablePanel.revalidate();
	}
	
	public void updateAmountOfPendingRequests(int amountOfPendingRequests) {
		if(amountOfPendingRequests == 0) {
			pendingRequestsLabel.setVisible(false);
		}
		else {
			pendingRequestsLabel.setVisible(true);
			pendingRequestsLabel.setText("Pending Requests Queue: " + amountOfPendingRequests);
		}
	} 
	
	private void changeRequestResponseView(boolean force) {
		if (table.getSelectedRow() != -1) {
			int modelRowIndex = table.convertRowIndexToModel(table.getSelectedRow());
			OriginalRequestResponse originalRequestResponse = tableModel.getOriginalRequestResponse(modelRowIndex);
			if (force || (originalRequestResponse != null && selectedId != originalRequestResponse.getId())) {
				selectedId = originalRequestResponse.getId();
				boolean compareViewVisible = changeMessageViewButton.getText().equals(BUTTON_TEXT_SINGLE_VIEW);
				IMessageEditorController controllerOriginal = new CustomIMessageEditorController(
						originalRequestResponse.getRequestResponse().getHttpService(),
						originalRequestResponse.getRequestResponse().getRequest(),
						originalRequestResponse.getRequestResponse().getResponse());
				IMessageEditor requestMessageEditorOriginal = BurpExtender.callbacks
						.createMessageEditor(controllerOriginal, false);
				requestMessageEditorOriginal.setMessage(originalRequestResponse.getRequestResponse().getRequest(),
						true);
				tabbedPanel1.setRequestMessage(tabbedPanel1.TITLE_ORIGINAL, requestMessageEditorOriginal.getComponent(),
						requestMessageEditorOriginal);
				if (compareViewVisible) {
					IMessageEditor requestMessageEditorOriginal2 = BurpExtender.callbacks
							.createMessageEditor(controllerOriginal, false);
					requestMessageEditorOriginal2.setMessage(originalRequestResponse.getRequestResponse().getRequest(),
							true);
					tabbedPanel2.setRequestMessage(tabbedPanel1.TITLE_ORIGINAL,
							requestMessageEditorOriginal2.getComponent(), requestMessageEditorOriginal2);
				}
				if (originalRequestResponse.getRequestResponse().getResponse() != null) {
					IMessageEditor responseMessageEditorOriginal = BurpExtender.callbacks
							.createMessageEditor(controllerOriginal, false);
					responseMessageEditorOriginal.setMessage(originalRequestResponse.getRequestResponse().getResponse(),
							false);
					tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
							responseMessageEditorOriginal.getComponent(), responseMessageEditorOriginal);
					if (compareViewVisible) {
						IMessageEditor responseMessageEditorOriginal2 = BurpExtender.callbacks
								.createMessageEditor(controllerOriginal, false);
						responseMessageEditorOriginal2
								.setMessage(originalRequestResponse.getRequestResponse().getResponse(), false);
						tabbedPanel2.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
								responseMessageEditorOriginal2.getComponent(), responseMessageEditorOriginal2);
					}
				} else {
					tabbedPanel1.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
							getMessageViewLabel(originalRequestResponse.getInfoText()), null);
					if (compareViewVisible) {
						tabbedPanel2.setResponseMessage(tabbedPanel1.TITLE_ORIGINAL,
								getMessageViewLabel(originalRequestResponse.getInfoText()), null);
					}
				}

				for (Session session : config.getSessions()) {
					AnalyzerRequestResponse analyzerRequestResponse = session.getRequestResponseMap()
							.get(originalRequestResponse.getId());
					IHttpRequestResponse sessionRequestResponse = analyzerRequestResponse.getRequestResponse();
					if (sessionRequestResponse != null) {
						IMessageEditorController controller = new CustomIMessageEditorController(
								sessionRequestResponse.getHttpService(), sessionRequestResponse.getRequest(),
								sessionRequestResponse.getResponse());

						IMessageEditor requestMessageEditor = BurpExtender.callbacks.createMessageEditor(controller,
								false);
						requestMessageEditor.setMessage(sessionRequestResponse.getRequest(), true);
						tabbedPanel1.setRequestMessage(session.getName(), requestMessageEditor.getComponent(),
								requestMessageEditor);
						if (compareViewVisible) {
							IMessageEditor requestMessageEditor2 = BurpExtender.callbacks
									.createMessageEditor(controller, false);
							requestMessageEditor2.setMessage(sessionRequestResponse.getRequest(), true);
							tabbedPanel2.setRequestMessage(session.getName(), requestMessageEditor2.getComponent(),
									requestMessageEditor2);
						}

						IMessageEditor responseMessageEditor = BurpExtender.callbacks.createMessageEditor(controller,
								false);
						responseMessageEditor.setMessage(sessionRequestResponse.getResponse(), false);
						tabbedPanel1.setResponseMessage(session.getName(), responseMessageEditor.getComponent(),
								responseMessageEditor);
						if (compareViewVisible) {
							IMessageEditor responseMessageEditor2 = BurpExtender.callbacks
									.createMessageEditor(controller, false);
							responseMessageEditor2.setMessage(sessionRequestResponse.getResponse(), false);
							tabbedPanel2.setResponseMessage(session.getName(), responseMessageEditor2.getComponent(),
									responseMessageEditor2);
						}
					} else {
						tabbedPanel1.setRequestMessage(session.getName(),
								getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
						tabbedPanel1.setResponseMessage(session.getName(),
								getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
						if (compareViewVisible) {
							tabbedPanel2.setRequestMessage(session.getName(),
									getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
							tabbedPanel2.setResponseMessage(session.getName(),
									getMessageViewLabel(analyzerRequestResponse.getInfoText()), null);
						}
					}
				}
				updateDiffPane();
				SwingUtilities.invokeLater(new Runnable() {

					@Override
					public void run() {
						messageViewPanel.revalidate();
					}
				});
			}
		}
	}

	private JLabel getMessageViewLabel(String text) {
		String labelText = "";
		if (text != null) {
			labelText = text;
		}
		return new JLabel(labelText, JLabel.CENTER);
	}

	private void updateColumnWidths() {		
		for (Column column : Column.values()) {
			if (!columnSet.contains(column)) {
				for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
					String columnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
					if(columnName.endsWith(column.toString())) {
						table.getColumnModel().getColumn(i).setMinWidth(0);
						table.getColumnModel().getColumn(i).setMaxWidth(0);
					}
				}
			} else {
				if (column == Column.ID) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setMaxWidth(40);
					table.getColumnModel().getColumn(getColumnIdByName(Column.ID)).setPreferredWidth(40);
				} else if (column == Column.Host) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Host)).setPreferredWidth(200);
				} else if (column == Column.Path) {
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setMaxWidth(10000);
					table.getColumnModel().getColumn(getColumnIdByName(Column.Path)).setPreferredWidth(400);
				} else {
					for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
						String currentColumnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
						if(currentColumnName.endsWith(column.toString())) {
							table.getColumnModel().getColumn(i).setMaxWidth(10000);
							table.getColumnModel().getColumn(i).setPreferredWidth(80);
						}
					}
				}
			}
		}
	}
	
	private int getColumnIdByName(Column columnName) {
		for(int i=0; i<table.getColumnModel().getColumnCount(); i++) {
			String currentColumnName = table.getColumnModel().getColumn(i).getHeaderValue().toString();
			if(currentColumnName.endsWith(columnName.toString())) {
				return i;
			}
		}
		return -1;
	}
	
	private void showTableFilterDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		inputPanel.add(new JLabel("Table Filters"));
		inputPanel.add(showOnlyMarked);
		inputPanel.add(showDuplicates);
		inputPanel.add(showBypassed);
		inputPanel.add(showPotentialBypassed);
		inputPanel.add(showNotBypassed);
		inputPanel.add(showNA);
		
		inputPanel.add(new JLabel(" "));
		inputPanel.add(new JSeparator(SwingConstants.HORIZONTAL));
		inputPanel.add(new JLabel(" "));
		inputPanel.add(new JLabel("Search Options"));
		inputPanel.add(searchInPath);
		inputPanel.add(searchInRequest);
		inputPanel.add(searchInResponse);	
		inputPanel.add(negativeSearch);
		JOptionPane.showConfirmDialog(parent, inputPanel, "Table Filters", JOptionPane.CLOSED_OPTION);
		
	}
	
	private void showTableSettingsDialog(Component parent) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		inputPanel.add(new JLabel("Show Columns"));
		for (Column column : Column.values()) {
			JCheckBox columnCheckBox = new JCheckBox(column.toString());
			columnCheckBox.setSelected(columnSet.contains(column));
			columnCheckBox.addActionListener(e -> {
				if (columnCheckBox.isSelected()) {
					columnSet.add(column);
				} else {
					columnSet.remove(column);
				}
				updateColumnWidths();
			});
			inputPanel.add(columnCheckBox);
		}
		JOptionPane.showConfirmDialog(parent, inputPanel, "Show / Hide Columns", JOptionPane.CLOSED_OPTION);
		String saveString = columnSet.toString().replaceAll(" ", "").replace("[", "").replace("]", "");
		BurpExtender.callbacks.saveExtensionSetting(TABLE_SETTINGS, saveString);
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