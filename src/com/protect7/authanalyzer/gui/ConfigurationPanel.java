package com.protect7.authanalyzer.gui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.HashMap;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JToggleButton;
import com.protect7.authanalyzer.entities.Rule;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.filter.FileTypeFilter;
import com.protect7.authanalyzer.filter.InScopeFilter;
import com.protect7.authanalyzer.filter.MethodFilter;
import com.protect7.authanalyzer.filter.OnlyProxyFilter;
import com.protect7.authanalyzer.filter.PathFilter;
import com.protect7.authanalyzer.filter.QueryFilter;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.StatusCodeFilter;
import com.protect7.authanalyzer.util.CurrentConfig;

public class ConfigurationPanel extends JPanel {

	private static final long serialVersionUID = -4278008236240529083L;
	private CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final String ANALYZER_STOPPED_TEXT = "<html><span style='color:red; font-weight: bold'>&#x26AB;</span> Analyzer Stopped</html>";
	private final String ANALYZER_STARTED_TEXT = "<html><span style='color:green; font-weight: bold'>&#x26AB;</span> Analyzer Running</html>";
	private final String ANALYZER_PAUSED_TEXT = "<html><span style='color:orange; font-weight: bold'>&#x26AB;</span> Analyzer Paused</html>";
	private JButton startStopButton = new JButton();
	private JButton pauseButton = new JButton();
	private HashMap<String, SessionPanel> sessionPanelMap = new HashMap<>();
	private JButton createSessionButton;
	private JButton renameSessionButton;
	private JButton removeSessionButton;
	private final String PAUSE_TEXT = "\u23f8";
	private final String PLAY_TEXT = "\u25b6";
	private final JTabbedPane sessionTabbedPane = new JTabbedPane();
	boolean sessionListChanged = false;
	private final CenterPanel centerPanel;

	public ConfigurationPanel(CenterPanel centerPanel) {
		this.centerPanel = centerPanel;
		JPanel sessionButtonPanel = new JPanel();
		sessionButtonPanel.setLayout(new BoxLayout(sessionButtonPanel, BoxLayout.Y_AXIS));
		createSessionButton = new JButton("New Session");
		renameSessionButton = new JButton("Rename Session");
		renameSessionButton.setEnabled(false);
		removeSessionButton = new JButton("Remove Session");
		removeSessionButton.setEnabled(false);
		createSessionButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of Session (e.g. user1)");
				if(sessionName != null && !sessionName.equals("") && !sessionPanelMap.containsKey(sessionName) && !sessionName.equals("Original")) {
					if(doModify()) {
						SessionPanel sessionPanel = new SessionPanel();
						sessionTabbedPane.add(sessionName, sessionPanel);
						sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount()-1);
						sessionPanelMap.put(sessionName, sessionPanel);
						renameSessionButton.setEnabled(true);
						removeSessionButton.setEnabled(true);
					}
				}
			}
		});
		renameSessionButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				int currentIndex = sessionTabbedPane.getSelectedIndex();
				String currentTitle = sessionTabbedPane.getTitleAt(currentIndex);
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Rename Current Session:", currentTitle);
				if(sessionName != null && !sessionName.equals("") && !sessionPanelMap.containsKey(sessionName) && !sessionName.equals("Original")) {
					if(doModify()) {
						sessionTabbedPane.setTitleAt(currentIndex, sessionName);
						sessionPanelMap.put(sessionName, sessionPanelMap.get(currentTitle));
						sessionPanelMap.remove(currentTitle);
					}
				}
			}
		});
		removeSessionButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				if(doModify()) {
					int currentIndex = sessionTabbedPane.getSelectedIndex();
					sessionPanelMap.remove(sessionTabbedPane.getTitleAt(currentIndex));
					sessionTabbedPane.remove(currentIndex);
					if(sessionTabbedPane.getTabCount() == 0) {
						renameSessionButton.setEnabled(false);
						removeSessionButton.setEnabled(false);
					}
				}
			}
		});
		sessionButtonPanel.add(createSessionButton);
		sessionButtonPanel.add(renameSessionButton);
		sessionButtonPanel.add(removeSessionButton);
			
		JPanel filterPanel = new JPanel();
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

		JCheckBox onlyInScopeButton = new JCheckBox("Only In Scope (0)");
		onlyInScopeButton.setSelected(true);
		addFilter(new InScopeFilter(), onlyInScopeButton, "Only In Scope requests are analyzed", "");		
		filterPanel.add(onlyInScopeButton);

		JCheckBox onlyProxyButton = new JCheckBox("Only Proxy Traffic (0)");
		onlyProxyButton.setSelected(true);
		addFilter(new OnlyProxyFilter(), onlyProxyButton, "Analyze only proxy traffic. Unselect to analyze repeater and proxy traffic.", "");		
		filterPanel.add(onlyProxyButton);

		JCheckBox fileTypeFilterButton = new JCheckBox("Exclude Filetypes (0)");
		fileTypeFilterButton.setSelected(true);
		addFilter(new FileTypeFilter(), fileTypeFilterButton, "Excludes every specified filetype.", "Enter filetypes to filter. Comma separated.\r\neg: jpg, png, js");
		filterPanel.add(fileTypeFilterButton);

		JCheckBox methodFilterButton = new JCheckBox("Exclude HTTP Methods (0)");
		methodFilterButton.setSelected(true);
		addFilter(new MethodFilter(), methodFilterButton, "Excludes every specified http method.", "Enter HTTP methods to filter. Comma separated.\r\neg: OPTIONS, TRACE");
		filterPanel.add(methodFilterButton);

		JCheckBox statusCodeFilterButton = new JCheckBox("Exclude Status Codes (0)");
		statusCodeFilterButton.setSelected(true);
		addFilter(new StatusCodeFilter(), statusCodeFilterButton, "Excludes every specified status code.", "Enter status codes to filter. Comma separated.\r\neg: 204, 304");
		filterPanel.add(statusCodeFilterButton);
		
		JCheckBox pathFilterButton = new JCheckBox("Exclude Paths (0)");
		pathFilterButton.setSelected(false);
		addFilter(new PathFilter(), pathFilterButton, "Excludes every path that contains one of the specified string literals.", "Enter String literals for paths to be excluded. Comma separated.\r\neg: log, libraries");
		filterPanel.add(pathFilterButton);
		
		JCheckBox queryFilterButton = new JCheckBox("Exclude Queries / Params (0)");
		queryFilterButton.setSelected(false);
		addFilter(new QueryFilter(), queryFilterButton, "Excludes every GET query that contains one of the specified string literals.", "Enter string literals for queries to be excluded. Comma separated.\r\neg: log, core");
		filterPanel.add(queryFilterButton);

		startStopButton.setText(ANALYZER_STOPPED_TEXT);
		startStopButton.addActionListener(e -> startStopButtonPressed());
		
		pauseButton.setText(PAUSE_TEXT);
		pauseButton.setEnabled(false);
		pauseButton.addActionListener(e -> pauseButtonPressed());
		
		add(sessionButtonPanel);
		add(Box.createHorizontalStrut(30));
		add(sessionTabbedPane);
		add(Box.createHorizontalStrut(60));
		add(filterPanel);
		add(Box.createHorizontalStrut(30));
		add(startStopButton);
		add(pauseButton);
	}
	
	private boolean doModify() {
		if(config.getTableModel().getRowCount() > 0 && !sessionListChanged) {
			int selection = JOptionPane.showConfirmDialog(this, "You are going to modify your session setup."
					+ "\nTable data will be lost.", "Change Session Setup", JOptionPane.OK_CANCEL_OPTION);
			if(selection == JOptionPane.YES_OPTION) {
				sessionListChanged = true;
				centerPanel.clearTable();
				return true;
			}
			else {
				return false;
			}
		}
		else {
			sessionListChanged = true;
			return true;
		}
	}
	
	// Appends the selected text from context menu within the header(s) to replace text are of the currently selected session
	public void setSelectedTextFromContextMenu(String selectedText) {
		if(!config.isRunning()) {
			int currentIndex = sessionTabbedPane.getSelectedIndex();
			String sessionName = sessionTabbedPane.getTitleAt(currentIndex);
			SessionPanel sessionPanel = sessionPanelMap.get(sessionName);
			String currentText = sessionPanel.getHeadersToReplaceText().getText();
			if(currentText.endsWith("\n") || currentText.equals("")) {
				sessionPanel.setHeadersToReplaceText(currentText + selectedText);
			}
			else {
				sessionPanel.setHeadersToReplaceText(currentText + "\n" + selectedText);
			}
			
		}
	}
	
	public SessionPanel getSelectedSession() {
		int currentIndex = sessionTabbedPane.getSelectedIndex();
		String sessionName = sessionTabbedPane.getTitleAt(currentIndex);
		return sessionPanelMap.get(sessionName);
	}
	
	private void addFilter(RequestFilter filter, JToggleButton onOffButton, String toolTipText, String inputDialogText) {
		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
		if(filter.hasStringLiterals()) {
			onOffButton.setToolTipText("<html>" + toolTipText + "<br>String literals: <em>" + getArrayAsString(filter.getFilterStringLiterals()) + "</em></html>");
		}
		else {
			onOffButton.setToolTipText(toolTipText);
		}
		onOffButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (onOffButton.isSelected() && filter.hasStringLiterals()) {
					String[] inputArray = getInputArray(onOffButton,
							inputDialogText,
							getArrayAsString(filter.getFilterStringLiterals()));
					if (inputArray != null) {
						filter.setFilterStringLiterals(inputArray);
						onOffButton.setToolTipText("<html>" + toolTipText + "<br>String literals: <em>" + getArrayAsString(filter.getFilterStringLiterals()) + "</em></html>");
					}
				}
			}
		});
	}

	private void startStopButtonPressed() {
		if(sessionPanelMap.size() == 0) {
			JOptionPane.showMessageDialog(this, "No Session Created");
		}
		else {
			if (config.isRunning() || pauseButton.getText().equals(PLAY_TEXT)) {
				for(String session : sessionPanelMap.keySet()) {
					sessionPanelMap.get(session).setStopped();
				}
				createSessionButton.setEnabled(true);
				renameSessionButton.setEnabled(true);
				removeSessionButton.setEnabled(true);
				pauseButton.setText(PAUSE_TEXT);
				pauseButton.setEnabled(false);
				config.setRunning(false);
				startStopButton.setText(ANALYZER_STOPPED_TEXT);
			} else {
				
				if(sessionListChanged) {
					config.clearSessionListAndTableModel();
				}
				for(String session : sessionPanelMap.keySet()) {				
					SessionPanel sessionPanel = sessionPanelMap.get(session);
					for(Rule rule : sessionPanel.getRules()) {
						rule.setReplacementValue(null);
					}
					Session newSession = null;
					if(sessionListChanged) {
						newSession = new Session(session, sessionPanel.getHeadersToReplaceText().getText(), 
								sessionPanel.getCsrfTokenToReplaceText().getText(), sessionPanel.getCsrfTokenValueText().getText(), 
								sessionPanel.getFilterRequestsWithSameHeader().isSelected(), sessionPanel.getRules(), sessionPanel.getStatusPanel());
						config.addSession(newSession);
					}
					else {
						newSession = config.getSessionByName(session);
						newSession.setHeadersToReplace(sessionPanel.getHeadersToReplaceText().getText());
						newSession.setCsrfTokenName(sessionPanel.getCsrfTokenToReplaceText().getText());
						newSession.setStaticCsrfTokenValue(sessionPanel.getCsrfTokenValueText().getText());
						newSession.setFilterRequestsWithSameHeader(sessionPanel.getFilterRequestsWithSameHeader().isSelected());
						newSession.setRules(sessionPanel.getRules());
					}
					sessionPanel.setRunning();
					sessionPanel.getStatusPanel().init(newSession);
				}			
				for(RequestFilter filter : config.getRequestFilterList()) {
					filter.resetFilteredAmount();
				}
				centerPanel.initCenterPanel(sessionListChanged);
				createSessionButton.setEnabled(false);
				renameSessionButton.setEnabled(false);
				removeSessionButton.setEnabled(false);
				pauseButton.setEnabled(true);
				config.setRunning(true);
				startStopButton.setText(ANALYZER_STARTED_TEXT);
				sessionListChanged = false;
			}
		}
	}
	
	private void pauseButtonPressed() {
		if (config.isRunning()) {
			config.setRunning(false);
			pauseButton.setText(PLAY_TEXT);
			startStopButton.setText(ANALYZER_PAUSED_TEXT);
			pauseButton.setToolTipText("Currently Paused");
		}
		else {
			config.setRunning(true);
			pauseButton.setText(PAUSE_TEXT);
			startStopButton.setText(ANALYZER_STARTED_TEXT);
			pauseButton.setToolTipText("Currently Running");
		}
	}

	private String[] getInputArray(Component parentFrame, String message, String value) {
		String userInput = JOptionPane.showInputDialog(parentFrame, message, value);
		if (userInput == null) {
			return null;
		}
		String[] userInputParts = userInput.split(",");
		String[] inputs = new String[userInputParts.length];
		for (int i = 0; i < inputs.length; i++) {
			inputs[i] = userInputParts[i].trim();
		}
		return inputs;
	}

	private String getArrayAsString(String[] array) {
		String arrayAsString = "";
		if (array != null) {
			for (String arrayPart : array) {
				if (arrayAsString.equals("")) {
					arrayAsString = arrayPart;
				} else {
					arrayAsString += ", " + arrayPart;
				}
			}
		}
		return arrayAsString;
	}
}
