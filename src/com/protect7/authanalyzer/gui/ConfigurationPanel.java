package com.protect7.authanalyzer.gui;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Scanner;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTabbedPane;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.filter.FileTypeFilter;
import com.protect7.authanalyzer.filter.InScopeFilter;
import com.protect7.authanalyzer.filter.MethodFilter;
import com.protect7.authanalyzer.filter.OnlyProxyFilter;
import com.protect7.authanalyzer.filter.PathFilter;
import com.protect7.authanalyzer.filter.QueryFilter;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.StatusCodeFilter;
import com.protect7.authanalyzer.util.CurrentConfig;
import burp.BurpExtender;

public class ConfigurationPanel extends JPanel {

	private static final long serialVersionUID = -4278008236240529083L;
	private final String STORE_KEY_SETUP_NAMES = "ed17de8eed6f56e556310cddbe724270";
	private final String STORE_LAST_USED = "Last Used";
	private CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final String ANALYZER_STOPPED_TEXT = "<html><span style='color:red; font-weight: bold'>&#x26AB;</span> Analyzer Stopped</html>";
	private final String ANALYZER_STARTED_TEXT = "<html><span style='color:green; font-weight: bold'>&#x26AB;</span> Analyzer Running</html>";
	private final String ANALYZER_PAUSED_TEXT = "<html><span style='color:orange; font-weight: bold'>&#x26AB;</span> Analyzer Paused</html>";
	private final String DROP_REQUEST_TEXT = "Drop Original Requests";
	private final String STOP_DROP_REQUEST_TEXT = "<html><span style='color:red;'>Stop Drop Requests</span></html>";
	private JButton startStopButton = new JButton();
	private JButton pauseButton = new JButton();
	private JButton dropOriginalButton = new JButton(DROP_REQUEST_TEXT);
	private final JPanel filterPanel;
	private HashMap<String, SessionPanel> sessionPanelMap = new HashMap<>();
	private JButton createSessionButton;
	private JButton cloneSessionButton;
	private JButton renameSessionButton;
	private JButton removeSessionButton;
	private JButton saveSetupButton;
	private JButton loadSetupButton;
	private final String PAUSE_TEXT = "\u23f8";
	private final String PLAY_TEXT = "\u25b6";
	private final JTabbedPane sessionTabbedPane = new JTabbedPane();
	boolean sessionListChanged = true;
	private final CenterPanel centerPanel;
	private final JScrollPane scrollPane;

	public ConfigurationPanel(CenterPanel centerPanel, JScrollPane scrollPane) {
		this.centerPanel = centerPanel;
		this.scrollPane = scrollPane;
		JPanel sessionButtonPanel = new JPanel();
		sessionButtonPanel.setLayout(new BoxLayout(sessionButtonPanel, BoxLayout.Y_AXIS));
		createSessionButton = new JButton("New Session");
		cloneSessionButton = new JButton("Clone Session");
		cloneSessionButton.setEnabled(false);
		renameSessionButton = new JButton("Rename Session");
		renameSessionButton.setEnabled(false);
		removeSessionButton = new JButton("Remove Session");
		removeSessionButton.setEnabled(false);
		
		saveSetupButton = new JButton("Save Setup");
		loadSetupButton = new JButton("Load Setup");

		createSessionButton.addActionListener(e -> {
			String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of Session");
			if (sessionName != null && isSessionNameValid(sessionName)) {
				createSession(sessionName);
			}
		});

		cloneSessionButton.addActionListener(e -> {
			String newSessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of New Session");
			if (newSessionName != null && isSessionNameValid(newSessionName)) {
				int currentIndex = sessionTabbedPane.getSelectedIndex();
				String currentSessionName = sessionTabbedPane.getTitleAt(currentIndex);
				cloneSession(newSessionName, sessionPanelMap.get(currentSessionName));
			}
		});

		renameSessionButton.addActionListener(e -> {
			int currentIndex = sessionTabbedPane.getSelectedIndex();
			String currentTitle = sessionTabbedPane.getTitleAt(currentIndex);
			String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Rename Current Session:",
					currentTitle);
			if (sessionName != null && isSessionNameValid(sessionName)) {
				if (doModify()) {
					sessionTabbedPane.setTitleAt(currentIndex, sessionName);
					sessionPanelMap.put(sessionName, sessionPanelMap.get(currentTitle));
					sessionPanelMap.remove(currentTitle);
					sessionPanelMap.get(sessionName).setSessionName(sessionName);
				}
			}
		});

		removeSessionButton.addActionListener(e -> {
			if (doModify()) {
				int currentIndex = sessionTabbedPane.getSelectedIndex();
				sessionPanelMap.remove(sessionTabbedPane.getTitleAt(currentIndex));
				sessionTabbedPane.remove(currentIndex);
				if (sessionTabbedPane.getTabCount() == 0) {
					cloneSessionButton.setEnabled(false);
					renameSessionButton.setEnabled(false);
					removeSessionButton.setEnabled(false);
				}
			}
		});

		saveSetupButton.addActionListener(e -> saveSetup());

		loadSetupButton.addActionListener(e -> loadSetup());

		sessionButtonPanel.add(createSessionButton);
		sessionButtonPanel.add(cloneSessionButton);
		sessionButtonPanel.add(renameSessionButton);
		sessionButtonPanel.add(removeSessionButton);
		sessionButtonPanel.add(new JLabel(" "));
		sessionButtonPanel.add(saveSetupButton);
		sessionButtonPanel.add(loadSetupButton);

		filterPanel = new JPanel();
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

		JCheckBox onlyInScopeButton = new JCheckBox("Only In Scope");
		onlyInScopeButton.setSelected(true);
		addFilter(new InScopeFilter(filterPanel.getComponentCount(), "Only In Scope requests are analyzed"),
				onlyInScopeButton, "");
		filterPanel.add(onlyInScopeButton);

		JCheckBox onlyProxyButton = new JCheckBox("Only Proxy Traffic");
		onlyProxyButton.setSelected(true);
		addFilter(
				new OnlyProxyFilter(filterPanel.getComponentCount(),
						"Analyze only proxy traffic. Unselect to analyze repeater and proxy traffic."),
				onlyProxyButton, "");
		filterPanel.add(onlyProxyButton);

		JCheckBox fileTypeFilterButton = new JCheckBox("Exclude Filetypes");
		fileTypeFilterButton.setSelected(true);
		addFilter(new FileTypeFilter(filterPanel.getComponentCount(), "Excludes every specified filetype."),
				fileTypeFilterButton, "Enter filetypes to filter. Comma separated.\r\neg: jpg, png, js");
		filterPanel.add(fileTypeFilterButton);

		JCheckBox methodFilterButton = new JCheckBox("Exclude HTTP Methods");
		methodFilterButton.setSelected(true);
		addFilter(new MethodFilter(filterPanel.getComponentCount(), "Excludes every specified http method."),
				methodFilterButton, "Enter HTTP methods to filter. Comma separated.\r\neg: OPTIONS, TRACE");
		filterPanel.add(methodFilterButton);

		JCheckBox statusCodeFilterButton = new JCheckBox("Exclude Status Codes");
		statusCodeFilterButton.setSelected(true);
		addFilter(new StatusCodeFilter(filterPanel.getComponentCount(), "Excludes every specified status code."),
				statusCodeFilterButton, "Enter status codes to filter. Comma separated.\r\neg: 204, 304");
		filterPanel.add(statusCodeFilterButton);

		JCheckBox pathFilterButton = new JCheckBox("Exclude Paths");
		pathFilterButton.setSelected(false);
		addFilter(
				new PathFilter(filterPanel.getComponentCount(),
						"Excludes every path that contains one of the specified string literals."),
				pathFilterButton,
				"Enter String literals for paths to be excluded. Comma separated.\r\neg: log, libraries");
		filterPanel.add(pathFilterButton);

		JCheckBox queryFilterButton = new JCheckBox("Exclude Queries / Params");
		queryFilterButton.setSelected(false);
		addFilter(
				new QueryFilter(filterPanel.getComponentCount(),
						"Excludes every GET query that contains one of the specified string literals."),
				queryFilterButton,
				"Enter string literals for queries to be excluded. Comma separated.\r\neg: log, core");
		filterPanel.add(queryFilterButton);

		startStopButton.setText(ANALYZER_STOPPED_TEXT);
		startStopButton.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				try {
					startStopButtonPressed();
				} catch (Exception ex) {
					ex.printStackTrace(new PrintWriter(BurpExtender.callbacks.getStdout()));
				}

			}
		});

		pauseButton.setText(PAUSE_TEXT);
		pauseButton.setEnabled(false);
		pauseButton.addActionListener(e -> pauseButtonPressed());

		dropOriginalButton.addActionListener(e -> dropOriginalButtonPressed());
		dropOriginalButton.setEnabled(false);

		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.PAGE_START;
		c.insets = new Insets(40, 20, 20, 20);

		add(sessionButtonPanel, c);
		c.gridx = 1;
		c.insets = new Insets(5, 20, 20, 20);
		add(sessionTabbedPane, c);
		c.insets = new Insets(40, 20, 20, 40);
		c.gridx = 2;
		add(filterPanel, c);
		
		JPanel startStopButtonPanel = new JPanel();
		startStopButtonPanel.setLayout(new GridBagLayout());
		GridBagConstraints c1 = new GridBagConstraints();
		c1.anchor = GridBagConstraints.WEST;
		c1.gridy = 0;
		c1.gridx = 0;
		startStopButtonPanel.add(startStopButton, c1);
		c1.gridx = 1;
		startStopButtonPanel.add(pauseButton, c1);
		c1.gridy = 1;
		c1.gridx = 0;
		c1.gridwidth = 2;
		c1.insets = new Insets(10, 0, 0, 0);
		startStopButtonPanel.add(dropOriginalButton, c1);
		
		c.gridx = 3;
		add(startStopButtonPanel, c);
		
		/*c.gridx = 3;
		c.insets = new Insets(60, 0, 20, 0);
		add(startStopButton, c);
		c.gridx = 4;
		add(pauseButton, c);
		c.gridx = 5;
		c.insets = new Insets(90, -175, 0, 0);
		
		add(dropOriginalButton, c);*/

		try {
			String storedData = BurpExtender.callbacks.loadExtensionSetting(STORE_LAST_USED);
			loadSetup(storedData);
		} catch (Exception e) {
			sessionPanelMap.clear();
			sessionTabbedPane.removeAll();
			BurpExtender.callbacks.printOutput("Can not restore saved Data. Error Message: " + e.getMessage());
		}
	}

	private void saveSetup() {
		JFileChooser chooser = new JFileChooser();
		int status = chooser.showSaveDialog(this);
		if (status == JFileChooser.APPROVE_OPTION) {
			File file = chooser.getSelectedFile();
			if (!file.getName().endsWith(".json")) {
				String newFileName;
				if (file.getName().lastIndexOf(".") != -1) {
					int index = file.getAbsolutePath().lastIndexOf(".");
					newFileName = file.getAbsolutePath().substring(0, index);
				} else {
					newFileName = file.getAbsolutePath();
				}
				newFileName = newFileName + ".json";
				file = new File(newFileName);
			}
			try {
				FileWriter writer = new FileWriter(file);
				createSessionObjects(false);
				writer.write(getSetupAsJsonString());
				writer.close();
				JOptionPane.showMessageDialog(this, "Successfully saved to\n" + file.getAbsolutePath());
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Error. Can not write setup to JSON file. " + e.getMessage());
				JOptionPane.showMessageDialog(this, "Error.\nCan not write setup to JSON file.");
			}
		}
	}

	private void loadSetup() {
		if(doModify()) {
			JFileChooser chooser = new JFileChooser();
			int status = chooser.showOpenDialog(this);
			if (status == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if(selectedFile != null) {
					Scanner scanner;
					String jsonString = null;
					try {
						scanner = new Scanner(selectedFile);
						while (scanner.hasNextLine()) {
							jsonString = scanner.nextLine();
						}
						scanner.close();
						sessionTabbedPane.removeAll();
						loadSetup(jsonString);
						JOptionPane.showMessageDialog(this, "Setup successfully loaded");
					} catch (Exception e) {
						BurpExtender.callbacks.printError("Error. Can not load setup from JSON file. " + e.getMessage());
						JOptionPane.showMessageDialog(this, "Error.\nCan not load setup from JSON file.");
					}
				}
			}
		}
	}

	private void dropOriginalButtonPressed() {
		if (CurrentConfig.getCurrentConfig().isDropOriginal()) {
			setDropOriginalRequest(false);
		} else {
			setDropOriginalRequest(true);
		}
	}

	private void setDropOriginalRequest(boolean dropRequests) {
		if (dropRequests) {
			dropOriginalButton.setText(STOP_DROP_REQUEST_TEXT);
			CurrentConfig.getCurrentConfig().setDropOriginal(true);
		} else {
			dropOriginalButton.setText(DROP_REQUEST_TEXT);
			CurrentConfig.getCurrentConfig().setDropOriginal(false);
		}
	}

	private boolean isSessionNameValid(String sessionName) {
		if (sessionName != null && !sessionName.equals("") && !sessionPanelMap.containsKey(sessionName)
				&& !sessionName.equals("Original")) {
			return true;
		} else {
			JOptionPane.showMessageDialog(this, "The entered Session Name is invalid", "Session Name Invalid",
					JOptionPane.WARNING_MESSAGE);
			return false;
		}
	}

	private SessionPanel createSession(String sessionName) {
		if (doModify()) {
			SessionPanel sessionPanel = new SessionPanel(sessionName, scrollPane);
			sessionTabbedPane.add(sessionName, sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 1);
			sessionPanelMap.put(sessionName, sessionPanel);
			cloneSessionButton.setEnabled(true);
			renameSessionButton.setEnabled(true);
			removeSessionButton.setEnabled(true);
			return sessionPanel;
		} else {
			return null;
		}
	}

	private boolean cloneSession(String newSessionName, SessionPanel sessionPanelToClone) {
		if (doModify()) {
			SessionPanel sessionPanel = new SessionPanel(newSessionName, scrollPane);
			sessionPanel.setHeadersToReplaceText(sessionPanelToClone.getHeadersToReplaceText());
			sessionPanel.setFilterRequestsWithSameHeader(sessionPanelToClone.isFilterRequestsWithSameHeader());
			for (TokenPanel tokenPanel : sessionPanelToClone.getTokenPanelList()) {
				TokenPanel newTokenPanel = sessionPanel.addToken(tokenPanel.getTokenName());
				newTokenPanel.setIsRemoveToken(tokenPanel.isRemoveToken());
				if (tokenPanel.isAutoExtract()) {
					newTokenPanel.setAutoExtractFieldName(tokenPanel.getAutoExtractFieldName());
				}
				if (tokenPanel.isStaticValue()) {
					newTokenPanel.setStaticTokenValue(tokenPanel.getStaticTokenValue());
				}
				if (tokenPanel.isFromToString()) {
					newTokenPanel.setFromToString(tokenPanel.getGrepFromString(), tokenPanel.getGrepToString());
				}
				if (tokenPanel.isPromptForInput()) {
					newTokenPanel.setPromptForInput();
				}
			}
			sessionTabbedPane.add(newSessionName, sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 1);
			sessionPanelMap.put(newSessionName, sessionPanel);
			return true;
		} else {
			return false;
		}
	}

	// Creates a new session if session name not already exists and set header to
	// replace text
	public SessionPanel createSession(String sessionName, String headerToReplace) {
		if (!sessionPanelMap.containsKey(sessionName)) {
			SessionPanel sessionPanel = createSession(sessionName);
			if (sessionPanel != null) {
				sessionPanel.setHeadersToReplaceText(headerToReplace);
				return sessionPanel;
			}
		}
		return null;
	}

	private boolean doModify() {
		if (config.getTableModel().getRowCount() > 0 && !sessionListChanged) {
			int selection = JOptionPane.showConfirmDialog(this,
					"You are going to modify your session setup." + "\nTable data will be lost.",
					"Change Session Setup", JOptionPane.OK_CANCEL_OPTION);
			if (selection == JOptionPane.YES_OPTION) {
				sessionListChanged = true;
				centerPanel.clearTable();
				return true;
			} else {
				return false;
			}
		} else {
			sessionListChanged = true;
			return true;
		}
	}

	public SessionPanel getSessionPanelByName(String name) {
		return sessionPanelMap.get(name);
	}

	public void setSelectedSession(String sessionName) {
		for (int i = 0; i < sessionTabbedPane.getTabCount(); i++) {
			if (sessionTabbedPane.getTitleAt(i).equals(sessionName)) {
				sessionTabbedPane.setSelectedIndex(i);
				break;
			}
		}
	}

	public ArrayList<String> getSessionNames() {
		ArrayList<String> sessionNames = new ArrayList<String>();
		for (int i = 0; i < sessionTabbedPane.getTabCount(); i++) {
			sessionNames.add(sessionTabbedPane.getTitleAt(i));
		}
		return sessionNames;
	}

	private void addFilter(RequestFilter filter, JCheckBox onOffButton, String inputDialogText) {
		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
		setFilterToolTipText(filter);
		onOffButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (onOffButton.isSelected() && filter.hasStringLiterals()) {
					String[] inputArray = getInputArray(onOffButton, inputDialogText,
							getArrayAsString(filter.getFilterStringLiterals()));
					if (inputArray != null) {
						filter.setFilterStringLiterals(inputArray);
						setFilterToolTipText(filter);
					}
				}
			}
		});
	}

	private void setFilterToolTipText(RequestFilter filter) {
		JCheckBox filterCheckBox = filter.getOnOffButton();
		if (filterCheckBox != null) {
			if (filter.hasStringLiterals()) {
				filterCheckBox.setToolTipText("<html>" + filter.getDescription() + "<br>String literals: <em>"
						+ getArrayAsString(filter.getFilterStringLiterals()) + "</em></html>");
			} else {
				filterCheckBox.setToolTipText(filter.getDescription());
			}
		}
	}

	private void startStopButtonPressed() {
		if (sessionPanelMap.size() == 0) {
			JOptionPane.showMessageDialog(this, "No Session Created");
		} else {
			if (config.isRunning() || pauseButton.getText().equals(PLAY_TEXT)) {
				for (String session : sessionPanelMap.keySet()) {
					sessionPanelMap.get(session).setStopped();
				}
				createSessionButton.setEnabled(true);
				renameSessionButton.setEnabled(true);
				removeSessionButton.setEnabled(true);
				cloneSessionButton.setEnabled(true);
				saveSetupButton.setEnabled(true);
				loadSetupButton.setEnabled(true);
				pauseButton.setText(PAUSE_TEXT);
				pauseButton.setEnabled(false);
				dropOriginalButton.setEnabled(false);
				setDropOriginalRequest(false);
				config.setRunning(false);
				startStopButton.setText(ANALYZER_STOPPED_TEXT);
			} else {
				// Validate all defined Tokens first
				boolean success = true;
				for (String session : sessionPanelMap.keySet()) {
					SessionPanel sessionPanel = sessionPanelMap.get(session);
					if (!sessionPanel.tokensValid() || !sessionPanel.isHeaderValid() || !sessionPanel.isScopeValid()) {
						success = false;
						setSelectedSession(session);
						break;
					}
				}
				if (success) {
					createSessionObjects(true);
					// Auto Store
					try {
						storeSetup(STORE_LAST_USED);
					} catch (Exception e) {
						BurpExtender.callbacks.printOutput("Can not store setup. Error Message: " + e.getMessage());
					}
					
					for (RequestFilter filter : config.getRequestFilterList()) {
						filter.resetFilteredAmount();
					}

					centerPanel.initCenterPanel(sessionListChanged);
					createSessionButton.setEnabled(false);
					cloneSessionButton.setEnabled(false);
					renameSessionButton.setEnabled(false);
					removeSessionButton.setEnabled(false);
					saveSetupButton.setEnabled(false);
					loadSetupButton.setEnabled(false);
					pauseButton.setEnabled(true);
					dropOriginalButton.setEnabled(true);
					config.setRunning(true);
					startStopButton.setText(ANALYZER_STARTED_TEXT);
					sessionListChanged = false;
				}
			}
		}
	}
	
	private void createSessionObjects(boolean setRunning) {
		if(sessionPanelMap.size() != config.getSessions().size()) {
			sessionListChanged = true;
		}
		for (String session : sessionPanelMap.keySet()) {
			if(config.getSessionByName(session) == null) {
				sessionListChanged = true;
				break;
			}
		}
		if (sessionListChanged) {
			config.clearSessionList();
		}
		for (String session : sessionPanelMap.keySet()) {
			SessionPanel sessionPanel = sessionPanelMap.get(session);
			ArrayList<Token> tokenList = new ArrayList<Token>();
			for (TokenPanel tokenPanel : sessionPanel.getTokenPanelList()) {
				Token token = new Token(tokenPanel.getTokenName(), tokenPanel.getStaticTokenValue(),
						tokenPanel.getAutoExtractFieldName(), tokenPanel.getGrepFromString(),
						tokenPanel.getGrepToString(), tokenPanel.isRemoveToken(),
						tokenPanel.isAutoExtract(), tokenPanel.isStaticValue(), tokenPanel.isFromToString(),
						tokenPanel.isPromptForInput());
				tokenList.add(token);
			}
			Session newSession = null;
			if (sessionListChanged) {
				newSession = new Session(session, sessionPanel.getHeadersToReplaceText(),
						sessionPanel.isFilterRequestsWithSameHeader(), sessionPanel.isRestrictToScope(),
						sessionPanel.getScopeUrl(), tokenList, sessionPanel.getStatusPanel());
				config.addSession(newSession);
			} else {
				newSession = config.getSessionByName(session);
				newSession.setHeadersToReplace(sessionPanel.getHeadersToReplaceText());
				newSession.setFilterRequestsWithSameHeader(sessionPanel.isFilterRequestsWithSameHeader());
				newSession.setRestrictToScope(sessionPanel.isRestrictToScope());
				newSession.setScopeUrl(sessionPanel.getScopeUrl());
				for (Token newToken : tokenList) {
					for (Token oldToken : newSession.getTokens()) {
						if (newToken.getName().equals(oldToken.getName())) {
							newToken.setValue(oldToken.getValue());
							newToken.setRequest(oldToken.getRequest());
						}
					}
				}
				newSession.setTokens(tokenList);
			}
			if(setRunning) {
				sessionPanel.setRunning();
				sessionPanel.getStatusPanel().init(newSession);
			}
		}
	}

	private void storeSetup(String setupName) {
		String storedSetupNames = BurpExtender.callbacks.loadExtensionSetting(STORE_KEY_SETUP_NAMES);
		boolean alreadySaved = false;
		JsonArray storedSetupNameArray;
		if (storedSetupNames != null) {
			storedSetupNameArray = JsonParser.parseString(storedSetupNames).getAsJsonArray();
			for (JsonElement storedSetupName : storedSetupNameArray) {
				if (storedSetupName.getAsString().equals(setupName)) {
					alreadySaved = true;
					break;
				}
			}
		} else {
			storedSetupNameArray = new JsonArray();
		}
		if (!alreadySaved) {
			storedSetupNameArray.add(setupName);
			BurpExtender.callbacks.saveExtensionSetting(STORE_KEY_SETUP_NAMES, storedSetupNameArray.toString());
		}	
		BurpExtender.callbacks.saveExtensionSetting(setupName, getSetupAsJsonString());
	}
	
	private String getSetupAsJsonString() {
		JsonArray sessionArray = new JsonArray();
		for (Session session : config.getSessions()) {
			// Save Current Session Setup. No way to save extension settings on project
			// level
			Gson gson = new GsonBuilder().setExclusionStrategies(session.getExclusionStrategy()).create();
			String sessionJsonAsString = gson.toJson(session);
			JsonObject sessionElement = JsonParser.parseString(sessionJsonAsString).getAsJsonObject();
			sessionElement.addProperty("panelPosition",	sessionTabbedPane.indexOfTab(session.getName()));
			sessionElement.addProperty("name", session.getName());
			sessionArray.add(sessionElement);
		}

		JsonObject sessionsObject = new JsonObject();
		sessionsObject.add("sessions", sessionArray);

		JsonArray filterArray = new JsonArray();
		for (RequestFilter filter : config.getRequestFilterList()) {
			JsonObject filterElement = JsonParser.parseString(filter.toJson()).getAsJsonObject();
			filterArray.add(filterElement);
		}
		sessionsObject.add("filters", filterArray);
		return sessionsObject.toString();
	}

	private void loadSetup(String jsonString) {
		// Load Sessions
		JsonArray storedSessionsArray = JsonParser.parseString(jsonString).getAsJsonObject().get("sessions")
				.getAsJsonArray();
		SessionPanel[] sessionPanels = new SessionPanel[storedSessionsArray.size()];
		for (JsonElement sessionEl : storedSessionsArray) {
			JsonObject sessionObject = sessionEl.getAsJsonObject();
			String sessionName = sessionObject.get("name").getAsString();
			SessionPanel sessionPanel = new SessionPanel(sessionName, scrollPane);
			sessionPanel.setHeadersToReplaceText(sessionObject.get("headersToReplace").getAsString());
			sessionPanel
					.setFilterRequestsWithSameHeader(sessionObject.get("filterRequestsWithSameHeader").getAsBoolean());
			if (sessionObject.get("restrictToScope") != null) {
				sessionPanel.setRestrictToScope(sessionObject.get("restrictToScope").getAsBoolean());
			}
			if (sessionObject.get("scopeUrl") != null) {
				sessionPanel.setRestrictToScopeText(sessionObject.get("scopeUrl").getAsString());
			}
			JsonArray tokenArray = sessionObject.get("tokens").getAsJsonArray();
			for (JsonElement tokenElement : tokenArray) {
				JsonObject tokenObject = tokenElement.getAsJsonObject();
				// create new token panel for each token
				TokenPanel tokenPanel = sessionPanel.addToken(tokenObject.get("name").getAsString());
				tokenPanel.setIsRemoveToken(tokenObject.get("remove").getAsBoolean());
				tokenPanel.setTokenValueComboBox(tokenObject.get("autoExtract").getAsBoolean(),
						tokenObject.get("staticValue").getAsBoolean(), tokenObject.get("fromToString").getAsBoolean(),
						tokenObject.get("promptForInput").getAsBoolean());
				if (tokenObject.get("extractName") != null) {
					tokenPanel.setGenericTextFieldText(tokenObject.get("extractName").getAsString());
				} else if (tokenObject.get("grepFromString") != null && tokenObject.get("grepToString") != null) {
					tokenPanel.setGenericTextFieldText("from [" + tokenObject.get("grepFromString").getAsString()
							+ "] to [" + tokenObject.get("grepToString").getAsString() + "]");
				} else if (tokenObject.get("value") != null) {
					tokenPanel.setGenericTextFieldText(tokenObject.get("value").getAsString());
				}
			}
			sessionPanels[sessionObject.get("panelPosition").getAsInt()] = sessionPanel;
		}
		for (SessionPanel sessionPanel : sessionPanels) {
			sessionTabbedPane.add(sessionPanel.getSessionName(), sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 1);
			sessionPanelMap.put(sessionPanel.getSessionName(), sessionPanel);
			cloneSessionButton.setEnabled(true);
			renameSessionButton.setEnabled(true);
			removeSessionButton.setEnabled(true);
		}
		if (sessionTabbedPane.getSelectedIndex() > 0) {
			sessionTabbedPane.setSelectedIndex(0);
		}

		// Load Filters
		JsonArray storedFiltersArray = JsonParser.parseString(jsonString).getAsJsonObject().get("filters")
				.getAsJsonArray();
		for (JsonElement filterEl : storedFiltersArray) {
			JsonObject filterObject = filterEl.getAsJsonObject();
			RequestFilter requestFilter = config.getRequestFilterAt(filterObject.get("filterIndex").getAsInt());
			requestFilter.setIsSelected(filterObject.get("isSelected").getAsBoolean());
			if (filterObject.get("stringLiterals") != null) {
				JsonArray tokenArray = filterObject.get("stringLiterals").getAsJsonArray();
				String[] stringLiterals = new String[tokenArray.size()];
				for (int i = 0; i < tokenArray.size(); i++) {
					stringLiterals[i] = tokenArray.get(i).getAsString();
				}
				requestFilter.setFilterStringLiterals(stringLiterals);
				setFilterToolTipText(requestFilter);
			}
		}
	}

	private void pauseButtonPressed() {
		if (config.isRunning()) {
			config.setRunning(false);
			pauseButton.setText(PLAY_TEXT);
			startStopButton.setText(ANALYZER_PAUSED_TEXT);
			pauseButton.setToolTipText("Currently Paused");
		} else {
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
