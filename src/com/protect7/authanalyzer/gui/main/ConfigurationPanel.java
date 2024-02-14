package com.protect7.authanalyzer.gui.main;

import java.awt.Component;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Scanner;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JToggleButton;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import com.google.gson.Gson;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.reflect.TypeToken;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.MatchAndReplace;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenBuilder;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.filter.FileTypeFilter;
import com.protect7.authanalyzer.filter.InScopeFilter;
import com.protect7.authanalyzer.filter.MethodFilter;
import com.protect7.authanalyzer.filter.OnlyProxyFilter;
import com.protect7.authanalyzer.filter.PathFilter;
import com.protect7.authanalyzer.filter.QueryFilter;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.filter.StatusCodeFilter;
import com.protect7.authanalyzer.gui.dialog.SettingsDialog;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.entity.TokenPanel;
import com.protect7.authanalyzer.gui.listener.CloneSessionListener;
import com.protect7.authanalyzer.gui.listener.DeleteSessionListener;
import com.protect7.authanalyzer.gui.listener.NewSessionListener;
import com.protect7.authanalyzer.gui.listener.RenameSessionListener;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.gui.util.SessionTabbedPane;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.BurpExtender;

public class ConfigurationPanel extends JPanel {

	private static final long serialVersionUID = -4278008236240529083L;
	private final CurrentConfig config = CurrentConfig.getCurrentConfig();
	private final String ANALYZER_STOPPED_TEXT = "<html><span style='color:red; font-weight: bold'>&#x26AB;</span> Analyzer Stopped</html>";
	private final String ANALYZER_STARTED_TEXT = "<html><span style='color:green; font-weight: bold'>&#x26AB;</span> Analyzer Running</html>";
	private final String ANALYZER_PAUSED_TEXT = "<html><span style='color:orange; font-weight: bold'>&#x26AB;</span> Analyzer Paused</html>";
	private final String DROP_REQUEST_TEXT = "Drop Original Requests";
	private final String STOP_DROP_REQUEST_TEXT = "Stop Drop Requests";
	private final JButton startStopButton = new JButton();
	private final JButton pauseButton = new JButton();
	//private final JLabel pendingRequestsLabel = new JLabel("Pending Requests Queue: 0");
	private final JToggleButton dropOriginalButton = new JToggleButton(DROP_REQUEST_TEXT);
	private final JPanel filterPanel;
	private final LinkedHashMap<String, SessionPanel> sessionPanelMap = new LinkedHashMap<>();
	private final String PAUSE_TEXT = "\u23f8";
	private final String PLAY_TEXT = "\u25b6";
	private final SessionTabbedPane sessionTabbedPane = new SessionTabbedPane();
	boolean sessionListChanged = true;
	private final MainPanel mainPanel;

	public ConfigurationPanel(MainPanel mainPanel) {
		this.mainPanel = mainPanel;	
		sessionTabbedPane.addNewSessionListener(new NewSessionListener() {
			@Override
			public void newSession() {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of Session");
				if (sessionName != null && isSessionNameValid(sessionName)) {
					createSession(sessionName);
				}
			}
		});
		
		sessionTabbedPane.addCloneSessionListener(new CloneSessionListener() {
			
			@Override
			public void cloneSession() {
				String newSessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Enter Name of New Session");
				if (newSessionName != null && isSessionNameValid(newSessionName)) {
					int currentIndex = sessionTabbedPane.getSelectedIndex();
					String currentSessionName = sessionTabbedPane.getTitleAt(currentIndex);
					doCloneSession(newSessionName, sessionPanelMap.get(currentSessionName));
				}
			}
		});
		
		sessionTabbedPane.addRenameSessionListener(new RenameSessionListener() {
			@Override
			public void renameSession(String currentName) {
				String sessionName = JOptionPane.showInputDialog(sessionTabbedPane, "Rename Current Session:",
						currentName);
				if (sessionName != null && isSessionNameValid(sessionName)) {
					if (doModify()) {
						sessionTabbedPane.setTitleAt(getTabbedPaneIndexForTitle(currentName), sessionName);
						sessionPanelMap.put(sessionName, sessionPanelMap.get(currentName));
						sessionPanelMap.remove(currentName);
						sessionPanelMap.get(sessionName).setSessionName(sessionName);
					}
				}
			}
		});
		
		sessionTabbedPane.addDeleteSessionListener(new DeleteSessionListener() {		
			@Override
			public void deleteSession(String title) {
				if (doModify()) {
					sessionPanelMap.remove(title);
					sessionTabbedPane.remove(getTabbedPaneIndexForTitle(title));
					sessionTabbedPane.setSelectedIndex(0);
				}
			}
		});

		filterPanel = new JPanel();
		filterPanel.setLayout(new BoxLayout(filterPanel, BoxLayout.Y_AXIS));

		HintCheckBox onlyInScopeButton = new HintCheckBox("Only In Scope");
		onlyInScopeButton.setSelected(true);
		addFilter(new InScopeFilter(filterPanel.getComponentCount(), "Only In Scope requests are analyzed"),
				onlyInScopeButton, "");
		filterPanel.add(onlyInScopeButton);

		HintCheckBox onlyProxyButton = new HintCheckBox("Only Proxy Traffic");
		onlyProxyButton.setSelected(true);
		addFilter(
				new OnlyProxyFilter(filterPanel.getComponentCount(),
						"Analyze only proxy traffic. Unselect to analyze repeater and proxy traffic"),
				onlyProxyButton, "");
		filterPanel.add(onlyProxyButton);

		HintCheckBox fileTypeFilterButton = new HintCheckBox("Exclude Filetypes");
		fileTypeFilterButton.setSelected(true);
		addFilter(new FileTypeFilter(filterPanel.getComponentCount(), "Excludes every specified filetype"),
				fileTypeFilterButton, "Enter filetypes to filter. Comma separated.\r\neg: jpg, png, js");
		filterPanel.add(fileTypeFilterButton);

		HintCheckBox methodFilterButton = new HintCheckBox("Exclude HTTP Methods");
		methodFilterButton.setSelected(true);
		addFilter(new MethodFilter(filterPanel.getComponentCount(), "Excludes every specified http method"),
				methodFilterButton, "Enter HTTP methods to filter. Comma separated.\r\neg: OPTIONS, TRACE");
		filterPanel.add(methodFilterButton);

		HintCheckBox statusCodeFilterButton = new HintCheckBox("Exclude Status Codes");
		statusCodeFilterButton.setSelected(true);
		addFilter(new StatusCodeFilter(filterPanel.getComponentCount(), "Excludes every specified status code"),
				statusCodeFilterButton, "Enter status codes to filter. Comma separated.\r\neg: 204, 304");
		filterPanel.add(statusCodeFilterButton);

		HintCheckBox pathFilterButton = new HintCheckBox("Exclude Paths");
		pathFilterButton.setSelected(false);
		addFilter(
				new PathFilter(filterPanel.getComponentCount(),
						"Excludes every path that contains one of the specified string literals"),
				pathFilterButton,
				"Enter String literals for paths to be excluded. Comma separated.\r\neg: log, libraries");
		filterPanel.add(pathFilterButton);

		HintCheckBox queryFilterButton = new HintCheckBox("Exclude Queries / Params");
		queryFilterButton.setSelected(false);
		addFilter(
				new QueryFilter(filterPanel.getComponentCount(),
						"Excludes every GET query that contains one of the specified string literals"),
				queryFilterButton,
				"Enter string literals for queries to be excluded. Comma separated.\r\neg: log, core");
		filterPanel.add(queryFilterButton);
		startStopButton.putClientProperty("html.disable", null);
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
		
		JButton settingsButton = new JButton("Settings");
		settingsButton.addActionListener(e -> new SettingsDialog(this));

		setLayout(new GridBagLayout());
		JPanel startStopButtonPanel = new JPanel();
		startStopButtonPanel.setLayout(new GridBagLayout());
		GridBagConstraints c1 = new GridBagConstraints();
		c1.fill = GridBagConstraints.BOTH;
		c1.gridx = 0;
		c1.insets = new Insets(10, 0, 0, 5);
		c1.gridy = 1;
		c1.gridwidth = 1;
		startStopButtonPanel.add(startStopButton, c1);
		c1.gridx = 1;
		startStopButtonPanel.add(pauseButton, c1);
		c1.gridy = 2;
		c1.gridx = 0;
		c1.gridwidth = 2;
		startStopButtonPanel.add(dropOriginalButton, c1);
		c1.gridy = 3;
		startStopButtonPanel.add(new JLabel(" "), c1);
		c1.gridy = 4;
		startStopButtonPanel.add(settingsButton, c1);
		
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.PAGE_START;
		c.insets = new Insets(10, 20, 20, 20);

		add(startStopButtonPanel, c);
		c.gridx = 1;
		c.insets = new Insets(5, 20, 20, 20);
		sessionTabbedPane.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Sessions"), new EmptyBorder(3, 3, 3, 3)));
		add(sessionTabbedPane, c);
		c.insets = new Insets(5, 20, 20, 25);
		c.gridx = 2;
		filterPanel.setBorder(new CompoundBorder(BorderFactory.createTitledBorder("Filters"), new EmptyBorder(3, 3, 3, 3)));
		add(filterPanel, c);
		
	}

	public void loadAutoStoredData() {
		try {
			String storedData = DataStorageProvider.loadSetup();
			if(storedData != null) {
				loadSetup(storedData);
				mainPanel.updateDividerLocation();
			}
		} catch (Exception e) {
			BurpExtender.callbacks.printOutput("Can not restore saved Data. Error Message: " + e.getMessage());
		}
		if(sessionTabbedPane.getTabCount() == 1) {
			createSession("user1");
		}
		sessionTabbedPane.setSelectedIndex(0);
	}
	
	public void saveSetup() {
		JFileChooser chooser = new JFileChooser();
		chooser.setSelectedFile(new File("Auth_Analyzer_Setup.json"));
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
				writer.write(DataStorageProvider.getSetupAsJsonString());
				writer.close();
				JOptionPane.showMessageDialog(this, "Successfully saved to\n" + file.getAbsolutePath());
			} catch (Exception e) {
				BurpExtender.callbacks.printError("Error. Can not write setup to JSON file. " + e.getMessage());
				JOptionPane.showMessageDialog(this, "Error.\nCan not write setup to JSON file.");
			}
		}
	}

	public void loadSetup() {
		if(doModify()) {
			JFileChooser chooser = new JFileChooser();
			int status = chooser.showOpenDialog(this);
			if (status == JFileChooser.APPROVE_OPTION) {
				File selectedFile = chooser.getSelectedFile();
				if(selectedFile != null) {
					Scanner scanner;
					String jsonString = "";
					try {
						scanner = new Scanner(selectedFile);
						while (scanner.hasNextLine()) {
							jsonString += scanner.nextLine();
						}
						scanner.close();
						sessionTabbedPane.removeAll();
						loadSetup(jsonString);
						mainPanel.updateDividerLocation();
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
			dropOriginalButton.setSelected(true);
			CurrentConfig.getCurrentConfig().setDropOriginal(true);
		} else {
			dropOriginalButton.setText(DROP_REQUEST_TEXT);
			dropOriginalButton.setSelected(false);
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
			SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
			sessionTabbedPane.add(sessionName, sessionPanel);
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 2);
			sessionPanelMap.put(sessionName, sessionPanel);
			return sessionPanel;
		} else {
			return null;
		}
	}

	private boolean doCloneSession(String newSessionName, SessionPanel sessionPanelToClone) {
		if (doModify()) {
			SessionPanel sessionPanel = new SessionPanel(newSessionName, mainPanel);
			sessionPanel.setHeadersToReplaceText(sessionPanelToClone.getHeadersToReplaceText());
			sessionPanel.setHeadersToRemoveText(sessionPanelToClone.getHeadersToRemoveText());
			sessionPanel.setRemoveHeaders(sessionPanelToClone.isRemoveHeaders());
			sessionPanel.setFilterRequestsWithSameHeader(sessionPanelToClone.isFilterRequestsWithSameHeader());
			sessionPanel.setRestrictToScope(sessionPanelToClone.isRestrictToScope());
			sessionPanel.setRestrictToScopeText(sessionPanelToClone.getRestrictToScopeText());
			sessionPanel.setTestCors(sessionPanelToClone.isTestCors());
			sessionPanel.setMatchAndReplaceList(sessionPanelToClone.getMatchAndReplaceList());
			for (TokenPanel tokenPanel : sessionPanelToClone.getTokenPanelList()) {
				TokenPanel newTokenPanel = sessionPanel.addToken(tokenPanel.getTokenName());
				newTokenPanel.setTokenLocationSet(tokenPanel.getTokenLocationSet());
				newTokenPanel.setAutoExtractLocationSet(tokenPanel.getAutoExtractLocationSet());
				newTokenPanel.setFromToExtractLocationSet(tokenPanel.getFromToExtractLocationSet());
				newTokenPanel.setIsRemoveToken(tokenPanel.isRemoveToken());
				newTokenPanel.setAddTokenIfNotExists(tokenPanel.isAddTokenIfNotExists());
				newTokenPanel.setCaseSensitiveTokenName(tokenPanel.isCaseSensitiveTokenName());
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
			sessionTabbedPane.setSelectedIndex(sessionTabbedPane.getTabCount() - 2);
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
				mainPanel.getCenterPanel().clearTable();
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
		int index = getTabbedPaneIndexForTitle(sessionName);
		if(index != -1) {
			sessionTabbedPane.setSelectedIndex(index);
		}
	}
	
	private int getTabbedPaneIndexForTitle(String title) {
		for (int i = 0; i < sessionTabbedPane.getTabCount()-1; i++) {
			if (sessionTabbedPane.getTitleAt(i).equals(title)) {
				return i;
			}
		}
		return -1;
	}

	public ArrayList<String> getSessionNames() {
		ArrayList<String> sessionNames = new ArrayList<String>();
		for (int i = 0; i < sessionTabbedPane.getTabCount()-1; i++) {
			sessionNames.add(sessionTabbedPane.getTitleAt(i));
		}
		return sessionNames;
	}

	private void addFilter(RequestFilter filter, HintCheckBox onOffButton, String inputDialogText) {
		config.addRequestFilter(filter);
		filter.registerOnOffButton(onOffButton);
		onOffButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				if (onOffButton.isSelected() && filter.hasStringLiterals()) {
					String[] inputArray = getInputArray(onOffButton, inputDialogText,
							GenericHelper.getArrayAsString(filter.getFilterStringLiterals()));
					if (inputArray != null) {
						filter.setFilterStringLiterals(inputArray);
					}
				}
			}
		});
	}

	public void startStopButtonPressed() {
		if (sessionPanelMap.size() == 0) {
			JOptionPane.showMessageDialog(this, "No Session Created");
		} else {
			if (config.isRunning() || pauseButton.getText().equals(PLAY_TEXT)) {
				for (String session : sessionPanelMap.keySet()) {
					sessionPanelMap.get(session).setStopped();
				}
				sessionTabbedPane.setModifEnabled(true);
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
						DataStorageProvider.saveSetup();
					} catch (Exception e) {
						BurpExtender.callbacks.printOutput("Can not store setup. Error Message: " + e.getMessage());
					}
					
					for (RequestFilter filter : config.getRequestFilterList()) {
						filter.resetFilteredAmount();
					}

					if(sessionListChanged) {
						mainPanel.getCenterPanel().initCenterPanel();
					}
					sessionTabbedPane.setModifEnabled(false);
					pauseButton.setEnabled(true);
					dropOriginalButton.setEnabled(true);
					config.setRunning(true);
					startStopButton.setText(ANALYZER_STARTED_TEXT);
					sessionListChanged = false;
				}
			}
			mainPanel.updateDividerLocation();
		}
	}
	
	public void createSessionObjects(boolean setRunning) {
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
				Token token = new TokenBuilder()
						.setName(tokenPanel.getTokenName())
						.setTokenLocationSet(tokenPanel.getTokenLocationSet())
						.setAutoExtractLocationSet(tokenPanel.getAutoExtractLocationSet())
						.setFromToExtractLocationSet(tokenPanel.getFromToExtractLocationSet())
						.setValue(tokenPanel.getStaticTokenValue())
						.setExtractName(tokenPanel.getAutoExtractFieldName())
						.setGrepFromString(tokenPanel.getGrepFromString())
						.setGrepToString(tokenPanel.getGrepToString())
						.setIsRemove(tokenPanel.isRemoveToken())
						.setIsAutoExtract(tokenPanel.isAutoExtract())
						.setIsStaticValue(tokenPanel.isStaticValue())
						.setIsFromToString(tokenPanel.isFromToString())
						.setIsPromptForInput(tokenPanel.isPromptForInput())
						.setIsCaseSensitiveTokenName(tokenPanel.isCaseSensitiveTokenName())
						.setIsAddIfNotExists(tokenPanel.isAddTokenIfNotExists())
						.setIsUrlEncoded(tokenPanel.isUrlEncoded())
						.setAliases(tokenPanel.getAliases())
						.build();
				tokenList.add(token);
			}
			Session newSession = null;
			if (sessionListChanged) {
				newSession = new Session(session, sessionPanel.getHeadersToReplaceText(), sessionPanel.isRemoveHeaders(),
						sessionPanel.getHeadersToRemoveText(), sessionPanel.isFilterRequestsWithSameHeader(), sessionPanel.isRestrictToScope(),
						sessionPanel.getScopeUrl(), sessionPanel.isTestCors(), tokenList, sessionPanel.getMatchAndReplaceList(), sessionPanel.getStatusPanel());
				config.addSession(newSession);
			} else {
				newSession = config.getSessionByName(session);
				newSession.setHeadersToReplace(sessionPanel.getHeadersToReplaceText());
				newSession.setRemoveHeaders(sessionPanel.isRemoveHeaders());
				newSession.setHeadersToRemove(sessionPanel.getHeadersToRemoveText());
				newSession.setFilterRequestsWithSameHeader(sessionPanel.isFilterRequestsWithSameHeader());
				newSession.setRestrictToScope(sessionPanel.isRestrictToScope());
				newSession.setScopeUrl(sessionPanel.getScopeUrl());
				newSession.setTestCors(sessionPanel.isTestCors());
				newSession.setMatchAndReplaceList(sessionPanel.getMatchAndReplaceList());
				for (Token newToken : tokenList) {
					for (Token oldToken : newSession.getTokens()) {
						if (newToken.getName().equals(oldToken.getName())) {
							if(newToken.isAutoExtract() && oldToken.isAutoExtract() ||
								newToken.isFromToString() && oldToken.isFromToString()) {
									newToken.setValue(oldToken.getValue());
									newToken.setRequestResponse(oldToken.getRequestResponse());
								}
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

	private void loadSetup(String jsonString) {
		sessionPanelMap.clear();
		sessionTabbedPane.removeAll();
		// Load Sessions
		JsonArray storedSessionsArray = JsonParser.parseString(jsonString).getAsJsonObject().get("sessions")
				.getAsJsonArray();
		for (JsonElement sessionEl : storedSessionsArray) {
			JsonObject sessionObject = sessionEl.getAsJsonObject();
			String sessionName = sessionObject.get("name").getAsString();
			SessionPanel sessionPanel = new SessionPanel(sessionName, mainPanel);
			sessionPanel.setHeadersToReplaceText(sessionObject.get("headersToReplace").getAsString());
			sessionPanel
					.setFilterRequestsWithSameHeader(sessionObject.get("filterRequestsWithSameHeader").getAsBoolean());
			if(sessionObject.get("removeHeaders") != null) {
				sessionPanel.setRemoveHeaders(sessionObject.get("removeHeaders").getAsBoolean());
			}
			if(sessionObject.get("headersToRemove") != null) {
				sessionPanel.setHeadersToRemoveText(sessionObject.get("headersToRemove").getAsString());
			}
			if (sessionObject.get("restrictToScope") != null) {
				sessionPanel.setRestrictToScope(sessionObject.get("restrictToScope").getAsBoolean());
			}
			if (sessionObject.get("scopeUrl") != null) {
				sessionPanel.setRestrictToScopeText(sessionObject.get("scopeUrl").getAsString());
			}
			if (sessionObject.get("testCors") != null) {
				sessionPanel.setTestCors(sessionObject.get("testCors").getAsBoolean());
			}
			if(sessionObject.get("matchAndReplaceList") != null) {
				JsonArray matchAndReplaceArray = sessionObject.get("matchAndReplaceList").getAsJsonArray();
				ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
				for (JsonElement matchAndReplaceElement : matchAndReplaceArray) {
					JsonObject matchAndReplaceObject = matchAndReplaceElement.getAsJsonObject();
					if(matchAndReplaceObject.get("match") != null && matchAndReplaceObject.get("replace") != null) {
						matchAndReplaceList.add(new MatchAndReplace(matchAndReplaceObject.get("match").getAsString(), 
								matchAndReplaceObject.get("replace").getAsString()));
					}
				}
				sessionPanel.setMatchAndReplaceList(matchAndReplaceList);
			}
			JsonArray tokenArray = sessionObject.get("tokens").getAsJsonArray();
			for (JsonElement tokenElement : tokenArray) {
				JsonObject tokenObject = tokenElement.getAsJsonObject();
				// create new token panel for each token
				TokenPanel tokenPanel = sessionPanel.addToken(tokenObject.get("name").getAsString());
				if(tokenObject.get("tokenLocationSet") != null) {
					Type type = new TypeToken<EnumSet<TokenLocation>>(){}.getType();
					EnumSet<TokenLocation> tokenLocationSet =  new Gson().fromJson(tokenObject.get("tokenLocationSet"), type);
					tokenPanel.setTokenLocationSet(tokenLocationSet);
				}
				if(tokenObject.get("autoExtractLocationSet") != null) {
					Type type = new TypeToken<EnumSet<AutoExtractLocation>>(){}.getType();
					EnumSet<AutoExtractLocation> autoExtractLocationSet =  new Gson().fromJson(tokenObject.get("autoExtractLocationSet"), type);
					tokenPanel.setAutoExtractLocationSet(autoExtractLocationSet);
				}
				if(tokenObject.get("fromToExtractLocationSet") != null) {
					Type type = new TypeToken<EnumSet<FromToExtractLocation>>(){}.getType();
					EnumSet<FromToExtractLocation> fromToExtractLocationSet =  new Gson().fromJson(tokenObject.get("fromToExtractLocationSet"), type);
					tokenPanel.setFromToExtractLocationSet(fromToExtractLocationSet);
				}
				if(tokenObject.get("addIfNotExists") != null) {
					tokenPanel.setAddTokenIfNotExists(tokenObject.get("addIfNotExists").getAsBoolean());
				}
				if(tokenObject.get("urlEncoded") != null) {
					tokenPanel.setUrlEncoded(tokenObject.get("urlEncoded").getAsBoolean());
				}
				if(tokenObject.get("caseSensitiveTokenName") != null) {
					tokenPanel.setCaseSensitiveTokenName(tokenObject.get("caseSensitiveTokenName").getAsBoolean());
				}
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
			sessionTabbedPane.add(sessionPanel.getSessionName(), sessionPanel);
			sessionPanelMap.put(sessionPanel.getSessionName(), sessionPanel);
			sessionTabbedPane.setModifEnabled(true);
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
			}
		}
	}

	public void pauseButtonPressed() {
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
	
	public boolean isPaused() {
		return pauseButton.getText().equals(PLAY_TEXT);
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
}