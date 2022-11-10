package com.protect7.authanalyzer.gui.entity;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.ArrayList;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.UIManager;
import com.protect7.authanalyzer.entities.MatchAndReplace;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.gui.dialog.MatchAndReplaceDialog;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.gui.util.PlaceholderTextArea;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Globals;

public class SessionPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private final int textFieldWidth = 70;
	private String sessionName = "";
	private final PlaceholderTextArea headersToReplaceText = new PlaceholderTextArea(3, textFieldWidth);
	private final HintCheckBox removeHeaders;
	private final JCheckBox filterRequestsWithSameHeader;
	private final HintCheckBox restrictToScope;
	private final HintCheckBox testCors;
	private final JLabel headerToRemoveLabel = new JLabel("Header(s) to Remove");
	private final PlaceholderTextArea headersToRemoveText = new PlaceholderTextArea(3, textFieldWidth);
	private final JLabel restrictToScopeLabel = new JLabel("Restrict to Scope");
	private final PlaceholderTextField restrictToScopeText = new PlaceholderTextField();
	private final JButton addTokenButton;
	private final JButton matchAndReplaceButton;
	private final JPanel sessionPanel = new JPanel();
	private final StatusPanel statusPanel = new StatusPanel();
	private final GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<TokenPanel> tokenPanels = new ArrayList<TokenPanel>();
	private ArrayList<MatchAndReplace> matchAndReplaceList = new ArrayList<MatchAndReplace>();
	private final MainPanel mainPanel;

	public SessionPanel(String sessionName, MainPanel mainPanel) {
		this.sessionName = sessionName;
		this.mainPanel = mainPanel;
		sessionPanel.setLayout(new GridBagLayout());
		c.gridx = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridwidth = 4;
		c.weighty = 1;
		
		statusPanel.setVisible(false);
		add(statusPanel, c);
		setupContextMenu();

		JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
		c.gridy = 0;
		sessionPanel.add(headerToReplaceLabel, c);
		headersToReplaceText.setAlignmentX(Component.LEFT_ALIGNMENT);
		headersToReplaceText.setPlaceholder("Cookie: Session=d3c2b484-5fed-11eb-ae93-0242ac130002;"); 
		c.gridy++;
		sessionPanel.add(headersToReplaceText, c);
		headersToReplaceText.setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		headersToReplaceText.putClientProperty("html.disable", null);
		removeHeaders = new HintCheckBox("Remove Header(s)", false, "The defined Headers will be removed");
		c.gridwidth = 1;
		c.insets = new Insets(5, 0, 0, 20);
		c.gridy++;
		sessionPanel.add(removeHeaders, c);
		
		filterRequestsWithSameHeader = new JCheckBox("Filter requests with same header(s)", false);
		c.gridx = 1;
		//sessionPanel.add(filterRequestsWithSameHeader, c);
		restrictToScope = new HintCheckBox("Restrict to Scope", false, "Session will only be repeated for defined Scope / Path");
		c.gridx = 2;
		sessionPanel.add(restrictToScope, c);
		
		//testCors = new JCheckBox("Test CORS", false);
		testCors = new HintCheckBox("Test CORS", false, "HTTP Method will be set to OPTIONS");
		c.gridx = 3;
		sessionPanel.add(testCors, c);
		
		c.gridwidth = 4;
		c.gridx = 0;
		c.gridy++;
		headerToRemoveLabel.setVisible(false);
		sessionPanel.add(headerToRemoveLabel, c);
		c.gridy++;
		c.insets = new Insets(0, 0, 0, 0);
		headersToRemoveText.setPlaceholder("Cookie:"); 
		headersToRemoveText.setVisible(false);
		sessionPanel.add(headersToRemoveText, c);
		removeHeaders.addActionListener(e -> updateGui());		
		
		c.gridy++;
		c.insets = new Insets(5, 0, 0, 0);
		restrictToScopeLabel.setVisible(false);
		sessionPanel.add(restrictToScopeLabel, c);
		c.gridy++;
		c.insets = new Insets(0, 0, 0, 0);
		restrictToScopeText.setPlaceholder("https://restrict_to_this.domain/restrict/to/this/path");
		restrictToScopeText.setVisible(false);
		sessionPanel.add(restrictToScopeText, c);
		restrictToScope.addActionListener(e -> updateGui());
		
		c.gridy++;
		c.insets = new Insets(5, 0, 0, 0);
		sessionPanel.add(new JSeparator(), c);

		JPanel buttonPanel = new JPanel();
		addTokenButton = new JButton("Add Parameter");
		addTokenButton.addActionListener(e -> addToken());
		buttonPanel.add(addTokenButton);
		matchAndReplaceButton = new JButton("Match and Replace");
		matchAndReplaceButton.addActionListener(e -> {
			new MatchAndReplaceDialog(this);
		});
		buttonPanel.add(matchAndReplaceButton);
		JButton infoButton = new JButton("?");
		infoButton.addActionListener(e -> {
			
			try {
				Desktop.getDesktop().browse(new URI(Globals.URL_GITHUB_PARAMETER_HELP));
			} catch (Exception e1) {
				JOptionPane.showMessageDialog(this, "Browser can not be opened.", "Error", JOptionPane.WARNING_MESSAGE);
			}
		});
		buttonPanel.add(infoButton);
		c.gridy++;
		c.fill = GridBagConstraints.VERTICAL;
		sessionPanel.add(buttonPanel, c);
		c.insets = new Insets(0, 0, 0, 0);
		add(sessionPanel);
	}
	
	private void updateGui() {
		if(removeHeaders.isSelected()) {
			headerToRemoveLabel.setVisible(true);
			headersToRemoveText.setVisible(true);
		}
		else {
			headerToRemoveLabel.setVisible(false);
			headersToRemoveText.setVisible(false);
		}
		if(restrictToScope.isSelected()) {
			restrictToScopeLabel.setVisible(true);
			restrictToScopeText.setVisible(true);
		}
		else {
			restrictToScopeLabel.setVisible(false);
			restrictToScopeText.setVisible(false);
		}
		revalidate();
		mainPanel.updateDividerLocation();
	}
	
	public void updateMatchAndReplaceButtonText() {
		if(matchAndReplaceList.size() > 0) {
			matchAndReplaceButton.setText("Match and Replace (" + matchAndReplaceList.size() + ")");
		}
		else {
			matchAndReplaceButton.setText("Match and Replace");
		}
	}

	public void setRunning() {
		statusPanel.setVisible(true);
		sessionPanel.setVisible(false);
	}

	public void setStopped() {
		statusPanel.setVisible(false);
		sessionPanel.setVisible(true);
	}

	private TokenPanel addToken() {
		TokenPanel tokenPanel = new TokenPanel();
		if(tokenPanels.size() > 0) {
			tokenPanel.setHeaderVisible(false);
		}
		tokenPanels.add(tokenPanel);
		c.gridy++;
		sessionPanel.add(tokenPanel, c);
		sessionPanel.revalidate();
		
		tokenPanel.getRemoveButton().addActionListener(e -> {
			sessionPanel.remove(tokenPanel);
			tokenPanels.remove(tokenPanel);
			if(tokenPanels.size() > 0) {
				tokenPanels.get(0).setHeaderVisible(true);
			}
			revalidate();
			mainPanel.updateDividerLocation();
		});
		mainPanel.updateDividerLocation();
		return tokenPanel;
	}
	
	public TokenPanel addToken(String name) {
		TokenPanel tokenPanel = addToken();
		tokenPanel.setTokenName(name);
		//Set Token Extract Field Name as well
		tokenPanel.setAutoExtractFieldName(name);
		return tokenPanel;
	}
	
	public TokenPanel addToken(Token token) {
		TokenPanel tokenPanel = addToken(token.getName());
		tokenPanel.setTokenLocationSet(token.getTokenLocationSet());
		tokenPanel.setTokenLocationSet(token.getTokenLocationSet());
		tokenPanel.setAutoExtractLocationSet(token.getAutoExtractLocationSet());
		tokenPanel.setFromToExtractLocationSet(token.getFromToExtractLocationSet());
		tokenPanel.setCaseSensitiveTokenName(token.isCaseSensitiveTokenName());
		tokenPanel.setIsRemoveToken(token.isRemove());
		tokenPanel.setAddTokenIfNotExists(token.isAddIfNotExists());
		if (token.isAutoExtract()) {
			tokenPanel.setAutoExtractFieldName(token.getExtractName());
		}
		if (token.isStaticValue()) {
			tokenPanel.setStaticTokenValue(token.getValue());
		}
		if (token.isFromToString()) {
			tokenPanel.setFromToString(token.getGrepFromString(), token.getGrepToString());
		}
		if (token.isPromptForInput()) {
			tokenPanel.setPromptForInput();
		}
		return tokenPanel;
	}
	
	public boolean tokensValid() {
		ArrayList<String> tokenNames = new ArrayList<String>();
		for (TokenPanel tokenPanel : tokenPanels) {
			tokenPanel.setDefaultColorAllTextFields();
			// Token Name can not be empty
			if (tokenPanel.getTokenName().equals("")) {
				tokenPanel.setRedColorNameTextField();
				showValidationFailedDialog("You are not allowed to use empty parameter names\nAffected Session: " + getSessionName() );
				return false;
			}
			// Extract Field Name can not be empty (if selected)
			if (tokenPanel.isAutoExtract() && tokenPanel.getAutoExtractFieldName().equals("")) {
				tokenPanel.setRedColorGenericTextField();
				showValidationFailedDialog("You are not allowed to use an empty \"Extract Field Name\"\nAffected Session: "  + 
			getSessionName() + "\nAffected Parameter: " + tokenPanel.getTokenName());
				return false;
			}
			// From To String must be in correct format (if selected)
			if (tokenPanel.isFromToString() && tokenPanel.getFromToStringArray() == null) {
				tokenPanel.setRedColorGenericTextField();
				showValidationFailedDialog("\"From To String\" not correctly formatted\nAffected Session: "  + getSessionName() +
						"\nAffected Parameter: " + tokenPanel.getTokenName());
				tokenPanel.setGenericTextFieldText("from [] to []");
				return false;
			}
			// Check for duplicated Names
			if (tokenNames.contains(tokenPanel.getTokenName())) {
				tokenPanel.setRedColorNameTextField();
				showValidationFailedDialog(
						"You are not allowed to use duplicated parameter names\nAffected Session: " + getSessionName() +
						"\nAffected Parameter: " + tokenPanel.getTokenName());
				return false;
			}
			tokenNames.add(tokenPanel.getTokenName());
		}
		return true;
	}

	public boolean isHeaderValid() {
		headersToReplaceText.setBackground(UIManager.getColor("TextArea.background"));
		//Allow empty header
		if(headersToReplaceText.getText().equals("")) {
			return true;
		}
		boolean valid = true;
		String[] headerLines = headersToReplaceText.getText().replace("\r", "").split("\n");
		if(headerLines.length == 0) {
			valid = false;
		}
		for(String header : headerLines) {
			String[] keyValueSplit = header.split(":");
			if(keyValueSplit.length < 2) {
				valid = false;
			}
		}
		if(!valid) {
			showValidationFailedDialog("The definied Header(s) to replace are not valid. \nAffected Session: " + getSessionName());
			headersToReplaceText.setBackground(GenericHelper.getErrorBgColor());
			return false;
		}
		else {
			return true;
		}
	}
	
	public boolean isScopeValid() {
		restrictToScopeText.setBackground(UIManager.getColor("TextArea.background"));
		if(restrictToScope.isSelected()) {
			try {
				new URL(restrictToScopeText.getText());
			} catch (MalformedURLException e) {
				showValidationFailedDialog("The definied scope URL is not valid\nAffected Session: " +	getSessionName());
				restrictToScopeText.setBackground(GenericHelper.getErrorBgColor());
				return false;
			}
		}
		return true;
	}
	
	public void setMatchAndReplaceList(ArrayList<MatchAndReplace> matchAndReplaceList) {
		this.matchAndReplaceList = matchAndReplaceList;
		updateMatchAndReplaceButtonText();
	}
	
	public ArrayList<MatchAndReplace> getMatchAndReplaceList() {
		return matchAndReplaceList;
	}
	
	public URL getScopeUrl() {
		if(restrictToScope.isSelected()) {
			try {
				URL scopeUrl = new URL(restrictToScopeText.getText());
				return scopeUrl;
			} catch (MalformedURLException e) {
				return null;
			}
		}
		return null;
	}
	
	private void showValidationFailedDialog(String text) {
		JOptionPane.showMessageDialog(this, text, "Validation Failed", JOptionPane.WARNING_MESSAGE);
	}

	private void setupContextMenu() {
		headersToReplaceText.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseReleased(MouseEvent event) {
				if (event.getButton() == MouseEvent.BUTTON3 && headersToReplaceText.getSelectedText() != null
						&& tokenPanels.size() > 0) {
					JPopupMenu contextMenu = new JPopupMenu();
					for (TokenPanel tokenPanel : tokenPanels) {
						JMenuItem item = new JMenuItem("Set Insertion Point for " + tokenPanel.getTokenName());
						String textWithReplacement = headersToReplaceText.getText().substring(0,
								headersToReplaceText.getSelectionStart()) + Globals.INSERTION_POINT_IDENTIFIER + tokenPanel.getTokenName() + Globals.INSERTION_POINT_IDENTIFIER
								+ headersToReplaceText.getText().substring(headersToReplaceText.getSelectionEnd());
						item.addActionListener(e -> headersToReplaceText.setText(textWithReplacement));
						contextMenu.add(item);
					}
					contextMenu.show(event.getComponent(), event.getX(), event.getY());
				} else {
					super.mouseReleased(event);
				}
			}
		});
	}

	public StatusPanel getStatusPanel() {
		return statusPanel;
	}

	public String getHeadersToReplaceText() {
		return headersToReplaceText.getText();
	}

	public void setHeadersToReplaceText(String text) {
		this.headersToReplaceText.setText(text);
	}
	
	public String getHeadersToRemoveText() {
		return headersToRemoveText.getText();
	}
	
	public void setHeadersToRemoveText(String text) {
		this.headersToRemoveText.setText(text);
	}

	public void appendHeadersToReplaceText(String selectedText) {
		if (getHeadersToReplaceText().endsWith("\n") || getHeadersToReplaceText().equals("")) {
			setHeadersToReplaceText(getHeadersToReplaceText() + selectedText);
		} else {
			setHeadersToReplaceText(getHeadersToReplaceText() + "\n" + selectedText);
		}
	}
	
	public boolean isRemoveHeaders() {
		return removeHeaders.isSelected();
	}
	
	public void setRemoveHeaders(boolean removeHeaders) {
		this.removeHeaders.setSelected(removeHeaders);
		updateGui();
	}

	public boolean isFilterRequestsWithSameHeader() {
		return filterRequestsWithSameHeader.isSelected();
	}

	public void setFilterRequestsWithSameHeader(boolean filterRequestsWithSameHeader) {
		this.filterRequestsWithSameHeader.setSelected(filterRequestsWithSameHeader);
	}
	
	public boolean isRestrictToScope() {
		return restrictToScope.isSelected();
	}
	
	public void setTestCors(boolean testCors) {
		this.testCors.setSelected(testCors);
	}
	
	public boolean isTestCors() {
		return testCors.isSelected();
	}
	
	public void setRestrictToScope(boolean restrictToScope) {
		this.restrictToScope.setSelected(restrictToScope);
		updateGui();
	}
	
	public void setRestrictToScopeText(String text) {
		this.restrictToScopeText.setText(text);
	}
	public String getRestrictToScopeText() {
		return restrictToScopeText.getText();
	}

	public ArrayList<TokenPanel> getTokenPanelList() {
		return tokenPanels;
	}

	public String getSessionName() {
		return sessionName;
	}

	public void setSessionName(String sessionName) {
		this.sessionName = sessionName;
	}
}
