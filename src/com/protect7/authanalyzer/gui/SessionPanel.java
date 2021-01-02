package com.protect7.authanalyzer.gui;

import java.awt.Color;
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
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JScrollBar;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.border.Border;

public class SessionPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private int textFieldWidth = 70;
	private String sessionName = "";
	private JTextArea headersToReplaceText = new JTextArea(3, textFieldWidth);
	private JCheckBox filterRequestsWithSameHeader;
	private JCheckBox restrictToScope;
	private PlaceholderTextField restrictToScopeText;
	private JButton addTokenButton;
	private JPanel sessionPanel = new JPanel();
	private StatusPanel statusPanel = new StatusPanel();
	private JPanel tokenHeaderPanel = getTokenHeaderPanel();
	private GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<TokenPanel> tokenPanels = new ArrayList<TokenPanel>();
	private final JScrollPane scrollPane;

	public SessionPanel(String sessionName, JScrollPane scrollPane) {
		this.sessionName = sessionName;
		this.scrollPane = scrollPane;
		sessionPanel.setLayout(new GridBagLayout());
		c.gridx = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
		c.gridwidth = 2;
		c.weighty = 1;
		
		statusPanel.setVisible(false);
		add(statusPanel, c);

		headersToReplaceText.setLineWrap(true);
		Border border = BorderFactory.createLineBorder(Color.LIGHT_GRAY);
		headersToReplaceText.setBorder(border);
		setupContextMenu();

		JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
		c.gridy = 0;
		sessionPanel.add(headerToReplaceLabel, c);
		headersToReplaceText.setAlignmentX(Component.LEFT_ALIGNMENT);
		c.gridy++;
		sessionPanel.add(headersToReplaceText, c);
		headersToReplaceText.setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		
		filterRequestsWithSameHeader = new JCheckBox("Filter requests with same header(s)");
		filterRequestsWithSameHeader.setSelected(false);
		c.gridwidth = 1;
		c.insets = new Insets(5, 0, 0, 20);
		c.gridy++;
		sessionPanel.add(filterRequestsWithSameHeader, c);
		restrictToScope = new JCheckBox("Restrict to Scope");
		c.gridx = 1;
		sessionPanel.add(restrictToScope, c);
		
		c.gridwidth = 2;
		c.gridx = 0;
		c.insets = new Insets(5, 0, 0, 0);
		c.gridy++;
		restrictToScopeText = new PlaceholderTextField();
		restrictToScopeText.setPlaceholder("Enter URL e.g. https://example.com/path)...");
		restrictToScopeText.setVisible(false);
		sessionPanel.add(restrictToScopeText, c);
		restrictToScope.addActionListener(e -> {
			if(restrictToScope.isSelected()) {
				restrictToScopeText.setVisible(true);
				revalidate();
			}
			else {
				restrictToScopeText.setVisible(false);
				revalidate();
			}
		});
		
		c.gridy++;
		c.insets = new Insets(10, 0, 0, 0);
		sessionPanel.add(new JSeparator(), c);

		JPanel buttonPanel = new JPanel();
		addTokenButton = new JButton("Add Parameter");
		addTokenButton.addActionListener(e -> addToken());
		buttonPanel.add(addTokenButton);
		JButton infoButton = new JButton("?");
		infoButton.addActionListener(e -> {
			
			try {
				Desktop.getDesktop().browse(new URI("https://github.com/simioni87/auth_analyzer/blob/main/README.md#parameter-extraction"));
			} catch (Exception e1) {
				JOptionPane.showMessageDialog(this, "Browser can not be opened.", "Error", JOptionPane.WARNING_MESSAGE);
			}
		});
		buttonPanel.add(infoButton);
		c.gridy++;
		c.fill = GridBagConstraints.VERTICAL;
		sessionPanel.add(buttonPanel, c);

		c.gridy++;
		c.insets = new Insets(0, 0, 0, 0);
		tokenHeaderPanel.setVisible(false);
		sessionPanel.add(tokenHeaderPanel, c);
		add(sessionPanel);
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
		tokenHeaderPanel.setVisible(true);
		TokenPanel tokenPanel = new TokenPanel();
		tokenPanels.add(tokenPanel);
		c.gridy++;
		sessionPanel.add(tokenPanel, c);
		sessionPanel.revalidate();
		
		tokenPanel.getRemoveButton().addActionListener(e -> {
			sessionPanel.remove(tokenPanel);
			c.gridy--;
			tokenPanels.remove(tokenPanel);
			if (tokenPanels.size() == 0) {
				tokenHeaderPanel.setVisible(false);
			}
			revalidate();
		});
		
		if(scrollPane != null) {
			SwingUtilities.invokeLater(new Runnable() {
				
				@Override
				public void run() {
					JScrollBar scrollBar = scrollPane.getVerticalScrollBar();
					scrollBar.setValue(scrollBar.getMaximum());
				}
			});
			
		}
		return tokenPanel;
	}
	
	public TokenPanel addToken(String name) {
		TokenPanel tokenPanel = addToken();
		tokenPanel.setTokenName(name);
		//Set Token Extract Field Name as well
		tokenPanel.setAutoExtractFieldName(name);
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
		if(headersToReplaceText.getText().trim().equals("")) {
			return true;
		}
		String[] headerLines = headersToReplaceText.getText().replace("\r", "").split("\n");
		for(String header : headerLines) {
			String[] keyValueSplit = header.split(":");
			if(keyValueSplit.length < 2) {
				showValidationFailedDialog("The definied Header(s) to replace are not valid. \nAffected Session: " +
			getSessionName() + "\nAffected Header: " + header);
				headersToReplaceText.setBackground(new Color(255, 102, 102));
				return false;
			}
		}
		return true;
	}
	
	public boolean isScopeValid() {
		restrictToScopeText.setBackground(UIManager.getColor("TextArea.background"));
		if(restrictToScope.isSelected()) {
			try {
				new URL(restrictToScopeText.getText());
			} catch (MalformedURLException e) {
				showValidationFailedDialog("The definied scope URL is not valid\nAffected Session: " +	getSessionName());
				restrictToScopeText.setBackground(new Color(255, 102, 102));
				return false;
			}
		}
		return true;
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
						String selectedText = headersToReplaceText.getText().substring(headersToReplaceText.getSelectionStart(), 
								headersToReplaceText.getSelectionEnd());
						String textWithReplacement = headersToReplaceText.getText().substring(0,
								headersToReplaceText.getSelectionStart()) + "§" + tokenPanel.getTokenName() + "["+selectedText+"]§"
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

	public void appendHeadersToReplaceText(String selectedText) {
		if (getHeadersToReplaceText().endsWith("\n") || getHeadersToReplaceText().equals("")) {
			setHeadersToReplaceText(getHeadersToReplaceText() + selectedText);
		} else {
			setHeadersToReplaceText(getHeadersToReplaceText() + "\n" + selectedText);
		}
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
	
	public void setRestrictToScope(boolean restrictToScope) {
		this.restrictToScope.setSelected(restrictToScope);
		if(restrictToScope) {
			restrictToScopeText.setVisible(true);
		}
		else {
			restrictToScopeText.setVisible(false);
		}
	}
	
	public void setRestrictToScopeText(String text) {
		this.restrictToScopeText.setText(text);
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
	
	private JPanel getTokenHeaderPanel() {
		JPanel tokenHeaderPanel = new JPanel();
		tokenHeaderPanel.setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.NONE;
		c.gridwidth = 1;
		c.insets = new Insets(10, 70, 0, 0);
		
		tokenHeaderPanel.add(new JLabel("Parameter Name"), c);
		
		c.insets = new Insets(10, 65, 0, 0);
		c.gridx = 1;
		tokenHeaderPanel.add(new JLabel("Remove"), c);
		
		c.insets = new Insets(10, 15, 0, 0);
		c.gridx = 2;
		tokenHeaderPanel.add(new JLabel("Parameter Value"), c);
		
		c.insets = new Insets(10, 50, 0, 0);
		c.gridx = 3;
		tokenHeaderPanel.add(new JLabel("Extract Field Name / Static Value / From To String"), c);
		
		return tokenHeaderPanel;
	}
}
