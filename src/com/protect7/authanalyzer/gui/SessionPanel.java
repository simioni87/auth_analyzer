package com.protect7.authanalyzer.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.Desktop;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.util.ArrayList;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPopupMenu;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.UIManager;
import javax.swing.border.Border;

public class SessionPanel extends JPanel {

	private static final long serialVersionUID = 1L;
	private int textFieldWidth = 70;
	private String sessionName = "";
	private JTextArea headersToReplaceText = new JTextArea(3, textFieldWidth);
	private JCheckBox filterRequestsWithSameHeader;
	private JButton addTokenButton;
	private JButton removeTokenButton;
	private JPanel sessionPanel = new JPanel();
	private StatusPanel statusPanel = new StatusPanel();
	private GridBagConstraints c = new GridBagConstraints();
	private final ArrayList<TokenPanel> tokenPanels = new ArrayList<TokenPanel>();

	public SessionPanel(String sessionName) {
		this.sessionName = sessionName;
		sessionPanel.setLayout(new GridBagLayout());
		c.gridx = 0;
		c.anchor = GridBagConstraints.WEST;
		c.fill = GridBagConstraints.HORIZONTAL;
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
		c.gridy = 1;
		sessionPanel.add(headersToReplaceText, c);
		headersToReplaceText.setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		filterRequestsWithSameHeader = new JCheckBox("Filter requests with same header(s)");
		filterRequestsWithSameHeader.setSelected(false);
		c.gridy = 2;
		sessionPanel.add(filterRequestsWithSameHeader, c);

		c.gridy = 3;
		sessionPanel.add(new JLabel(" "), c);
		c.gridy = 4;
		sessionPanel.add(new JSeparator(), c);
		c.gridy = 5;
		sessionPanel.add(new JLabel(" "), c);

		JPanel buttonPanel = new JPanel();
		addTokenButton = new JButton("Add Parameter");
		addTokenButton.addActionListener(e -> addToken());
		removeTokenButton = new JButton("Remove Last Parameter");
		removeTokenButton.setEnabled(false);
		removeTokenButton.addActionListener(e -> removeToken());
		buttonPanel.add(addTokenButton);
		buttonPanel.add(removeTokenButton);
		JButton infoButton = new JButton("?");
		infoButton.addActionListener(e -> {
			
			try {
				Desktop.getDesktop().browse(new URI("https://github.com/simioni87/auth_analyzer/blob/main/README.md#parameter-extraction"));
			} catch (Exception e1) {
				JOptionPane.showMessageDialog(this, "Browser can not be opened.", "Error", JOptionPane.WARNING_MESSAGE);
			}
		});
		buttonPanel.add(infoButton);
		c.gridy = 6;
		c.fill = GridBagConstraints.VERTICAL;
		sessionPanel.add(buttonPanel, c);

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
		TokenPanel tokenPanel = new TokenPanel();
		tokenPanels.add(tokenPanel);
		c.gridy++;
		sessionPanel.add(tokenPanel, c);
		removeTokenButton.setEnabled(true);
		sessionPanel.revalidate();
		return tokenPanel;
	}
	
	public TokenPanel addToken(String name) {
		addToken();
		TokenPanel tokenPanel = tokenPanels.get(tokenPanels.size()-1);
		tokenPanel.setTokenName(name);
		//Set Token Extract Field Name as well
		tokenPanel.setAutoExtractFieldName(name);
		return tokenPanel;
	}

	private void removeToken() {
		TokenPanel tokenPanel = tokenPanels.get(tokenPanels.size() - 1);
		sessionPanel.remove(tokenPanel);
		c.gridy--;
		tokenPanels.remove(tokenPanel);
		if (tokenPanels.size() == 0) {
			removeTokenButton.setEnabled(false);
		}
		revalidate();
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
