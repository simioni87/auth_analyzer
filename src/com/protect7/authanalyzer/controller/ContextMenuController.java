package com.protect7.authanalyzer.controller;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.gui.dialog.RepeatRequestFilterDialog;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.entity.TokenPanel;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.util.ExtractionHelper;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Globals;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController implements IContextMenuFactory {

	private final ConfigurationPanel configurationPanel;
	private static final int MAX_CHAR_AMOUNT = 60;
	private static final int MIN_CHAR_AMOUNT_FROM = 10;
	private static final int MIN_CHAR_AMOUNT_TO = 1;
	private static final String[] DELIMITERS = { ";", "&", ",", "\"", "\n", ":" };

	public ContextMenuController(ConfigurationPanel configurationPanel) {
		this.configurationPanel = configurationPanel;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		JMenu authAnalyzerMenu = new JMenu(Globals.EXTENSION_NAME);
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		if(invocation.getSelectedMessages() != null && invocation.getSelectedMessages().length > 0) {
			// Set Repeat Request Menu
			addRepeatRequestMenu(authAnalyzerMenu, invocation);
			if(invocation.getSelectedMessages().length > 1) {
				addRepeatWithOptionsMenu(authAnalyzerMenu, invocation);
			}
			authAnalyzerMenu.addSeparator();
			// Set Token Auto Add Menu
			addAutoSetTokenMenu(authAnalyzerMenu, invocation);
		}
		if (selection != null && selection[0] != selection[1]) {
			if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
				authAnalyzerMenu.addSeparator();
				IHttpRequestResponse message = invocation.getSelectedMessages()[0];
				if (message.getRequest() == null) {
					return menuItems;
				}
				String selectedText = new String(Arrays.copyOfRange(message.getRequest(), selection[0], selection[1]));
				if (isHeader(selectedText)) {
					// Set header menu
					addHeaderMenu(authAnalyzerMenu, selectedText);
				}
				else {
					// Token Name
					addTokenNameMenu(authAnalyzerMenu, selectedText);
					// Static Token Value
					addTokenStaticValueMenu(authAnalyzerMenu, selectedText);
				}
			} else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE
					|| iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
				authAnalyzerMenu.addSeparator();
				IHttpRequestResponse message = invocation.getSelectedMessages()[0];
				String selectedText = new String(Arrays.copyOfRange(message.getResponse(), selection[0], selection[1]));
				// Token Name (for e.g. Session Cookie)
				addTokenNameMenu(authAnalyzerMenu, selectedText);
				// Set Token Extract Field Name
				addTokenExtractFieldNameMenu(authAnalyzerMenu, selectedText);
				// Set Static Token Value
				addTokenStaticValueMenu(authAnalyzerMenu, selectedText);
				// Set From To String. Only show menu if no line feed is selected
				addTokenFromToExtractMenu(authAnalyzerMenu, selectedText, selection, message.getResponse());
			}
		}
		if(authAnalyzerMenu.getItemCount() > 0) {
			menuItems.add(authAnalyzerMenu);
		}
		return menuItems;
	}
	
	private boolean isHeader(String selectedText) {
		String[] selectedTextLines = selectedText.replace("\r", "").split("\n");
		for (String line : selectedTextLines) {
			if (line.split(":").length < 2) {
				return false;
			}
		}
		return true;
	}
	
	private void addRepeatRequestMenu(JMenu authAnalyzerMenu, IContextMenuInvocation invocation) {
		JMenuItem repeatRequests;
		if(invocation.getSelectedMessages().length == 1) {
			repeatRequests = new JMenuItem("Repeat Request (1)");
		}
		else {
			repeatRequests = new JMenuItem("Repeat All Requests (" + invocation.getSelectedMessages().length + ")");
		}
		repeatRequests.addActionListener(e -> {
			GenericHelper.repeatRequests(invocation.getSelectedMessages(), configurationPanel);
		});
		authAnalyzerMenu.add(repeatRequests);	
	}
	
	private void addRepeatWithOptionsMenu(JMenu authAnalyzerMenu, IContextMenuInvocation invocation) {
		JMenuItem repeatRequests = new JMenuItem("Repeat Requests with Filter Options");
		repeatRequests.addActionListener(e1 -> new RepeatRequestFilterDialog(authAnalyzerMenu, configurationPanel, invocation.getSelectedMessages()));
		authAnalyzerMenu.add(repeatRequests);
	}
	
	private void addAutoSetTokenMenu(JMenu authAnalyzerMenu, IContextMenuInvocation invocation) {
		JMenu autoSetParams = new JMenu("Set Parameters Automatically");
		for (String sessionName : configurationPanel.getSessionNames()) {
			JMenuItem sessionItem = new JMenuItem("Session: " + sessionName);
			sessionItem.addActionListener(e -> {
				ArrayList<Token> tokens = ExtractionHelper
						.extractTokensFromMessages(invocation.getSelectedMessages());
				for (Token token : tokens) {
					configurationPanel.getSessionPanelByName(sessionName).addToken(token);
				}
				configurationPanel.setSelectedSession(sessionName);
				GenericHelper.animateBurpExtensionTab();
			});
			autoSetParams.add(sessionItem);
		}
		JMenuItem newSessionItem = new JMenuItem("Create New Session");
		final String newSessionName = getNewSessionName();
		newSessionItem.addActionListener(e -> {
			SessionPanel sessionPanel = configurationPanel.createSession(newSessionName, "");
			ArrayList<Token> tokens = ExtractionHelper.extractTokensFromMessages(invocation.getSelectedMessages());
			for (Token token : tokens) {
				sessionPanel.addToken(token);
			}
			GenericHelper.animateBurpExtensionTab();
		});
		autoSetParams.addSeparator();
		autoSetParams.add(newSessionItem);
		authAnalyzerMenu.add(autoSetParams);
	}
	
	private void addHeaderMenu(JMenu authAnalyzerMenu, String selectedText) {
		JMenu setHeaderMenu = new JMenu("Set Header");
		authAnalyzerMenu.add(setHeaderMenu);
		for (String sessionName : configurationPanel.getSessionNames()) {
			JMenuItem sessionItem = new JMenuItem("Session: " + sessionName);
			sessionItem.addActionListener(e -> {
				configurationPanel.getSessionPanelByName(sessionName).setHeadersToReplaceText(selectedText);
				configurationPanel.setSelectedSession(sessionName);
				GenericHelper.animateBurpExtensionTab();
			});
			setHeaderMenu.add(sessionItem);
		}
		JMenuItem newSessionItem = new JMenuItem("Create New Session");
		final String newSessionName = getNewSessionName();
		newSessionItem.addActionListener(e -> {
			configurationPanel.createSession(newSessionName, selectedText);
			GenericHelper.animateBurpExtensionTab();
		});
		setHeaderMenu.addSeparator();
		setHeaderMenu.add(newSessionItem);

		if (configurationPanel.getSessionNames().size() > 0) {
			JMenu appendHeaderMenu = new JMenu("Append Header");
			authAnalyzerMenu.add(appendHeaderMenu);
			for (String sessionName : configurationPanel.getSessionNames()) {
				JMenuItem sessionItem = new JMenuItem("Session: " + sessionName);
				sessionItem.addActionListener(e -> {
					configurationPanel.getSessionPanelByName(sessionName)
							.appendHeadersToReplaceText(selectedText);
					configurationPanel.setSelectedSession(sessionName);
					GenericHelper.animateBurpExtensionTab();
				});
				appendHeaderMenu.add(sessionItem);
			}
		}
	}

	private void addTokenNameMenu(JMenu authAnalyzerMenu, String selectedText) {
		JMenu tokenNameMenu = new JMenu("Set as Parameter Name");
		authAnalyzerMenu.add(tokenNameMenu);

		for (String sessionName : configurationPanel.getSessionNames()) {
			JMenu sessionItem = new JMenu("Session: " + sessionName);
			for (TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
				JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
				tokenItem.addActionListener(e -> {
					tokenPanel.setTokenName(selectedText);
					configurationPanel.setSelectedSession(sessionName);
					GenericHelper.animateBurpExtensionTab();
				});
				sessionItem.add(tokenItem);
			}
			JMenuItem newToken1 = new JMenuItem("Create New Parameter");
			newToken1.addActionListener(e -> {
				configurationPanel.getSessionPanelByName(sessionName).addToken(selectedText);
				configurationPanel.setSelectedSession(sessionName);
				GenericHelper.animateBurpExtensionTab();
			});
			sessionItem.addSeparator();
			sessionItem.add(newToken1);
			tokenNameMenu.add(sessionItem);
		}
		JMenu newSession = new JMenu("Create New Session");
		JMenuItem newToken = new JMenuItem("Create New Parameter");
		final String newSessionName = getNewSessionName();
		newToken.addActionListener(e -> {
			SessionPanel sessionPanel = configurationPanel.createSession(newSessionName, "");
			if (sessionPanel != null) {
				sessionPanel.addToken(selectedText);
				GenericHelper.animateBurpExtensionTab();
			}
		});
		newSession.add(newToken);
		tokenNameMenu.addSeparator();
		tokenNameMenu.add(newSession);
	}
	
	private void addTokenStaticValueMenu(JMenu authAnalyzerMenu, String selectedText) {
		JMenu tokenStaticValueMenu = new JMenu("Set as Static Parameter Value");
		for (String sessionName : configurationPanel.getSessionNames()) {
			JMenu sessionItem = new JMenu("Session: " + sessionName);
			for (TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName)
					.getTokenPanelList()) {
				JMenuItem tokenItem = new JMenuItem("Token: " + tokenPanel.getTokenName());
				tokenItem.addActionListener(e -> {
					tokenPanel.setStaticTokenValue(selectedText);
					configurationPanel.setSelectedSession(sessionName);
					GenericHelper.animateBurpExtensionTab();
				});
				sessionItem.add(tokenItem);
			}
			if (sessionItem.getItemCount() > 0) {
				tokenStaticValueMenu.add(sessionItem);
			}
		}
		if (tokenStaticValueMenu.getItemCount() > 0) {
			authAnalyzerMenu.add(tokenStaticValueMenu);
		}
	}
	
	private void addTokenExtractFieldNameMenu(JMenu authAnalyzerMenu, String selectedText) {
		JMenu tokenExtractFieldName = new JMenu("Set as Extract Field Name");
		for (String sessionName : configurationPanel.getSessionNames()) {
			JMenu sessionItem = new JMenu("Session: " + sessionName);
			for (TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName)
					.getTokenPanelList()) {
				JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
				tokenItem.addActionListener(e -> {
					tokenPanel.setAutoExtractFieldName(selectedText);
					configurationPanel.setSelectedSession(sessionName);
					GenericHelper.animateBurpExtensionTab();
				});
				sessionItem.add(tokenItem);
			}
			if (sessionItem.getItemCount() > 0) {
				tokenExtractFieldName.add(sessionItem);
			}
		}
		if (tokenExtractFieldName.getItemCount() > 0) {
			authAnalyzerMenu.add(tokenExtractFieldName);
		}
	}
	
	private void addTokenFromToExtractMenu(JMenu authAnalyzerMenu, String selectedText, int[] selection, byte[] response) {
		if (selectedText.split("\n").length == 1) {
			JMenu tokenFromToValueMenu = new JMenu("Set as From-To Extract");
			for (String sessionName : configurationPanel.getSessionNames()) {
				JMenu sessionItem = new JMenu("Session: " + sessionName);
				for (TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName)
						.getTokenPanelList()) {
					JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
					tokenItem.addActionListener(e -> {
						String responseAsString = new String(response);
						tokenPanel.setFromToString(getFromString(responseAsString, selection[0]),
								getToString(responseAsString, selection[1]));
						configurationPanel.setSelectedSession(sessionName);
						GenericHelper.animateBurpExtensionTab();
					});
					sessionItem.add(tokenItem);
				}
				if (sessionItem.getItemCount() > 0) {
					tokenFromToValueMenu.add(sessionItem);
				}
			}
			if (tokenFromToValueMenu.getItemCount() > 0) {
				authAnalyzerMenu.add(tokenFromToValueMenu);
			}
		}
	}

	private String getNewSessionName() {
		int index = 1;
		String newSessionName = "Session " + index;
		while (configurationPanel.getSessionNames().contains(newSessionName)) {
			index++;
			newSessionName = "Session " + index;
		}
		return newSessionName;
	}

	private String getFromString(String text, int fromOffset) {
		int startPoint = fromOffset - MAX_CHAR_AMOUNT;
		String fromTextMax;
		if (startPoint >= 0) {
			fromTextMax = text.substring(startPoint, fromOffset);
		} else {
			fromTextMax = text.substring(0, fromOffset);
		}
		String[] fromTextMaxLFSplit = fromTextMax.replace("\r", "").split("\n");
		if (fromTextMaxLFSplit.length > 1) {
			fromTextMax = fromTextMaxLFSplit[fromTextMaxLFSplit.length - 1];
		}
		if (fromTextMax.length() <= MIN_CHAR_AMOUNT_FROM) {
			return fromTextMax;
		}
		String fromTextCut = fromTextMax;
		for (String delimiter : DELIMITERS) {
			String[] split = fromTextMax.split(delimiter);
			if (split.length > 1) {
				String tmp = split[split.length - 1];
				if (tmp.length() < fromTextCut.length() && tmp.length() >= MIN_CHAR_AMOUNT_FROM) {
					fromTextCut = tmp;
				}
			}
		}
		// Trim leading whitespaces
		String regex = "^\\s+";
		return fromTextCut.replaceAll(regex, "");
	}

	private String getToString(String text, int toOffset) {
		int endPoint = toOffset + MAX_CHAR_AMOUNT;
		String toTextMax;
		if (endPoint <= text.length()) {
			toTextMax = text.substring(toOffset, toOffset + MAX_CHAR_AMOUNT);
		} else {
			toTextMax = text.substring(toOffset, text.length());
		}
		String[] toTextMaxLFSplit = toTextMax.replace("\r", "").split("\n");
		if (toTextMaxLFSplit.length > 1) {
			toTextMax = toTextMaxLFSplit[0];
		}
		if (toTextMax.replace("\r", "").startsWith("\n")) {
			return "";
		}
		String toTextCut = toTextMax;
		for (String delimiter : DELIMITERS) {
			String[] split = toTextMax.split(delimiter);
			if (split.length > 1) {
				String tmp = split[0] + delimiter;
				if (tmp.length() < toTextCut.length() && tmp.length() >= MIN_CHAR_AMOUNT_TO) {
					toTextCut = tmp;
				}
			}
		}
		return toTextCut;
	}
}