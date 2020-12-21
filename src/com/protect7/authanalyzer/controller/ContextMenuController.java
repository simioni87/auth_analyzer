package com.protect7.authanalyzer.controller;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import com.protect7.authanalyzer.gui.ConfigurationPanel;
import com.protect7.authanalyzer.gui.SessionPanel;
import com.protect7.authanalyzer.gui.TokenPanel;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController implements IContextMenuFactory {
	
	private final ConfigurationPanel configurationPanel;
	private static final int MAX_CHAR_AMOUNT = 60;
	private static final int MIN_CHAR_AMOUNT_FROM = 10;
	private static final int MIN_CHAR_AMOUNT_TO = 1;
	private static final String[] DELIMITERS = {";", "&", ",", "\"", "\n", ":"};
	
	public ContextMenuController(ConfigurationPanel configurationPanel) {
		this.configurationPanel = configurationPanel;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		if (selection != null) { 
			IHttpRequestResponse message = invocation.getSelectedMessages()[0];
			if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
				if(message.getRequest() == null) {
					return menuItems;
				}
				String selectedText = new String(message.getRequest()).substring(selection[0], selection[1]).trim();
				boolean isHeader = true;
				String[] selectedTextLines = selectedText.replace("\r", "").split("\n");
				for(String line : selectedTextLines) {
					if(line.split(":").length < 2) {
						isHeader = false;
						break;
					}
				}
				JMenu authAnalyzerMenu = new JMenu("Auth Analyzer");
				// Set header menu
				if(isHeader) {
					JMenu headerMenu = new JMenu("Append Header");
					authAnalyzerMenu.add(headerMenu);
					for(String sessionName : configurationPanel.getSessionNames()) {
						JMenuItem sessionItem = new JMenuItem("Session: " + sessionName);
						sessionItem.addActionListener(e -> {
							configurationPanel.getSessionPanelByName(sessionName).appendHeadersToReplaceText(selectedText);
							configurationPanel.setSelectedSession(sessionName);
						});
						headerMenu.add(sessionItem);
					}
					JMenuItem newSessionItem = new JMenuItem("Create New Session");
					final String newSessionName = getNewSessionName();
					newSessionItem.addActionListener(e -> configurationPanel.createSession(newSessionName, selectedText));
					headerMenu.add(newSessionItem);
				}
				// Set Token Menu				
				if(!isHeader) {
					// Token Name
					addTokenNameMenu(authAnalyzerMenu, selectedText);
					// Static Token Value
					JMenu tokenStaticValueMenu = new JMenu("Set as Static Parameter Value");
					for(String sessionName : configurationPanel.getSessionNames()) {
						JMenu sessionItem = new JMenu("Session: " + sessionName);
						for(TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
							JMenuItem tokenItem = new JMenuItem("Token: " + tokenPanel.getTokenName());
							tokenItem.addActionListener(e -> {
								tokenPanel.setStaticTokenValue(selectedText);
								configurationPanel.setSelectedSession(sessionName);
							});
							sessionItem.add(tokenItem);
						}
						if(sessionItem.getItemCount() > 0) {
							tokenStaticValueMenu.add(sessionItem);
						}						
					}
					if(tokenStaticValueMenu.getItemCount() > 0) {
						authAnalyzerMenu.add(tokenStaticValueMenu);
					}
				}
				if(authAnalyzerMenu.getItemCount() != 0) {
					menuItems.add(authAnalyzerMenu);
				}				
			} else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
				String responseAsString = new String(message.getResponse());
				String selectedText = responseAsString.substring(selection[0], selection[1]).trim();
				JMenu authAnalyzerMenu = new JMenu("Auth Analyzer");
				// Token Name (for e.g. Session Cookie)
				addTokenNameMenu(authAnalyzerMenu, selectedText);
				//Set Token Extract Field Name
				JMenu tokenExtractFieldName = new JMenu("Set as Extract Field Name");
				for(String sessionName : configurationPanel.getSessionNames()) {
					JMenu sessionItem = new JMenu("Session: " + sessionName);
					for(TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
						JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
						tokenItem.addActionListener(e -> {
							tokenPanel.setAutoExtractFieldName(selectedText);
							configurationPanel.setSelectedSession(sessionName);
						});
						sessionItem.add(tokenItem);
					}
					if(sessionItem.getItemCount() > 0) {
						tokenExtractFieldName.add(sessionItem);
					}						
				}
				if(tokenExtractFieldName.getItemCount() > 0) {
					authAnalyzerMenu.add(tokenExtractFieldName);
				}
				
				
				if(authAnalyzerMenu.getItemCount() != 0) {
					menuItems.add(authAnalyzerMenu);
				}
				// Set Static Token Value
				JMenu tokenStaticValueMenu = new JMenu("Set as Static Parameter Value");
				for(String sessionName : configurationPanel.getSessionNames()) {
					JMenu sessionItem = new JMenu("Session: " + sessionName);
					for(TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
						JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
						tokenItem.addActionListener(e -> {
							tokenPanel.setStaticTokenValue(selectedText);
							configurationPanel.setSelectedSession(sessionName);
						});
						sessionItem.add(tokenItem);
					}
					if(sessionItem.getItemCount() > 0) {
						tokenStaticValueMenu.add(sessionItem);
					}						
				}
				if(tokenStaticValueMenu.getItemCount() > 0) {
					authAnalyzerMenu.add(tokenStaticValueMenu);
				}				
				// Set From To String. Only show menu if no line feed is selected
				if(selectedText.split("\n").length == 1) {
					JMenu tokenFromToValueMenu = new JMenu("Set as From-To Extract");
					for(String sessionName : configurationPanel.getSessionNames()) {
						JMenu sessionItem = new JMenu("Session: " + sessionName);
						for(TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
							JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
							tokenItem.addActionListener(e -> {
								tokenPanel.setFromToString(getFromString(responseAsString, selection[0]), getToString(responseAsString, selection[1]));
								configurationPanel.setSelectedSession(sessionName);
							});
							sessionItem.add(tokenItem);
						}
						if(sessionItem.getItemCount() > 0) {
							tokenFromToValueMenu.add(sessionItem);
						}						
					}
					if(tokenFromToValueMenu.getItemCount() > 0) {
						authAnalyzerMenu.add(tokenFromToValueMenu);
					}
					
					
					if(authAnalyzerMenu.getItemCount() != 0) {
						menuItems.add(authAnalyzerMenu);
					}
				}
			}
		}
		return menuItems;
	}
	
	private void addTokenNameMenu(JMenu authAnalyzerMenu, String selectedText) {
		JMenu tokenNameMenu = new JMenu("Set as Parameter Name");
		authAnalyzerMenu.add(tokenNameMenu);
		
		for(String sessionName : configurationPanel.getSessionNames()) {
			JMenu sessionItem = new JMenu("Session: " + sessionName);
			for(TokenPanel tokenPanel : configurationPanel.getSessionPanelByName(sessionName).getTokenPanelList()) {
				JMenuItem tokenItem = new JMenuItem("Parameter: " + tokenPanel.getTokenName());
				tokenItem.addActionListener(e -> {
					tokenPanel.setTokenName(selectedText);
					configurationPanel.setSelectedSession(sessionName);
				});
				sessionItem.add(tokenItem);
			}
			JMenuItem newToken1 = new JMenuItem("Create New Parameter");
			newToken1.addActionListener(e -> {
				configurationPanel.getSessionPanelByName(sessionName).addToken(selectedText);
				configurationPanel.setSelectedSession(sessionName);
			});
			sessionItem.add(newToken1);
			tokenNameMenu.add(sessionItem);						
		}
		JMenu newSession = new JMenu("Create New Session");
		JMenuItem newToken = new JMenuItem("Create New Parameter");
		final String newSessionName = getNewSessionName();
		newToken.addActionListener(e -> {
			SessionPanel sessionPanel = configurationPanel.createSession(newSessionName, "");
			if(sessionPanel != null) {
				sessionPanel.addToken(selectedText);
			}
		});
		newSession.add(newToken);
		tokenNameMenu.add(newSession);
	}
	
	private String getNewSessionName() {
		int index = 1;
		String newSessionName = "Session " + index;
		while(configurationPanel.getSessionNames().contains(newSessionName)) {
			index++;
			newSessionName = "Session " + index;
		}
		return newSessionName;
	}

	private String getFromString(String text, int fromOffset) {
		int startPoint = fromOffset - MAX_CHAR_AMOUNT;
		String fromTextMax;
		if(startPoint >= 0) {
			fromTextMax = text.substring(startPoint, fromOffset);
		}
		else {
			fromTextMax = text.substring(0, fromOffset);
		}
		String[] fromTextMaxLFSplit = fromTextMax.replace("\r", "").split("\n");
		if(fromTextMaxLFSplit.length > 1) {
			fromTextMax = fromTextMaxLFSplit[fromTextMaxLFSplit.length-1];
		}
		if(fromTextMax.length() <= MIN_CHAR_AMOUNT_FROM) {
			return fromTextMax;
		}
		String fromTextCut = fromTextMax;
		for(String delimiter : DELIMITERS) {
			String[] split = fromTextMax.split(delimiter);
			if(split.length > 1) {
				String tmp = split[split.length-1];
				if(tmp.length()<fromTextCut.length() && tmp.length() >= MIN_CHAR_AMOUNT_FROM) {
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
		if(endPoint <= text.length()) {
			toTextMax = text.substring(toOffset, toOffset + MAX_CHAR_AMOUNT);
		}
		else {
			toTextMax = text.substring(toOffset, text.length());
		}
		String[] toTextMaxLFSplit = toTextMax.replace("\r", "").split("\n");
		if(toTextMaxLFSplit.length > 1) {
			toTextMax = toTextMaxLFSplit[0];
		}
		if(toTextMax.replace("\r", "").startsWith("\n")) {
			return "";
		}
		String toTextCut = toTextMax;
		for(String delimiter : DELIMITERS) {
			String[] split = toTextMax.split(delimiter);
			if(split.length > 1) {
				String tmp = split[0] + delimiter;
				if(tmp.length()<toTextCut.length() && tmp.length() >= MIN_CHAR_AMOUNT_TO) {
					toTextCut = tmp;
				}
			}
		}
		return toTextCut;
	}
}
