package com.protect7.authanalyzer.controller;

import java.util.ArrayList;
import java.util.List;
import javax.swing.JMenuItem;
import com.protect7.authanalyzer.gui.ConfigurationPanel;
import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import burp.IHttpRequestResponse;

public class ContextMenuController implements IContextMenuFactory {
	
	private final ConfigurationPanel configurationPanel;
	
	public ContextMenuController(ConfigurationPanel configurationPanel) {
		this.configurationPanel = configurationPanel;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
		List<JMenuItem> menuItems = new ArrayList<JMenuItem>();
		int[] selection = invocation.getSelectionBounds();
		byte iContext = invocation.getInvocationContext();
		String selectedText = null;
		if (selection != null) { 
			IHttpRequestResponse message = invocation.getSelectedMessages()[0];
			if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST) {
				selectedText = new String(message.getRequest()).substring(selection[0], selection[1]);
			} else if (iContext == IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE || iContext == IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE) {
				selectedText = new String(message.getResponse()).substring(selection[0], selection[1]);
			}
			//Show menu only if user has selected text. Otherwise return empty list.
			if(selectedText != null) {
				final String selectedTextFinal = selectedText.trim();
				JMenuItem item = new JMenuItem("Send to Auth Analyzer");
				item.addActionListener(e -> configurationPanel.setSelectedTextFromContextMenu(selectedTextFinal));
				menuItems.add(item);
			}
		}
		return menuItems;
	}	
}
