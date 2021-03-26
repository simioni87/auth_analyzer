package com.protect7.authanalyzer.gui.util;

import javax.swing.JMenu;
import javax.swing.JMenuItem;

import com.protect7.authanalyzer.gui.dialog.InfoDialog;
import com.protect7.authanalyzer.gui.dialog.SettingsDialog;

import burp.BurpExtender;

public class AuthAnalyzerMenu extends JMenu {

	private static final long serialVersionUID = 2230192165470056210L;

	public AuthAnalyzerMenu(String name) {
		super(name);
		JMenuItem exportSetupMenuItem = new JMenuItem("Export Setup");
		exportSetupMenuItem.addActionListener(e -> BurpExtender.mainPanel.getConfigurationPanel().saveSetup());
		add(exportSetupMenuItem);
		JMenuItem importSetupMenuItem = new JMenuItem("Import Setup");
		importSetupMenuItem.addActionListener(e -> BurpExtender.mainPanel.getConfigurationPanel().loadSetup());
		add(importSetupMenuItem);
		addSeparator();
		JMenuItem settingsMenuItem = new JMenuItem("Settings");
		settingsMenuItem.addActionListener(e -> new SettingsDialog(settingsMenuItem));
		add(settingsMenuItem);
		addSeparator();
		JMenuItem aboutMenuItem = new JMenuItem("About");
		aboutMenuItem.addActionListener(e -> new InfoDialog(aboutMenuItem));
		add(aboutMenuItem);
	}
	
}
