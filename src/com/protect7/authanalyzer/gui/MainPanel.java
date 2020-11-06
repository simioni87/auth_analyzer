package com.protect7.authanalyzer.gui;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.border.EmptyBorder;

import com.protect7.authanalyzer.controller.ContextMenuController;

import burp.IBurpExtenderCallbacks;

public class MainPanel extends JPanel {

	private static final long serialVersionUID = -8438576029794021570L;

	public MainPanel(IBurpExtenderCallbacks callbacks) {
		setLayout(new BorderLayout(10, 10));
		setBorder(new EmptyBorder(20, 20, 20, 20));
		CenterPanel centerPanel = new CenterPanel(callbacks);
		ConfigurationPanel configurationPanel = new ConfigurationPanel(centerPanel);
		JSplitPane  splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(configurationPanel), centerPanel);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);
		callbacks.registerContextMenuFactory(new ContextMenuController(configurationPanel));
	}
}
