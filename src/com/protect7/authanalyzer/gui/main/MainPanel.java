package com.protect7.authanalyzer.gui.main;

import java.awt.BorderLayout;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.border.EmptyBorder;
import com.protect7.authanalyzer.controller.ContextMenuController;

import burp.BurpExtender;

public class MainPanel extends JPanel {

	private static final long serialVersionUID = -8438576029794021570L;
	private final ConfigurationPanel configurationPanel;
	private final JSplitPane splitPane;
	private final CenterPanel centerPanel;

	public MainPanel() {
		setLayout(new BorderLayout(10, 10));
		setBorder(new EmptyBorder(5, 5, 5, 5));
		centerPanel = new CenterPanel(this);
		configurationPanel = new ConfigurationPanel(this);
		JScrollPane scrollPane = new JScrollPane(configurationPanel);
		scrollPane.getVerticalScrollBar().setUnitIncrement(20);
		splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, scrollPane, centerPanel);
		splitPane.setDividerSize(5);
		add(splitPane, BorderLayout.CENTER);
		BurpExtender.callbacks.registerContextMenuFactory(new ContextMenuController(configurationPanel));
		configurationPanel.loadAutoStoredData();
	}
	
	public void updateDividerLocation() {
		double configPanelHeight = configurationPanel.getPreferredSize().getHeight();
		double currentSize = getSize().getHeight();
		double relation = configPanelHeight/currentSize;
		if(relation > 0.0 && relation < 1.0) {
			splitPane.setDividerLocation(relation);
		}
		else {
			splitPane.setResizeWeight(0.2d);
		}
	}
	
	public CenterPanel getCenterPanel() {
		return centerPanel;
	}
	
	public ConfigurationPanel getConfigurationPanel() {
		return configurationPanel;
	}
}