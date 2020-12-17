package com.protect7.authanalyzer.gui;

import java.awt.Component;

import javax.swing.JFrame;

public class TokenHelpWindow extends JFrame {
	
	private static final long serialVersionUID = 4040918962095399966L;

	public TokenHelpWindow(Component location) {
		setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		setTitle("Token Help");
		setLocationRelativeTo(location);
		setVisible(true);
	}

}
