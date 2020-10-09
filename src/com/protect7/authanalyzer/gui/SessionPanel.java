package com.protect7.authanalyzer.gui;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;

public class SessionPanel extends JPanel {
	
	private static final long serialVersionUID = 1L;
	private int textFieldWidth = 70;
	private JTextArea headersToReplaceText = new JTextArea(3, textFieldWidth);
	private JCheckBox filterRequestsWithSameHeader;
	private JTextField csrfTokenToReplaceText = new JTextField(textFieldWidth);
	private JTextField csrfTokenValueText = new JTextField(textFieldWidth);
	private JCheckBox determineValueAutoButton;

	public SessionPanel() {
		JPanel sessionPanel = new JPanel();
		sessionPanel.setLayout(new BoxLayout(sessionPanel, BoxLayout.Y_AXIS));
		
		headersToReplaceText.setLineWrap(true);

		JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
		sessionPanel.add(headerToReplaceLabel);
		getHeadersToReplaceText().setAlignmentX(Component.LEFT_ALIGNMENT);
		sessionPanel.add(getHeadersToReplaceText());
		getHeadersToReplaceText().setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		setFilterRequestsWithSameHeader(new JCheckBox("Filter requests with exact same header"));
		filterRequestsWithSameHeader.setSelected(true);
		sessionPanel.add(filterRequestsWithSameHeader);
		sessionPanel.add(new JLabel("   "));
		JLabel cssrfTokenParameterNameLabel = new JLabel("CSRF Token Parameter Name (leave empty if unsused)", SwingConstants.LEFT);
		cssrfTokenParameterNameLabel.setToolTipText("Enter param name of CSRF token. remove_token#name for removing the token.");
		sessionPanel.add(cssrfTokenParameterNameLabel);
		getCsrfTokenToReplaceText().setAlignmentX(Component.LEFT_ALIGNMENT);
		sessionPanel.add(getCsrfTokenToReplaceText());
		setDetermineValueAutoButton(new JCheckBox("Auto CSRF Value Detection (enter CSRF value if unselected)"));
		getDetermineValueAutoButton()
				.setToolTipText("CSRF token will be grapped from input fields with specified CSRF token name.");
		getDetermineValueAutoButton().addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				if (getDetermineValueAutoButton().isSelected()) {
					getCsrfTokenValueText().setEnabled(false);
					getCsrfTokenValueText().setText("");
				} else {
					getCsrfTokenValueText().setEnabled(true);
				}
			}
		});
		getDetermineValueAutoButton().setSelected(true);
		getCsrfTokenValueText().setEnabled(false);

		sessionPanel.add(getDetermineValueAutoButton());
		getCsrfTokenValueText().setAlignmentX(Component.LEFT_ALIGNMENT);
		sessionPanel.add(getCsrfTokenValueText());

		add(sessionPanel);
	}

	public JTextArea getHeadersToReplaceText() {
		return headersToReplaceText;
	}

	public void setHeadersToReplaceText(JTextArea headersToReplaceText) {
		this.headersToReplaceText = headersToReplaceText;
	}

	public JTextField getCsrfTokenToReplaceText() {
		return csrfTokenToReplaceText;
	}

	public void setCsrfTokenToReplaceText(JTextField csrfTokenToReplaceText) {
		this.csrfTokenToReplaceText = csrfTokenToReplaceText;
	}

	public JTextField getCsrfTokenValueText() {
		return csrfTokenValueText;
	}

	public void setCsrfTokenValueText(JTextField csrfTokenValueText) {
		this.csrfTokenValueText = csrfTokenValueText;
	}

	public JCheckBox getDetermineValueAutoButton() {
		return determineValueAutoButton;
	}

	public void setDetermineValueAutoButton(JCheckBox determineValueAutoButton) {
		this.determineValueAutoButton = determineValueAutoButton;
	}

	public JCheckBox getFilterRequestsWithSameHeader() {
		return filterRequestsWithSameHeader;
	}

	public void setFilterRequestsWithSameHeader(JCheckBox filterRequestsWithSameHeader) {
		this.filterRequestsWithSameHeader = filterRequestsWithSameHeader;
	}
	
}
