package com.protect7.authanalyzer.gui;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import com.protect7.authanalyzer.entities.Rule;

public class SessionPanel extends JPanel {
	
	private static final long serialVersionUID = 1L;
	private int textFieldWidth = 70;
	private ArrayList<Rule> rules = new ArrayList<>();
	private JTextArea headersToReplaceText = new JTextArea(3, textFieldWidth);
	private JCheckBox filterRequestsWithSameHeader;
	private JTextField csrfTokenToReplaceText = new JTextField(textFieldWidth);
	private JTextField csrfTokenValueText = new JTextField(textFieldWidth);
	private JCheckBox determineValueAutoButton;
	private JButton grepAndReplaceButton;
	private JPanel sessionPanel = new JPanel();
	private JLabel addedRulesLabel = new JLabel("<html><h3>Added Rules:</h3></html>");
	private int ruleId = 1;
	private boolean isRunning = false;
	private StatusPanel statusPanel = new StatusPanel();

	public SessionPanel() {
		statusPanel.setVisible(false);
		add(statusPanel);
		sessionPanel.setLayout(new BoxLayout(sessionPanel, BoxLayout.Y_AXIS));

		headersToReplaceText.setLineWrap(true);

		JLabel headerToReplaceLabel = new JLabel("Header(s) to Replace");
		sessionPanel.add(headerToReplaceLabel);
		getHeadersToReplaceText().setAlignmentX(Component.LEFT_ALIGNMENT);
		sessionPanel.add(getHeadersToReplaceText());
		getHeadersToReplaceText().setToolTipText(
				"<html>eg:<br>Cookie: session=06q7c9fj33rhb72f6qb60f52s6<br>AnyHeader: key=value</html>");
		setFilterRequestsWithSameHeader(new JCheckBox("Filter requests with exact same header(s)"));
		filterRequestsWithSameHeader.setSelected(false);
		sessionPanel.add(filterRequestsWithSameHeader);

		sessionPanel.add(new JLabel("   "));
		sessionPanel.add(new JSeparator());
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
		
		sessionPanel.add(new JLabel("   "));
		sessionPanel.add(new JSeparator());
		sessionPanel.add(new JLabel("   "));
		
		grepAndReplaceButton = new JButton("Add Grep and Replace Rule");
		grepAndReplaceButton.addActionListener(e -> addGrepAndReplace());
		sessionPanel.add(grepAndReplaceButton);
		sessionPanel.add(addedRulesLabel);
		addedRulesLabel.setVisible(false);

		add(sessionPanel);
	}
	
	public void setRunning() {
		isRunning = true;
		getHeadersToReplaceText().setEnabled(false);
		getCsrfTokenToReplaceText().setEnabled(false);
		getCsrfTokenValueText().setEnabled(false);
		getDetermineValueAutoButton().setEnabled(false);
		getFilterRequestsWithSameHeader().setEnabled(false);
		grepAndReplaceButton.setEnabled(false);
		for(Component component : sessionPanel.getComponents()) {
			if(component instanceof JLabel) {
				JLabel label = (JLabel) component;
				label.setForeground(Color.LIGHT_GRAY);
			}
		}
		statusPanel.setVisible(true);
		sessionPanel.setVisible(false);
	}
	
	public void setStopped() {
		isRunning = false;
		getHeadersToReplaceText().setEnabled(true);
		getCsrfTokenToReplaceText().setEnabled(true);
		if (!getDetermineValueAutoButton().isSelected()) {
			getCsrfTokenValueText().setEnabled(true);
		}
		getDetermineValueAutoButton().setEnabled(true);
		getFilterRequestsWithSameHeader().setEnabled(true);
		grepAndReplaceButton.setEnabled(true);
		for(Component component : sessionPanel.getComponents()) {
			if(component instanceof JLabel) {
				JLabel label = (JLabel) component;
				label.setForeground(Color.BLACK);
			}
		}
		statusPanel.setVisible(false);
		sessionPanel.setVisible(true);
	}
	
	public StatusPanel getStatusPanel() {
		return statusPanel;
	}
	
	private void addGrepAndReplace() {
		JTextField grepAt = new JTextField(5);
		grepAt.setText("from [TEXT] to [TEXT]");
		JTextField replaceAt = new JTextField(5);
		replaceAt.setText("from [TEXT] to [TEXT]");

		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));
		inputPanel.add(getRuleInfoLabel());
		inputPanel.add(new JLabel("<html><strong>GREP RULE:</strong></html>"));
		inputPanel.add(grepAt);
		inputPanel.add(new JLabel(" ")); 
		inputPanel.add(new JLabel("<html><strong>REPLACE RULE:</strong></html>"));
		inputPanel.add(replaceAt);

		int result = JOptionPane.showConfirmDialog(this, inputPanel, "Grep and Replace Rules",
				JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.OK_OPTION) {
			Rule rule = createRule("Rule " + ruleId, grepAt.getText(), replaceAt.getText());
			// Rule is null if input syntax incorrect
			if(rule != null) {
				rules.add(rule);
				sessionPanel.add(new RuleLabel(rule));
				addedRulesLabel.setVisible(true);
				sessionPanel.revalidate();
			}
		}
	}
	
	private void modifyGrepAndReplace(Rule rule, RuleLabel ruleLabel) {
		JTextField grepAt = new JTextField(5);
		String grepAtText = "from [" + rule.getGrepFromString() + "] to [" + rule.getGrepToString() + "]";
		grepAt.setText(grepAtText);
		JTextField replaceAt = new JTextField(5);
		String replaceAtText = "from [" + rule.getReplaceFromString() + "] to [" + rule.getReplaceToString() + "]";
		replaceAt.setText(replaceAtText);

		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.Y_AXIS));
		inputPanel.add(getRuleInfoLabel());
		inputPanel.add(new JLabel("<html><strong>GREP RULE:</strong></html>"));
		inputPanel.add(grepAt);
		inputPanel.add(new JLabel(" ")); 
		inputPanel.add(new JLabel("<html><strong>REPLACE RULE:</strong></html>"));
		inputPanel.add(replaceAt);

		Object[] choices = {"Save Changes", "Delete Rule"};
		Object defaultChoice = choices[0];
		int result = JOptionPane.showOptionDialog(this, inputPanel, "Modify Rule " + ruleLabel.getId(), JOptionPane.YES_NO_OPTION, JOptionPane.INFORMATION_MESSAGE, null, choices, defaultChoice);
		
		//Save Changes
		if (result == 0) {
			Rule newRule = createRule(ruleLabel.getRuleName(), grepAt.getText(), replaceAt.getText());
			if(newRule != null) {
				rules.remove(rule);
				ruleLabel.setRule(newRule);
				rules.add(newRule);
				sessionPanel.revalidate();
			}
		}
		//Delete
		if(result == 1) {
			sessionPanel.remove(ruleLabel);
			rules.remove(rule);
			if(rules.size() == 0) {
				addedRulesLabel.setVisible(false);
			}
			ruleLabel = null;
			sessionPanel.revalidate();
		}
	}
	
	private JLabel getRuleInfoLabel() {
		JLabel infoLabel = new JLabel("<html><h3>Information:</h3><p>The value between the defined <strong>GREP RULE</strong> will be grepped from every response (header and body) within the current Session.<br>"
				+ "The value between the defined <strong>REPLACE RULE</strong> will be replaced, with previously grepped value, within every request (header and body) within current Session.<br>"
				+ "No regular expressions accepted. Use the syntax 'from [TEXT] to [EOF]' to declare a value must be grepped or replaced to the end of request / response. Use '\n' to declare CRLF.<br><br>"
				+ "<h3>How to (syntax examples):</h3> <h4>Grep Rule:</h4><p>from [name=\"_requestVerificationToken\" value=\"] to [\" />]</p><br>"
				+ "<h4>Replace Rule:</h4><p>from [_RequestVerificationToken=] to [&]</p><br><br></html>");
		return infoLabel;
	}
	
	private Rule createRule(String ruleName, String grepRule, String replaceRule) {
		String grepFromString = null;
		String grepToString = null;
		String replaceFromString = null;
		String replaceToString = null;
		String[] split1Grep = grepRule.trim().split("\\[");
		if(split1Grep.length == 3) {
			String[] split2Grep = split1Grep[1].split("\\]");
			String[] split3Grep = split1Grep[2].split("\\]");
			if(split2Grep.length == 2 && split3Grep.length == 1) {
				grepFromString = split2Grep[0];
				grepToString = split3Grep[0];
				// The charset '\n' of JTextArea is escaped but must not be for proper work
				if(grepToString.trim().equals("\\n")) {					
					grepToString = "\n";
				}
			}
		}
		String[] split1Replace = replaceRule.trim().split("\\[");
		if(split1Replace.length == 3) {
			String[] split2Replace = split1Replace[1].split("\\]");
			String[] split3Replace = split1Replace[2].split("\\]");
			if(split2Replace.length == 2 && split3Replace.length == 1) {
				replaceFromString = split2Replace[0];
				replaceToString = split3Replace[0];
				// The charset '\n' of JTextArea is escaped but must not be for proper work
				if(replaceToString.trim().equals("\\n")) {
					replaceToString = "\n";
				}
			}
		}
		if(grepFromString != null && grepToString != null && replaceFromString != null && replaceToString != null &&
				!grepFromString.equals("") && !grepToString.equals("") && !replaceFromString.equals("") &&
				!replaceToString.equals("")) {
			return new Rule(ruleName, grepFromString, grepToString, replaceFromString, replaceToString);
		}
		return null;
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
	
	public ArrayList<Rule> getRules() {
		return rules;
	}
	
	class RuleLabel extends JLabel {
		
		private static final long serialVersionUID = -3096260871191135397L;
		private Rule rule;
		private final int id;
		
		RuleLabel(Rule ruleCurrent) {
			this.rule = ruleCurrent;
			id = ruleId;
			ruleId++;
			setText(getDisplayText());
			RuleLabel currentLabel = this;
			addMouseListener(new MouseAdapter() {
				public void mouseEntered(MouseEvent e) {
					if(!isRunning) {
						setText(getDisplayTextMouseOver());
					}
				};
				public void mouseExited(MouseEvent e) {
					if(!isRunning) {
						setText(getDisplayText());
					}
				};
				public void mouseClicked(MouseEvent e) {
					if(!isRunning) {
						modifyGrepAndReplace(rule, currentLabel);
					}
				};
			});
		}
		
		public int getId() {
			return id;
		}

		public Rule getRule() {
			return rule;
		}
		
		public String getRuleName() {
			return "Rule " + id;
		}
		
		public void setRule(Rule rule) {
			this.rule = rule;
			setText(getDisplayText());
		}
		
		private String getDisplayText() {
			String startString = "<html><p style='border:1px solid gray; margin-top:10px; padding:5px; background-color:white;'><strong>Rule " + id + ": </strong> ";
			String ruleString = "GREP RULE: from [" + rule.getGrepFromString() + "] to [" + rule.getGrepToString() + "] --- " +
			"REPLACE RULE: from [" + rule.getReplaceFromString() + "] to [" + rule.getReplaceToString() + "]";
			String completeString = startString + ruleString;
			if(completeString.length() > 210) {
				completeString = completeString.substring(0, 210) + "...";
			}
			completeString = completeString + "</p></html>";
			return completeString;
		}
		
		private String getDisplayTextMouseOver() {
			String startString = "<html><p style='border:1px solid gray; margin-top:10px; padding:5px; background-color:black;color:white;display:inline;'><strong>Rule " + id + ": </strong>";
			String ruleString = "GREP RULE: from [" + rule.getGrepFromString() + "] to [" + rule.getGrepToString() + "] --- " +
			"REPLACE RULE: from [" + rule.getReplaceFromString() + "] to [" + rule.getReplaceToString() + "]";
			String completeString = startString + ruleString;
			if(completeString.length() > 243) {
				completeString = completeString.substring(0, 243) + "...";
			}
			completeString = completeString + "</p></html>";
			return completeString;
		}
	}
	
}
