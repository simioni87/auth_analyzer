package com.protect7.authanalyzer.gui;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;
import com.protect7.authanalyzer.entities.Rule;
import com.protect7.authanalyzer.entities.Session;

public class StatusPanel extends JPanel{
	
	private JPanel statusPanel = new JPanel();
	private JLabel headerToReplaceValue = new JLabel("");
	private JLabel amountOfFilteredRequestsWithSameHeaderValue = new JLabel("0");
	private JLabel csrfTokenNameValue = new JLabel("-");
	private JLabel csrfTokenValue = new JLabel("-");
	private ArrayList<JLabel> ruleValueLabels = new ArrayList<>();
	private int amountOfFilteredRequests = 0;
	
	private final int WIDTH = 800;
	private final int HEIGTH = 240;
	
	private static final long serialVersionUID = -4518448060103739997L;

	public StatusPanel() {
		setPreferredSize(new Dimension(WIDTH, HEIGTH));
	}

	public void init(Session session) {
		statusPanel.removeAll();
		statusPanel.setLayout(new BoxLayout(statusPanel, BoxLayout.Y_AXIS));
		
		statusPanel.add(getTitleLabel("Header(s) to Replace:"));
		statusPanel.add(headerToReplaceValue);
		if(session.getHeadersToReplace().equals("")) {
			headerToReplaceValue.setText("unused");
		}
		else {
			headerToReplaceValue.setText(format(session.getHeadersToReplace()));
		}
		
		statusPanel.add(getTitleLabel("Filtered Requests with same Header(s):"));
		statusPanel.add(amountOfFilteredRequestsWithSameHeaderValue);
		amountOfFilteredRequests = 0;
		if(!session.isFilterRequestsWithSameHeader()) {
			amountOfFilteredRequestsWithSameHeaderValue.setText("not filtered");
		}
		else {
			amountOfFilteredRequestsWithSameHeaderValue.setText(amountOfFilteredRequests+"");
		}
		
		statusPanel.add(getTitleLabel("CSRF Token Name:"));
		statusPanel.add(csrfTokenNameValue);
		if(session.getCsrfTokenName().equals("")) {
			csrfTokenNameValue.setText("unused");
		}
		else {
			csrfTokenNameValue.setText(session.getCsrfTokenName());
		}
		
		statusPanel.add(getTitleLabel("Current CSRF Token Value:"));
		statusPanel.add(csrfTokenValue);
		if(session.getCsrfTokenName().equals("")) {
			csrfTokenValue.setText("unused");
		}
		else {
			csrfTokenValue.setText(format(session.getCurrentCsrftTokenValue()));
		}
	
		add(statusPanel, BorderLayout.CENTER);

		ruleValueLabels.clear();
		for(Rule rule : session.getRules()) {
			statusPanel.add(getTitleLabel(rule.getName() + " grepped Value:"));
			JLabel ruleValueLabel = new JLabel("-");
			ruleValueLabel.setName(rule.getName());
			ruleValueLabels.add(ruleValueLabel);
			ruleValueLabel.setText("currently no value grepped");
			statusPanel.add(ruleValueLabel);
		}
		//Do some GUI Magic
		setPreferredSize(new Dimension(WIDTH, HEIGTH + (session.getRules().size() * 53) + (headerToReplaceValue.getText().length()/100)*20));
	}
	
	private JLabel getTitleLabel(String text) {
		return new JLabel("<html><h4>"+text+"</h4></html>");
	}
	
	private String format(String text) {
		String htmlString = "<html><p style='width:600px'>"+text.replace("\n", "<br>")+"</p></html>";
		return htmlString;
	}
	
	public void incrementAmountOfFitleredRequests() {
		amountOfFilteredRequests++;
		amountOfFilteredRequestsWithSameHeaderValue.setText(amountOfFilteredRequests+"");
	}
	
	public void updateCsrfTokenValue(String value) {
		csrfTokenValue.setText(format(value));
	}
	
	public void setRuleValue(Rule rule, String value) {
		for(JLabel label : ruleValueLabels) {
			if(label.getName().equals(rule.getName())) {
				label.setText(format(value));
				break;
			}
		}
	}
}
