package com.protect7.authanalyzer.gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.util.HashMap;
import javax.swing.JLabel;
import javax.swing.JPanel;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;

public class StatusPanel extends JPanel{
	
	private JLabel headerLabel = new JLabel();
	private JLabel headerToReplaceValue = new JLabel("");
	//private JLabel amountOfFilteredRequestsWithSameHeaderValue = new JLabel("<html><p><strong>Filtered with same Header: </strong>0</p></html>");
	private HashMap<String, JLabel> tokenLabelMap = new HashMap<String, JLabel>();
	private int amountOfFilteredRequests = 0;
	
	private static final long serialVersionUID = -4518448060103739997L;

	public void init(Session session) {
		removeAll();
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.BOTH;
		c.insets = new Insets(10, 0, 0, 0);
		
		headerLabel.setText(getHeaderLabelText(0));
		add(headerLabel, c);

		c.gridy = 1;
		c.insets = new Insets(5, 0, 0, 0);
		add(headerToReplaceValue, c);
		if(session.getHeadersToReplace().equals("")) {
			headerToReplaceValue.setText("unused");
		}
		else {
			headerToReplaceValue.setText(format(session.getHeadersToReplace()));
		}
		amountOfFilteredRequests = 0;
		
		c.gridy = 2;
		c.insets = new Insets(20, 0, 0, 0);
		if(session.getTokens().size() > 0) {
			add(new JLabel("<html><p><strong>Parameter(s) of "+ session.getName() +"</strong></p></html>"), c);
		}
		
		c.gridy = 3;
		for(Token token : session.getTokens()) {
			JLabel tokenLabel = new JLabel(getTokenText(token));
			tokenLabelMap.put(token.getName(), tokenLabel);
			add(tokenLabel, c);
			c.gridy++;
		}		
	}
	
	private String getTokenText(Token token) {
		String tokenExtraction = "";
		String additionalInfo = "";
		if(token.isAutoExtract()) {
			tokenExtraction = ", Extraction: <code>Auto Extract</code>";
			additionalInfo = ", Extract Field Name: <code>" + token.getExtractName().replace("<", "&lt;") + "</code>";
		}
		if(token.isStaticValue()) {
			tokenExtraction = ", Extraction: <code>Static Value</code>";
			additionalInfo = ", Static Value: <code>" + token.getValue().replace("<", "&lt;") + "</code>";
		}
		if(token.isFromToString()) {
			tokenExtraction = ", Extraction: <code>From to String</code>";
			additionalInfo = ", Extract From-To String: <code>from[" + token.getGrepFromString().replace("<", "&lt;") + "] to [" + token.getGrepToString().replace("<", "&lt;") + "]</code>";
		}
		if(token.isPromptForInput()) {
			tokenExtraction = ", Extraction: <code>Prompt for Input</code>";
		}
		String tokenValue = "null";
		if(token.getValue() != null) {
			tokenValue = token.getValue().replace("<", "&lt;");
		}
		return "<html><p style='width:600px'><strong>Name: " + token.getName().replace("<", "&lt;").replace("\n", "<br>") + 
				"</strong> (Remove: <code>" + token.isRemove() +"</code>"+ tokenExtraction + additionalInfo +
				")</p> <p style='width:600px'><strong>Value: </strong>" +  tokenValue.replace("<", "&lt;").replace("\n", "<br>") + "</p></html>";
	}
	
	private String format(String text) {
		String htmlString = "<html><p style='width:600px'>"+text.replace("<", "&lt;").replace("\n", "<br>")+"</p></html>";
		return htmlString;
	}
	
	private String getHeaderLabelText(int amountOfFilteredRequestsWithSameHeader) {
		if(amountOfFilteredRequestsWithSameHeader == 0) {
			return "<html><p><strong>Header(s) to Replace</strong></html>";
		}
		else {
			return "<html><p><strong>Header(s) to Replace</strong> (Amount of Filtered: "+
					amountOfFilteredRequestsWithSameHeader+")<p></html>";
		}
	}
	
	public void incrementAmountOfFitleredRequests() {
		amountOfFilteredRequests++;
		headerLabel.setText(getHeaderLabelText(amountOfFilteredRequests));
	}
	
	public void updateTokenStatus(Token token) {
		JLabel tokenLabel = tokenLabelMap.get(token.getName());
		tokenLabel.setText(getTokenText(token));
	}
}
