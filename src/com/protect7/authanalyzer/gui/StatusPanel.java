package com.protect7.authanalyzer.gui;

import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;

import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JPanel;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;

public class StatusPanel extends JPanel{
	
	private final JLabel headerLabel = new JLabel();
	private final JLabel headerToReplaceValue = new JLabel("");
	private final JLabel amountOfFilteredRequestsLabel = new JLabel("");
	private final String SESSION_STARTED_TEXT = "<html><span style='color:green; font-weight: bold'>&#x26AB;</span> Session Running</html>";
	private final String SESSION_PAUSED_TEXT = "<html><span style='color:orange; font-weight: bold'>&#x26AB;</span> Session Paused</html>";
	private JButton onOffSwitch;
	private boolean running = true;
	private final HashMap<String, JLabel> tokenLabelMap = new HashMap<String, JLabel>();
	private final HashMap<String, JButton> tokenButtonMap = new HashMap<String, JButton>();
	private int amountOfFilteredRequests = 0;
	private ImageIcon loaderImageIcon = new ImageIcon(this.getClass().getClassLoader().getResource("loader.gif"));
	
	private static final long serialVersionUID = -4518448060103739997L;

	public void init(Session session) {
		removeAll();
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.anchor = GridBagConstraints.WEST;
		c.insets = new Insets(10, 0, 0, 0);
		onOffSwitch = new JButton(SESSION_STARTED_TEXT);
		running = true;
		onOffSwitch.addActionListener(e -> {
			if(running) {
				onOffSwitch.setText(SESSION_PAUSED_TEXT);
				running = false;
			}
			else {
				onOffSwitch.setText(SESSION_STARTED_TEXT);
				running = true;
			}
		});		
		add(onOffSwitch, c);
		
		c.gridx = 1;
		c.anchor = GridBagConstraints.EAST;
		amountOfFilteredRequestsLabel.setText("");
		add(amountOfFilteredRequestsLabel, c);
		
		c.anchor = GridBagConstraints.WEST;
		c.gridwidth = 3;
		c.gridx = 0;		
		
		c.fill = GridBagConstraints.BOTH;
		c.gridy++;;
		headerLabel.setText("<html><p><strong>Header(s) to Replace</strong></html>");
		add(headerLabel, c);

		c.gridy++;;
		c.insets = new Insets(5, 0, 0, 0);
		add(headerToReplaceValue, c);
		if(session.getHeadersToReplace().equals("")) {
			headerToReplaceValue.setText("unused");
		}
		else {
			headerToReplaceValue.setText(format(session.getHeadersToReplace()));
		}
		amountOfFilteredRequests = 0;
	
		c.insets = new Insets(10, 0, 0, 0);

		c.gridy++;
		for(Token token : session.getTokens()) {
			c.gridwidth = 2;
			c.fill = GridBagConstraints.BOTH;
			c.gridx = 0;
			JLabel tokenLabel = new JLabel(getTokenText(token));
			tokenLabelMap.put(token.getName(), tokenLabel);
			add(tokenLabel, c);
			if(token.isAutoExtract() || token.isFromToString()) {
				c.gridx = 3;
				c.gridwidth = 1;
				JButton renewButton = new JButton("Renew");
				tokenButtonMap.put(token.getName(), renewButton);
				if(token.getRequest() == null) {
					renewButton.setEnabled(false);
				}
				final StatusPanel statusPanel = this;
				renewButton.addActionListener(e -> {
					renewButton.setIcon(loaderImageIcon);
					new Thread(new Runnable() {
						
						@Override
						public void run() {
							boolean success = token.renewTokenValue(statusPanel, session);
							renewButton.setIcon(null);
							if(success) {
								renewButton.setText("<html><span style='color:green; font-weight: bold'>&#x2714;</span> Renew</html>");
							}
							else {
								renewButton.setText("<html><span style='color:red; font-weight: bold'>&#x274C;</span> Renew</html>");
							}
						}
					}).start();
				});
				c.fill = GridBagConstraints.NONE;
				add(renewButton, c);
			}
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
			if(token.isFromToString() || token.isAutoExtract()) {
				SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
				String timestap = sdf.format(new Date());
				tokenValue = "(Timestamp: " + timestap + ") ";
				tokenValue += "<span style='color:green; font-weight: bold'>" + token.getValue().replace("<", "&lt;") + "</span>";				
			}
			else {
				tokenValue = token.getValue().replace("<", "&lt;");
			}
		}
		return "<html><p style='width:500px'><strong>" + token.getName().replace("<", "&lt;").replace("\n", "<br>") + 
				"</strong> (Remove: <code>" + token.isRemove() +"</code>"+ tokenExtraction + additionalInfo +
				")</p> <p style='width:500px'>Value: " +  tokenValue.replace("\n", "<br>") + "</p></html>";
	}
	
	private String format(String text) {
		String htmlString = "<html><p style='width:500px'>"+text.replace("<", "&lt;").replace("\n", "<br>")+"</p></html>";
		return htmlString;
	}
	
	public boolean isRunning() {
		return running;
	}
	
	public void incrementAmountOfFitleredRequests() {
		amountOfFilteredRequests++;
		amountOfFilteredRequestsLabel.setText("Amount of Filtered Requests: " + amountOfFilteredRequests);
	}
	
	public void updateTokenStatus(Token token) {
		JLabel tokenLabel = tokenLabelMap.get(token.getName());
		tokenLabel.setText(getTokenText(token));
		if(token.getValue() != null && tokenButtonMap.get(token.getName()) != null) {
			tokenButtonMap.get(token.getName()).setEnabled(true);
		}
	}
}
