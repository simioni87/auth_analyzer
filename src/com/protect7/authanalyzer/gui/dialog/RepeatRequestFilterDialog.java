package com.protect7.authanalyzer.gui.dialog;

import java.awt.Component;
import java.awt.Dimension;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusEvent;
import java.awt.event.FocusListener;
import java.util.ArrayList;
import java.util.HashSet;
import javax.swing.Box;
import javax.swing.JButton;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.WindowConstants;
import javax.swing.border.EmptyBorder;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;

public class RepeatRequestFilterDialog extends JDialog {

	private static final long serialVersionUID = -5771536154913129631L;
	private String patternText = "";
	private String methodsText = "";

	public RepeatRequestFilterDialog(Component parent, ConfigurationPanel configurationPanel, IHttpRequestResponse[] selectedMessages) {
		JPanel inputPanel = (JPanel) getContentPane();
		inputPanel.setLayout(new GridBagLayout());
		inputPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
		GridBagConstraints c = new GridBagConstraints();
		c.fill = GridBagConstraints.HORIZONTAL;
		c.insets = new Insets(0, 5, 10, 0);
		c.gridx = 0;
		c.gridy = 0;
		c.gridwidth = 1;
		
		HintCheckBox uniqueRequestsCheckbox = new HintCheckBox("Filter Duplicates", "Duplicated Requests only repeated once. Unique identifier: METHOD + HOST + URL + PATH");
		inputPanel.add(uniqueRequestsCheckbox, c);
		inputPanel.add(Box.createRigidArea(new Dimension(0,10)));
		
		HintCheckBox withResponseCheckbox = new HintCheckBox("With avalibale Responses", "The request will no be repeated ff the selected Message does not has a response.");
		c.gridy++;
		inputPanel.add(withResponseCheckbox, c);
		inputPanel.add(Box.createRigidArea(new Dimension(0,10)));
		
		JLabel patternLabel = new JLabel("With specified Pattern:");
		c.insets = new Insets(0, 5, 5, 0);
		c.gridy++;
		inputPanel.add(patternLabel, c);
		PlaceholderTextField patternTextField = new PlaceholderTextField();
		patternTextField.setPlaceholder("Leave empty to apply no filter...");
		c.gridy++;
		c.insets = new Insets(0, 5, 20, 0);
		inputPanel.add(patternTextField, c);
		inputPanel.add(Box.createRigidArea(new Dimension(0,10)));
		
		JLabel methodLabel = new JLabel("HTTP Method(s) (Comma seperated):");
		c.insets = new Insets(0, 5, 5, 0);
		c.gridy++;
		inputPanel.add(methodLabel, c);
		PlaceholderTextField methodTextField = new PlaceholderTextField(25);
		methodTextField.setPlaceholder("Leave empty to apply no filter...");
		c.insets = new Insets(0, 5, 20, 0);
		c.gridy++;
		inputPanel.add(methodTextField, c);
		inputPanel.add(Box.createRigidArea(new Dimension(0,20)));
	
		JButton repeatButton = new JButton("Repeat Requests (" + selectedMessages.length + ")");
		c.gridy++;
		inputPanel.add(repeatButton, c);
		
		repeatButton.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				IHttpRequestResponse[] messages = getMessageToRepeat(selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
						patternTextField.getText().trim(), methodTextField.getText());
				GenericHelper.repeatRequests(messages, configurationPanel);
				dispose();
			}
		});
		
		uniqueRequestsCheckbox.addActionListener(e2 -> updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
				patternTextField.getText().trim(), methodTextField.getText()));
		withResponseCheckbox.addActionListener(e2 -> updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
				patternTextField.getText().trim(), methodTextField.getText()));
		patternTextField.addFocusListener(new FocusListener() {
			
			@Override
			public void focusLost(FocusEvent e) {
				if(textChanged(patternTextField.getText(), methodTextField.getText())) {
					updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
							patternTextField.getText().trim(), methodTextField.getText());
				}
			}
			
			@Override
			public void focusGained(FocusEvent e) {}
		});
		patternTextField.addActionListener(e2 -> updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
				patternTextField.getText().trim(), methodTextField.getText()));
		methodTextField.addFocusListener(new FocusListener() {
			
			@Override
			public void focusLost(FocusEvent e) {
				if(textChanged(patternTextField.getText(), methodTextField.getText())) {
					updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
							patternTextField.getText().trim(), methodTextField.getText());
				}
			}
			
			@Override
			public void focusGained(FocusEvent e) {}
		});
		methodTextField.addActionListener(e2 -> updateRepeatButtonText(repeatButton, selectedMessages, uniqueRequestsCheckbox.isSelected(), withResponseCheckbox.isSelected(), 
				patternTextField.getText().trim(), methodTextField.getText()));
		
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);	
		setVisible(true);
		setTitle("Repeat Filter Options");
		pack();
		setLocationRelativeTo(parent);
	}
	
	private boolean textChanged(String currentPatternText, String currentMethodsText) {
		if(currentPatternText.equals(patternText) && currentMethodsText.equals(methodsText)) {
			return false;
		}
		else {
			patternText = currentPatternText;
			methodsText = currentMethodsText;
			return true;
		}
	}
	
	private void updateRepeatButtonText(JButton repeatButton, IHttpRequestResponse[] sourceMessages, boolean onlyUnique, boolean onlyWithResponse, String pattern, String methods) {
		int length = getMessageToRepeat(sourceMessages, onlyUnique, onlyWithResponse, pattern, methods).length;
		repeatButton.setText("Repeat Requests (" + length + ")");
	}
	
	private IHttpRequestResponse[] getMessageToRepeat(IHttpRequestResponse[] sourceMessages, boolean onlyUnique, boolean onlyWithResponse, String pattern, String methods) {
		ArrayList<IHttpRequestResponse> messages = new ArrayList<>();
		HashSet<String> uniqueRequests = new HashSet<String>();
		for(IHttpRequestResponse message : sourceMessages) {
			boolean doRepeat = true;
			if(onlyWithResponse && message.getResponse() == null) {
				doRepeat = false;
			}
			if(doRepeat && onlyUnique) {
				String key = message.getHttpService().getHost();
				if(message.getRequest() != null) {
					IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message);
					key += requestInfo.getMethod() + requestInfo.getUrl().getPath();
				}
				if(uniqueRequests.contains(key)) {
					doRepeat = false;
				}
				else {
					uniqueRequests.add(key);
				}
			}
			if(doRepeat && (!pattern.equals("") || !methods.equals(""))) {
				if(message.getRequest() != null) {
					String request = new String(message.getRequest());
					if(!pattern.equals("")) {
						if(!request.contains(pattern)) {
							doRepeat = false;
						}
					}
					if(!methods.equals("")) {
						String[] methodSplit = methods.split(",");
						boolean methodInList = false;
						for(String method : methodSplit) {
							if(request.startsWith(method.trim())) {
								methodInList = true;
								break;
							}
						}
						if(!methodInList) {
							doRepeat = false;
						}
					}
				}
			}
			if(doRepeat) {
				messages.add(message);
			}
		}
		return messages.toArray(new IHttpRequestResponse[messages.size()]);
	}
}
