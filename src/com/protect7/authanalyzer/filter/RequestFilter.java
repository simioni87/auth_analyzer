package com.protect7.authanalyzer.filter;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JToggleButton;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class RequestFilter {
	
	protected boolean isSelected = true;
	protected JToggleButton onOffButton = null;
	protected int amountOfFilteredRequests = 0;
	
	public void registerOnOffButton(JToggleButton button) {
		onOffButton = button;
		isSelected = button.isSelected();
		button.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				isSelected = button.isSelected();
			}
		});
	}
	
	protected void incrementFiltered() {
		amountOfFilteredRequests++;
		if(onOffButton != null) {
			String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
			onOffButton.setText(textWihtoutFilterAmount + " (" + amountOfFilteredRequests + ")");
		}
	}
	
	public void resetFilteredAmount() {
		amountOfFilteredRequests = 0;
		if(onOffButton != null) {
			String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
			onOffButton.setText(textWihtoutFilterAmount + " (0)");
		}
	}
	
	public abstract boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo);

	public abstract boolean hasStringLiterals();
	
	public abstract String[] getFilterStringLiterals();
	
	public abstract void setFilterStringLiterals(String[] stringLiterals);
	
}
