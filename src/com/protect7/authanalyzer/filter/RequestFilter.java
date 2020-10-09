package com.protect7.authanalyzer.filter;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JToggleButton;

import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;

public abstract class RequestFilter {
	
	protected boolean isSelected = true;
	
	public void registerOnOffButton(JToggleButton button) {
		isSelected = button.isSelected();
		button.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				isSelected = button.isSelected();
			}
		});
	}
	
	public abstract boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IHttpRequestResponse messageInfo);

	public abstract boolean hasStringLiterals();
	
	public abstract String[] getFilterStringLiterals();
	
	public abstract void setFilterStringLiterals(String[] stringLiterals);
	
}
