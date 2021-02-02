package com.protect7.authanalyzer.filter;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import javax.swing.JCheckBox;

import com.protect7.authanalyzer.util.GenericHelper;

import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class RequestFilter {
	
	protected boolean isSelected = true;
	protected JCheckBox onOffButton = null;
	protected int amountOfFilteredRequests = 0;
	private final int filterIndex;
	private final String description;
	
	public RequestFilter(int filterIndex, String description) {
		this.filterIndex = filterIndex;
		this.description = description;
	}
	
	public void registerOnOffButton(JCheckBox button) {
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
		if(getOnOffButton() != null) {
			String textWihtoutFilterAmount = getOnOffButton().getText().split(" \\(")[0];
			getOnOffButton().setText(textWihtoutFilterAmount + " (Filtered: " + amountOfFilteredRequests + ")");
			GenericHelper.uiUpdateAnimation(getOnOffButton(), Color.RED);
		}
	}
	
	public void resetFilteredAmount() {
		amountOfFilteredRequests = 0;
		if(getOnOffButton() != null) {
			String textWihtoutFilterAmount = getOnOffButton().getText().split(" \\(")[0];
			getOnOffButton().setText(textWihtoutFilterAmount);
		}
	}
	
	public abstract boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo);

	public abstract boolean hasStringLiterals();
	
	public abstract String[] getFilterStringLiterals();
	
	public abstract void setFilterStringLiterals(String[] stringLiterals);
	
	public String toJson() {
		String json = "{\"filterIndex\":"+filterIndex+",\"isSelected\":"+isSelected;
		if(!hasStringLiterals()) {
			json = json + "}";
		}
		else {
			json = json + ",\"stringLiterals\":[";
			for(int i=0; i<getFilterStringLiterals().length; i++) {
				if(i == getFilterStringLiterals().length-1) {
					json = json + "\""+getFilterStringLiterals()[i]+"\"";
				}
				else {
					json = json + "\""+getFilterStringLiterals()[i]+"\",";
				}
			}
			json = json + "]}";
		}
		return json;
	}
	
	public void setIsSelected(boolean isSelected) {
		this.isSelected = isSelected;
		if(getOnOffButton() != null) {
			getOnOffButton().setSelected(isSelected);
		}
	}

	public int getFilterIndex() {
		return filterIndex;
	}

	public String getDescription() {
		return description;
	}

	public JCheckBox getOnOffButton() {
		return onOffButton;
	}
	
}
