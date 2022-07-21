package com.protect7.authanalyzer.filter;

import java.awt.Color;
import com.protect7.authanalyzer.gui.util.HintCheckBox;
import com.protect7.authanalyzer.util.GenericHelper;
import burp.IBurpExtenderCallbacks;
import burp.IRequestInfo;
import burp.IResponseInfo;

public abstract class RequestFilter {
	
	protected HintCheckBox onOffButton = null;
	protected int amountOfFilteredRequests = 0;
	protected String[] stringLiterals = null;
	private final int filterIndex;
	private final String description;
	
	public RequestFilter(int filterIndex, String description) {
		this.filterIndex = filterIndex;
		this.description = description;
	}
	
	public void registerOnOffButton(HintCheckBox button) {
		onOffButton = button;
		onOffButton.putClientProperty("html.disable", null);
		onOffButton.setHint(getInfoText());
	}
	
	protected void incrementFiltered() {
		amountOfFilteredRequests++;
		if(onOffButton != null) {
			String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
			onOffButton.setText(textWihtoutFilterAmount + " (Filtered: " + amountOfFilteredRequests + ")");
			GenericHelper.uiUpdateAnimation(onOffButton, new Color(240, 110, 0));
		}
	}
	
	public void resetFilteredAmount() {
		amountOfFilteredRequests = 0;
		if(onOffButton != null) {
			String textWihtoutFilterAmount = onOffButton.getText().split(" \\(")[0];
			onOffButton.setText(textWihtoutFilterAmount);
		}
	}
	
	public abstract boolean filterRequest(IBurpExtenderCallbacks callbacks, int toolFlag, IRequestInfo requestInfo, IResponseInfo responseInfo);

	public abstract boolean hasStringLiterals();
	
	public String[] getFilterStringLiterals() {
		return stringLiterals;
	}
	
	public void setFilterStringLiterals(String[] stringLiterals) {
		this.stringLiterals = stringLiterals;
		if(onOffButton != null) {
			onOffButton.setHint(getInfoText());
		}
	}
	
	public void setIsSelected(boolean selected) {
		onOffButton.setSelected(selected);
	}
	
	public String toJson() {
		String json = "{\"filterIndex\":"+filterIndex+",\"isSelected\":"+onOffButton.isSelected();
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
	
	public String getInfoText() {
		if (onOffButton != null) {
			if (hasStringLiterals()) {
				return "<html>" + getDescription() + "<br><strong><em>"
						+ GenericHelper.getArrayAsString(getFilterStringLiterals()) + "</em></strong></html>";
			} else {
				return getDescription();
			}
		}
		return "";
	}

	public int getFilterIndex() {
		return filterIndex;
	}

	public String getDescription() {
		return description;
	}
}