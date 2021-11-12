package com.protect7.authanalyzer.gui.dialog;

import java.util.ArrayList;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.gui.entity.TokenPanel;

public class TokenSettingsDialog {
	
	public TokenSettingsDialog(TokenPanel tokenPanel) {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		JPanel extractPanel = new JPanel();
		extractPanel.setLayout(new BoxLayout(extractPanel , BoxLayout.PAGE_AXIS));
		inputPanel.add(new JLabel("<html><strong>General Settings</strong></html>"));
		
		JCheckBox removeTokenCheckBox = new JCheckBox("Remove Parameter");
		removeTokenCheckBox.setSelected(tokenPanel.isRemoveToken());
		inputPanel.add(removeTokenCheckBox);
		JLabel infoLabel;
		if(removeTokenCheckBox.isSelected()) {
			infoLabel = new JLabel("<html><strong>Remove Parameter at</strong></html>");
		}
		else {
			infoLabel = new JLabel("<html><strong>Replace Parameter at</strong></html>");
		}
		JCheckBox addParameterCheckBox = new JCheckBox("Add Parameter if not Exists");		
		addParameterCheckBox.setSelected(tokenPanel.isAddTokenIfNotExists());
		addParameterCheckBox.setEnabled(!removeTokenCheckBox.isSelected());
		if(addParameterCheckBox.isSelected()) {
			infoLabel.setText("<html><strong>Replace / Add Parameter at</strong></html>");
		}
		else {
			infoLabel.setText("<html><strong>Replace Parameter at</strong></html>");
		}
		addParameterCheckBox.addActionListener(e -> {
			if(addParameterCheckBox.isSelected()) {
				tokenPanel.setAddTokenIfNotExists(true);
				removeTokenCheckBox.setEnabled(false);
				infoLabel.setText("<html><strong>Replace / Add Parameter at</strong></html>");
			}
			else {
				tokenPanel.setAddTokenIfNotExists(false);
				removeTokenCheckBox.setEnabled(true);
				infoLabel.setText("<html><strong>Replace Parameter at</strong></html>");
			}
		});
		inputPanel.add(addParameterCheckBox);
		
		JCheckBox urlEncodeTokenValue = new JCheckBox("URL Encode Value");
		urlEncodeTokenValue.setSelected(tokenPanel.isUrlEncoded());
		urlEncodeTokenValue.setEnabled(!removeTokenCheckBox.isSelected());
		urlEncodeTokenValue.addActionListener(e -> {
			tokenPanel.setUrlEncoded(urlEncodeTokenValue.isSelected());
		});
		inputPanel.add(urlEncodeTokenValue);
		
		JCheckBox caseSensitiveTokenNameCheckBox = new JCheckBox("Case Sensitive Parameter Name");
		caseSensitiveTokenNameCheckBox.setSelected(tokenPanel.isCaseSensitiveTokenName());
		caseSensitiveTokenNameCheckBox.addActionListener(e -> {
			tokenPanel.setCaseSensitiveTokenName(caseSensitiveTokenNameCheckBox.isSelected());
		});
		inputPanel.add(caseSensitiveTokenNameCheckBox);
		
		inputPanel.add(new JLabel(" "));
    	inputPanel.add(new JSeparator(JSeparator.HORIZONTAL));
    	inputPanel.add(new JLabel(" "));
		inputPanel.add(infoLabel);
		for(TokenLocation tokenLocation : TokenLocation.values()) {
			JCheckBox locationCheckBox = new JCheckBox(tokenLocation.getName());
			locationCheckBox.setSelected(tokenPanel.getTokenLocationSet().contains(tokenLocation));
			locationCheckBox.addActionListener(e -> {
				if(locationCheckBox.isSelected()) {
					tokenPanel.getTokenLocationSet().add(tokenLocation);
				}
				else {
					tokenPanel.getTokenLocationSet().remove(tokenLocation);
				}
			});
			inputPanel.add(locationCheckBox);
		}
		inputPanel.add(extractPanel);
			
		removeTokenCheckBox.addActionListener(e -> {
			tokenPanel.setFieldsEnabledDisabled();
			tokenPanel.setIsRemoveToken(removeTokenCheckBox.isSelected());
			setChildComponentsEnabled(extractPanel, !removeTokenCheckBox.isSelected());
			if(removeTokenCheckBox.isSelected()) {
				infoLabel.setText("<html><strong>Remove Parameter at</strong></html>");
				addParameterCheckBox.setEnabled(false);
				urlEncodeTokenValue.setEnabled(false);
			}
			else {
				infoLabel.setText("<html><strong>Replace Parameter at</strong></html>");
				addParameterCheckBox.setEnabled(true);
				urlEncodeTokenValue.setEnabled(true);
			}
		});
		
		if(tokenPanel.isSelectedItem(tokenPanel.OPTION_FROM_TO_STRING) || tokenPanel.isSelectedItem(tokenPanel.OPTION_AUTO_EXTRACT)) {
			extractPanel.add(new JLabel(" "));
			extractPanel.add(new JSeparator(JSeparator.HORIZONTAL));
			extractPanel.add(new JLabel(" "));
			extractPanel.add(new JLabel("<html><strong>Try to extract value from</strong></html>"));
	    	if(tokenPanel.isSelectedItem(tokenPanel.OPTION_AUTO_EXTRACT)) {
	    		for(AutoExtractLocation autoExtractLocation : AutoExtractLocation.values()) {
	    			JCheckBox locationCheckBox = new JCheckBox(autoExtractLocation.getName());
	    			locationCheckBox.setSelected(tokenPanel.getAutoExtractLocationSet().contains(autoExtractLocation));
	    			locationCheckBox.addActionListener(e -> {
	    				if(locationCheckBox.isSelected()) {
	    					tokenPanel.getAutoExtractLocationSet().add(autoExtractLocation);
	    				}
	    				else {
	    					tokenPanel.getAutoExtractLocationSet().remove(autoExtractLocation);
	    				}
	    			});
	    			extractPanel.add(locationCheckBox);
	    		}
			}
	    	if(tokenPanel.isSelectedItem(tokenPanel.OPTION_FROM_TO_STRING)) {
	    		final ArrayList<JCheckBox> locationCheckBoxList = new ArrayList<JCheckBox>();
		    	for(FromToExtractLocation fromToExtractLocation : FromToExtractLocation.values()) {
		    		JCheckBox locationCheckBox = new JCheckBox(fromToExtractLocation.getName());
		    		locationCheckBox.setSelected(tokenPanel.getFromToExtractLocationSet().contains(fromToExtractLocation));
		    		if(fromToExtractLocation == FromToExtractLocation.ALL) {
		    			locationCheckBox.addActionListener(e -> {
		    				if(locationCheckBox.isSelected()) {
		    					tokenPanel.getFromToExtractLocationSet().add(fromToExtractLocation);
			    				for(JCheckBox checkBox :locationCheckBoxList) {
			    					checkBox.setEnabled(false);
			    				}
			    			}
			    			else {
			    				tokenPanel.getFromToExtractLocationSet().remove(fromToExtractLocation);
			    				for(JCheckBox checkBox :locationCheckBoxList) {
			    					checkBox.setEnabled(true);
			    				}
			    			}
		    			});
		    		}
		    		else {
		    			if(fromToExtractLocation != FromToExtractLocation.HEADER && fromToExtractLocation != FromToExtractLocation.BODY)  {
		    				locationCheckBoxList.add(locationCheckBox);
			    			locationCheckBox.setEnabled(!tokenPanel.getFromToExtractLocationSet().contains(FromToExtractLocation.ALL));
		    			}
		    			locationCheckBox.addActionListener(e -> {
		    				if(locationCheckBox.isSelected()) {
		    					tokenPanel.getFromToExtractLocationSet().add(fromToExtractLocation);
			    			}
			    			else {
			    				tokenPanel.getFromToExtractLocationSet().remove(fromToExtractLocation);
			    			}
		    			});
		    		}
		    		extractPanel.add(locationCheckBox);
		    	}
	    	}
		}
		setChildComponentsEnabled(extractPanel, !removeTokenCheckBox.isSelected());
		JOptionPane.showConfirmDialog(tokenPanel, inputPanel, "Parameter Settings for " + tokenPanel.getTokenName(), JOptionPane.CLOSED_OPTION);
	}
	
	private void setChildComponentsEnabled(JPanel parent, boolean enabled) {
		for(int i=0; i<parent.getComponentCount(); i++) {
			parent.getComponent(i).setEnabled(enabled);
		}
	}
}