package com.protect7.authanalyzer.gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.EnumSet;
import javax.swing.BoxLayout;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.UIManager;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.util.GenericHelper;

public class TokenPanel extends JPanel {

	private static final long serialVersionUID = 7682542523017826799L;
	private final String OPTION_AUTO_EXTRACT = "Auto Extract";
	private final String OPTION_STATIC_VALUE = "Static Value";
	private final String OPTION_FROM_TO_STRING = "From To String";
	private final String OPTION_PROMPT_FOR_INPUT = "Prompt for Input";
	private final String PLACEHOLDER_EXTRACT_FIELD_NAME = "Enter Extract Field Name...";
	private final String PLACEHOLDER_STATIC_VALUE = "Enter Static Value...";
	private final String PLACEHOLDER_FROM_TO_STRING = "Enter From To String...";
	private final String TOOLTIP_EXTRACT_TOKEN_NAME = "<html>Name of the Parameter for which the static / extracted value will be replaced.<br>Respected Parameter locations: <strong>Path, URL, Body, Cookie</strong>.</html>";
	private final String TOOLTIP_REMOVE = "<html><strong>Remove Parameter</strong><br>Removes all parameters with the given name.</html>";
	private final String TOOLTIP_VALUE_EXTRACTION = "<html>Defines how the Parameter value will be discovered</html>";
	private final String TOOLTIP_EXTRACT_FIELD_NAME = "<html>Name of:<br>- Cookie (Set-Cookie Header)<br>- HTML Input Field (Name Attribute) or <br>- JSON Data (Key)</strong>.</html>";
	private final String TOOLTIP_STATIC_VALUE = "<html>The defined value will be used</html>";
	private final String TOOLTIP_FROM_TO_STRING = "<html>The value between the \"From\" and \"To\" String will be extracted.<br>The desired value can be marked in message editor and directly<br>set as From-To String by the context menu.</html>";
	private final String TOOLTIP_PROMPT_FOR_INPUT = "<html>Value can be entered manually if request has a Parameter with corresponding name</html>";
	private final PlaceholderTextArea nameTextField;
	private final JButton removeButton;
	private final JCheckBox removeTokenCheckBox;
	private final JComboBox<String> tokenValueComboBox;
	private final PlaceholderTextArea genericTextField;
	private String placeholderCache = "";
	private int currentValueComboBoxIndex = 0;
	private String[] valueTempText = {"", "", "", ""};
	private EnumSet<TokenLocation> tokenLocationSet = EnumSet.allOf(TokenLocation.class); 
	private EnumSet<AutoExtractLocation> autoExtractLocationSet = AutoExtractLocation.getDefaultSet();
	private EnumSet<FromToExtractLocation> fromToExtractLocationSet = FromToExtractLocation.getDefaultSet();

	public TokenPanel() {
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.NONE;
		c.gridwidth = 1;
		c.insets = new Insets(10, 5, 0, 5);
		
		nameTextField = new PlaceholderTextArea(1, 20);
		nameTextField.setToolTipText(TOOLTIP_EXTRACT_TOKEN_NAME);
		nameTextField.setPlaceholder("Enter Token Name...");
		add(nameTextField, c);
		
		c.gridx = 1;
		removeTokenCheckBox = new JCheckBox();
		removeTokenCheckBox.setToolTipText(TOOLTIP_REMOVE);
		add(removeTokenCheckBox, c);
		
		c.gridx = 2;
		String[] tokenValueItems = {OPTION_AUTO_EXTRACT, OPTION_STATIC_VALUE, OPTION_FROM_TO_STRING, OPTION_PROMPT_FOR_INPUT};
		tokenValueComboBox = new JComboBox<String>(tokenValueItems);
		tokenValueComboBox.setToolTipText(TOOLTIP_VALUE_EXTRACTION);
		add(tokenValueComboBox, c);
		
		c.gridx = 3;
		genericTextField = new PlaceholderTextArea(1, 27);
		genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
		genericTextField.setPlaceholder(PLACEHOLDER_EXTRACT_FIELD_NAME);
		add(genericTextField, c);
		
		c.gridx = 4;
		JButton settingsButton = new JButton();
		settingsButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("settings.png")));
		settingsButton.addActionListener(e -> showSettingsDialog());
		add(settingsButton, c);
		
		c.gridx = 5;
		removeButton = new JButton();
		removeButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("delete.png")));
		add(removeButton, c);
		
		removeTokenCheckBox.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				setFieldsEnabledDisabled();
			}
		});
		
		tokenValueComboBox.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				valueComboBoxChanged(tokenValueComboBox.getSelectedItem().toString());
			}
		});
	}
	
	private void valueComboBoxChanged(String newOption) {
		//Save current text to temp
		valueTempText[currentValueComboBoxIndex] = genericTextField.getText();
		// Add temp text of newly selected item to textfield
		currentValueComboBoxIndex = tokenValueComboBox.getSelectedIndex();
		genericTextField.setText(valueTempText[currentValueComboBoxIndex]);
	
		genericTextField.setEnabled(true);
		
		if(newOption.equals(OPTION_AUTO_EXTRACT)) {
			genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
			genericTextField.setPlaceholder(PLACEHOLDER_EXTRACT_FIELD_NAME);
			genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
		}
		if(newOption.equals(OPTION_STATIC_VALUE)) {
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
			genericTextField.setPlaceholder(PLACEHOLDER_STATIC_VALUE);
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
		}
		if(newOption.equals(OPTION_FROM_TO_STRING)) {
			genericTextField.setToolTipText(TOOLTIP_FROM_TO_STRING);
			genericTextField.setPlaceholder(PLACEHOLDER_FROM_TO_STRING);
			genericTextField.setToolTipText(TOOLTIP_FROM_TO_STRING);
			// Set Default Value for generic Text Field from to option
			if(genericTextField.getText().equals("")) {
				genericTextField.setText("from [] to []");
			}
		}
		if(newOption.equals(OPTION_PROMPT_FOR_INPUT)) {
			genericTextField.setEnabled(false);
			genericTextField.setToolTipText(TOOLTIP_PROMPT_FOR_INPUT);
			genericTextField.setPlaceholder("");
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
		}
		genericTextField.repaint();
	}

	private void setFieldsEnabledDisabled() {
		if (removeTokenCheckBox.isSelected()) {
			tokenValueComboBox.setEnabled(false);
			genericTextField.setEnabled(false);
			placeholderCache = genericTextField.getPlaceholder();
			genericTextField.setPlaceholder("");
		} else {
			tokenValueComboBox.setEnabled(true);
			genericTextField.setEnabled(true);
			genericTextField.setPlaceholder(placeholderCache);
		}
	}
	
	public JButton getRemoveButton() {
		return removeButton;
	}

	public String getTokenName() {
		return nameTextField.getText();
	}

	public void setTokenName(String name) {
		nameTextField.setText(name);
	}

	public boolean isRemoveToken() {
		return removeTokenCheckBox.isSelected();
	}

	public void setIsRemoveToken(boolean isRemoveToken) {
		removeTokenCheckBox.setSelected(isRemoveToken);
		setFieldsEnabledDisabled();
	}

	public void setTokenValueComboBox(boolean isAuto, boolean isStatic, boolean isFromToString, boolean isPromptForInput) {
		if (isAuto) {
			tokenValueComboBox.setSelectedItem(OPTION_AUTO_EXTRACT);
		} 
		if (isStatic) {
			tokenValueComboBox.setSelectedItem(OPTION_STATIC_VALUE);
		} 
		if (isFromToString) {
			tokenValueComboBox.setSelectedItem(OPTION_FROM_TO_STRING);
		}
		if(isPromptForInput) {
			tokenValueComboBox.setSelectedItem(OPTION_PROMPT_FOR_INPUT);
		}
	}

	public void setGenericTextFieldText(String text) {
		genericTextField.setText(text);
	}

	public boolean isAutoExtract() {
		if (isRemoveToken()) {
			return false;
		} else {
			return tokenValueComboBox.getSelectedItem().equals(OPTION_AUTO_EXTRACT);
		}
	}

	public boolean isStaticValue() {
		if (isRemoveToken()) {
			return false;
		} else {
			return tokenValueComboBox.getSelectedItem().equals(OPTION_STATIC_VALUE);
		}
	}

	public boolean isFromToString() {
		if (isRemoveToken()) {
			return false;
		} else {
			return tokenValueComboBox.getSelectedItem().equals(OPTION_FROM_TO_STRING);
		}
	}
	
	public boolean isPromptForInput() {
		if (isRemoveToken()) {
			return false;
		}
		else {
			return tokenValueComboBox.getSelectedItem().equals(OPTION_PROMPT_FOR_INPUT);
		}
	}
	
	public void setPromptForInput() {
		if(!isRemoveToken()) {
			tokenValueComboBox.setSelectedItem(OPTION_PROMPT_FOR_INPUT);
		}
	}

	public String getAutoExtractFieldName() {
		if (isAutoExtract()) {
			return genericTextField.getText();
		} else {
			return null;
		}
	}

	public String getStaticTokenValue() {
		if (isStaticValue()) {
			return genericTextField.getText();
		} else {
			return null;
		}
	}

	public String getGrepFromString() {
		if (isFromToString()) {
			return getFromToArray(genericTextField.getText())[0];
		} else {
			return null;
		}
	}

	public String getGrepToString() {
		if (isFromToString()) {
			return getFromToArray(genericTextField.getText())[1];
		} else {
			return null;
		}
	}

	public String[] getFromToStringArray() {
		if (isFromToString()) {
			return getFromToArray(genericTextField.getText());
		} else {
			return null;
		}
	}

	public void setAutoExtractFieldName(String extractFieldName) {
		tokenValueComboBox.setSelectedItem(OPTION_AUTO_EXTRACT);
		valueComboBoxChanged(OPTION_AUTO_EXTRACT);
		genericTextField.setText(extractFieldName);
	}

	public void setStaticTokenValue(String tokenValue) {
		tokenValueComboBox.setSelectedItem(OPTION_STATIC_VALUE);
		valueComboBoxChanged(OPTION_STATIC_VALUE);
		genericTextField.setText(tokenValue);
	}

	public void setFromToString(String fromString, String toString) {
		tokenValueComboBox.setSelectedItem(OPTION_FROM_TO_STRING);
		valueComboBoxChanged(OPTION_STATIC_VALUE);
		genericTextField.setText("from [" + fromString + "] to [" + toString + "]");
	}
	
	public void setRedColorNameTextField() {
		nameTextField.setBackground(GenericHelper.getErrorBgColor());
	}
	
	public void setRedColorGenericTextField() {
		genericTextField.setBackground(GenericHelper.getErrorBgColor());
	}
	
	public void setDefaultColorAllTextFields() {
		Color color = UIManager.getColor("TextField.background");
		nameTextField.setBackground(color);
		genericTextField.setBackground(color);
	}

	// Returns a String array of length 2. [0] = grepFrom / [1] = grepTo. Returns
	// null if not applicable
	private String[] getFromToArray(String text) {
		if (!isFromToString()) {
			return null;
		}
		String fromString = null;
		String toString = null;
		String[] split1From = text.trim().split("from \\[");
		if (split1From.length == 2) {
			String[] split2From = split1From[1].split("\\] to \\[");
			if(split2From.length == 2) {
				fromString = split2From[0];
			}
		}
		String[] split1To = text.trim().split("\\] to \\[");
		if(split1To.length == 2) {
			if(split1To[1].endsWith("]")) {
				toString = split1To[1].substring(0, split1To[1].length()-1);
			}
		}
		if (fromString != null && toString != null && !fromString.equals("")) {
			String[] fromToArry = { fromString, toString };
			// No no lines allowed in from string or to string
			if(fromString.contains("\n") || toString.contains("\n")) {
				return null;
			}
			return fromToArry;
		} else {
			return null;
		}
	}

	public EnumSet<TokenLocation> getTokenLocationSet() {
		return tokenLocationSet;
	}

	public void setTokenLocationSet(EnumSet<TokenLocation> tokenLocationSet) {
		this.tokenLocationSet = tokenLocationSet;
	}
	
	public EnumSet<AutoExtractLocation> getAutoExtractLocationSet() {
		return autoExtractLocationSet;
	}

	public void setAutoExtractLocationSet(EnumSet<AutoExtractLocation> autoExtractLocationSet) {
		this.autoExtractLocationSet = autoExtractLocationSet;
	}
	
	public EnumSet<FromToExtractLocation> getFromToExtractLocationSet() {
		return fromToExtractLocationSet;
	}

	public void setFromToExtractLocationSet(EnumSet<FromToExtractLocation> fromToExtractLocationSet) {
		this.fromToExtractLocationSet = fromToExtractLocationSet;
	}
	
	private void showSettingsDialog() {
		JPanel inputPanel = new JPanel();
		inputPanel.setLayout(new BoxLayout(inputPanel, BoxLayout.PAGE_AXIS));
		JLabel infoLabel;
		if(removeTokenCheckBox.isSelected()) {
			infoLabel = new JLabel("Remove Parameter at:");
		}
		else {
			infoLabel = new JLabel("Replace Parameter at:");
		}
		inputPanel.add(infoLabel);
		for(TokenLocation tokenLocation : TokenLocation.values()) {
			JCheckBox locationCheckBox = new JCheckBox(tokenLocation.getName());
			locationCheckBox.setSelected(tokenLocationSet.contains(tokenLocation));
			locationCheckBox.addActionListener(e -> {
				if(locationCheckBox.isSelected()) {
					tokenLocationSet.add(tokenLocation);
				}
				else {
					tokenLocationSet.remove(tokenLocation);
				}
			});
			inputPanel.add(locationCheckBox);
		}
		if(!removeTokenCheckBox.isSelected() && isAutoExtract() || isFromToString()) {
			inputPanel.add(new JLabel(" "));
	    	inputPanel.add(new JSeparator(JSeparator.HORIZONTAL));
	    	inputPanel.add(new JLabel(" "));
	    	inputPanel.add(new JLabel("Try to extract value from:"));
	    	if(isAutoExtract()) {
	    		for(AutoExtractLocation autoExtractLocation : AutoExtractLocation.values()) {
	    			JCheckBox locationCheckBox = new JCheckBox(autoExtractLocation.getName());
	    			locationCheckBox.setSelected(autoExtractLocationSet.contains(autoExtractLocation));
	    			locationCheckBox.addActionListener(e -> {
	    				if(locationCheckBox.isSelected()) {
	    					autoExtractLocationSet.add(autoExtractLocation);
	    				}
	    				else {
	    					autoExtractLocationSet.remove(autoExtractLocation);
	    				}
	    			});
	    			inputPanel.add(locationCheckBox);
	    		}
			}
	    	if(isFromToString()) {
	    		final ArrayList<JCheckBox> locationCheckBoxList = new ArrayList<JCheckBox>();
		    	for(FromToExtractLocation fromToExtractLocation : FromToExtractLocation.values()) {
		    		JCheckBox locationCheckBox = new JCheckBox(fromToExtractLocation.getName());
		    		locationCheckBox.setSelected(fromToExtractLocationSet.contains(fromToExtractLocation));
		    		if(fromToExtractLocation == FromToExtractLocation.ALL) {
		    			locationCheckBox.addActionListener(e -> {
		    				if(locationCheckBox.isSelected()) {
		    					fromToExtractLocationSet.add(fromToExtractLocation);
			    				for(JCheckBox checkBox :locationCheckBoxList) {
			    					checkBox.setEnabled(false);
			    				}
			    			}
			    			else {
			    				fromToExtractLocationSet.remove(fromToExtractLocation);
			    				for(JCheckBox checkBox :locationCheckBoxList) {
			    					checkBox.setEnabled(true);
			    				}
			    			}
		    			});
		    		}
		    		else {
		    			if(fromToExtractLocation != FromToExtractLocation.HEADER && fromToExtractLocation != FromToExtractLocation.BODY)  {
		    				locationCheckBoxList.add(locationCheckBox);
			    			locationCheckBox.setEnabled(!fromToExtractLocationSet.contains(FromToExtractLocation.ALL));
		    			}
		    			locationCheckBox.addActionListener(e -> {
		    				if(locationCheckBox.isSelected()) {
		    					fromToExtractLocationSet.add(fromToExtractLocation);
			    			}
			    			else {
			    				fromToExtractLocationSet.remove(fromToExtractLocation);
			    			}
		    			});
		    		}
		    		inputPanel.add(locationCheckBox);
		    	}
	    	}
		}
		JOptionPane.showConfirmDialog(this, inputPanel, "Parameter Settings for " + getTokenName(), JOptionPane.CLOSED_OPTION);
	}
}
