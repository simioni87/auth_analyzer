package com.protect7.authanalyzer.gui;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JSeparator;
import javax.swing.JTextField;
import javax.swing.UIManager;

public class TokenPanel extends JPanel {

	private static final long serialVersionUID = 7682542523017826799L;
	private final String OPTION_AUTO_EXTRACT = "Auto Extract";
	private final String OPTION_STATIC_VALUE = "Static Value";
	private final String OPTION_FROM_TO_STRING = "From To String";
	private final String OPTION_PROMPT_FOR_INPUT = "Prompt for Input";
	private final String LABEL_EXTRACT_FIELD_NAME = "Extract Field Name";
	private final String LABEL_STATIC_VALUE = "Static Value";
	private final String LABEL_FROM_TO_STRING = "From To String";
	private final String TOOLTIP_EXTRACT_TOKEN_NAME = "<html>Name of the Parameter for which the static / extracted value will be replaced.<br>Respected Parameter locations: <strong>URL, Body, Cookie</strong>.</html>";
	private final String TOOLTIP_REMOVE = "<html>Replaces the given token name with the Name \"dummyparam\"</html>";
	private final String TOOLTIP_VALUE_EXTRACTION = "<html>Defines how the Parameter value will be discovered</html>";
	private final String TOOLTIP_EXTRACT_FIELD_NAME = "<html>Respected Extract Locations (Names): <strong>Set-Cookie (Cookie Name), HTML Input Field Name, JSON Data (Key)</strong>.</html>";
	private final String TOOLTIP_STATIC_VALUE = "<html>The defined value will be used</html>";
	private final String TOOLTIP_FROM_TO_STRING = "<html>The value between the \"From\" and \"To\" String will be extracted.<br>The desired value can be marked in message editor and directly<br>set as From-To String by the context menu.</html>";
	private final String TOOLTIP_PROMPT_FOR_INPUT = "<html>Value can be entered manually if request has a Parameter with corresponding name</html>";
	private final JTextField nameTextField;
	private final JCheckBox removeTokenCheckBox;
	private final JComboBox<String> tokenValueComboBox;
	private final JTextField genericTextField;
	private final JLabel genericTextFieldLabel;
	private int currentValueComboBoxIndex = 0;
	private String[] valueTempText = {"", "", "", ""};
	private final JLabel valueExtractLocationLabel;

	public TokenPanel() {
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.BOTH;
		c.gridwidth = 4;
		Insets insetLabel = new Insets(10, 5, 0, 5);
		Insets insetInputField = new Insets(0, 5, 10, 5);
		c.insets = insetLabel;
		
		add(new JSeparator(), c);
		
		c.fill = GridBagConstraints.NONE;
		c.gridwidth = 1;
		c.gridy = 1;
		JLabel tokenNameLabel = new JLabel("Parameter Name");
		tokenNameLabel.setToolTipText(TOOLTIP_EXTRACT_TOKEN_NAME);
		add(tokenNameLabel, c);
		nameTextField = new JTextField(20);
		nameTextField.setToolTipText(TOOLTIP_EXTRACT_TOKEN_NAME);
		c.gridy = 2;
		c.insets = insetInputField;
		add(nameTextField, c);
		
		JLabel removeLabel = new JLabel("Remove");
		removeLabel.setToolTipText(TOOLTIP_REMOVE);
		c.gridx = 1;
		c.gridy = 1;
		c.insets = insetLabel;
		add(removeLabel, c);
		removeTokenCheckBox = new JCheckBox();
		removeTokenCheckBox.setToolTipText(TOOLTIP_REMOVE);
		c.gridy = 2;
		c.insets = insetInputField;
		add(removeTokenCheckBox, c);
		
		valueExtractLocationLabel = new JLabel("Parameter Value");
		valueExtractLocationLabel.setToolTipText(TOOLTIP_VALUE_EXTRACTION);
		c.gridx = 2;
		c.gridy = 1;
		c.insets = insetLabel;
		add(valueExtractLocationLabel, c);
		String[] tokenValueItems = {OPTION_AUTO_EXTRACT, OPTION_STATIC_VALUE, OPTION_FROM_TO_STRING, OPTION_PROMPT_FOR_INPUT};
		tokenValueComboBox = new JComboBox<String>(tokenValueItems);
		tokenValueComboBox.setToolTipText(TOOLTIP_VALUE_EXTRACTION);
		c.gridy = 2;
		c.insets = insetInputField;
		add(tokenValueComboBox, c);
		
		genericTextFieldLabel = new JLabel(LABEL_EXTRACT_FIELD_NAME);
		genericTextFieldLabel.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
		c.gridx = 3;
		c.gridy = 1;
		c.insets = insetLabel;
		add(genericTextFieldLabel, c);
		genericTextField = new JTextField(30);
		c.gridy = 2;
		c.insets = insetInputField;
		add(genericTextField, c);
		
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
		
		//AutoUpdate Token Extract Name
		genericTextField.addFocusListener(new FocusAdapter() {
			@Override
			public void focusGained(FocusEvent e) {
				if(tokenValueComboBox.getSelectedItem().equals(OPTION_AUTO_EXTRACT) && 
						genericTextField.getText().equals("")) {
					genericTextField.setText(nameTextField.getText());
				}
			}
		});
	}
	
	private void valueComboBoxChanged(String newOption) {
		//Save current text to temp
		valueTempText[currentValueComboBoxIndex] = genericTextField.getText();
		// Add temp text of newly selected item to textfield
		currentValueComboBoxIndex = tokenValueComboBox.getSelectedIndex();
		genericTextField.setText(valueTempText[currentValueComboBoxIndex]);
		
		genericTextFieldLabel.setEnabled(true);
		genericTextField.setEnabled(true);
		
		if(newOption.equals(OPTION_AUTO_EXTRACT)) {
			genericTextFieldLabel.setText(LABEL_EXTRACT_FIELD_NAME);
			genericTextFieldLabel.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
			genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
		}
		if(newOption.equals(OPTION_STATIC_VALUE)) {
			genericTextFieldLabel.setText(LABEL_STATIC_VALUE);
			genericTextFieldLabel.setToolTipText(TOOLTIP_STATIC_VALUE);
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
		}
		if(newOption.equals(OPTION_FROM_TO_STRING)) {
			genericTextFieldLabel.setText(LABEL_FROM_TO_STRING);
			genericTextFieldLabel.setToolTipText(TOOLTIP_FROM_TO_STRING);
			genericTextField.setToolTipText(TOOLTIP_FROM_TO_STRING);
			// Set Default Value for generic Text Field from to option
			if(genericTextField.getText().equals("")) {
				genericTextField.setText("from [] to []");
			}
		}
		if(newOption.equals(OPTION_PROMPT_FOR_INPUT)) {
			genericTextFieldLabel.setEnabled(false);
			genericTextField.setEnabled(false);
			genericTextFieldLabel.setToolTipText(TOOLTIP_PROMPT_FOR_INPUT);
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
		}
	}

	private void setFieldsEnabledDisabled() {
		if (removeTokenCheckBox.isSelected()) {
			valueExtractLocationLabel.setEnabled(false);
			tokenValueComboBox.setEnabled(false);
			genericTextFieldLabel.setEnabled(false);
			genericTextField.setEnabled(false);
		} else {
			valueExtractLocationLabel.setEnabled(true);
			tokenValueComboBox.setEnabled(true);
			genericTextFieldLabel.setEnabled(true);
			genericTextField.setEnabled(true);
		}
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
		nameTextField.setBackground(new Color(255, 102, 102));
	}
	
	public void setRedColorGenericTextField() {
		genericTextField.setBackground(new Color(255, 102, 102));
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
			return fromToArry;
		} else {
			return null;
		}
	}
}
