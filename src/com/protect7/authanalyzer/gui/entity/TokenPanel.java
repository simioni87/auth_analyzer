package com.protect7.authanalyzer.gui.entity;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.EnumSet;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.UIManager;
import com.protect7.authanalyzer.entities.AutoExtractLocation;
import com.protect7.authanalyzer.entities.FromToExtractLocation;
import com.protect7.authanalyzer.entities.TokenLocation;
import com.protect7.authanalyzer.gui.dialog.TokenSettingsDialog;
import com.protect7.authanalyzer.gui.util.PlaceholderTextArea;
import com.protect7.authanalyzer.util.GenericHelper;

public class TokenPanel extends JPanel {

	private static final long serialVersionUID = 7682542523017826799L;
	public final String OPTION_AUTO_EXTRACT = "Auto Extract";
	public final String OPTION_STATIC_VALUE = "Static Value";
	public final String OPTION_FROM_TO_STRING = "From To String";
	public final String OPTION_PROMPT_FOR_INPUT = "Prompt for Input";
	private final String PLACEHOLDER_STATIC_VALUE = "Enter Static Value...";
	private final String PLACEHOLDER_FROM_TO_STRING = "from [] to []";
	private final String TOOLTIP_EXTRACT_TOKEN_NAME = "<html>Name of the Parameter for which the static / extracted value will be replaced.<br>Respected Parameter locations: <strong>Path, URL, Body, Cookie</strong>.</html>";
	private final String TOOLTIP_VALUE_EXTRACTION = "<html>Defines how the Parameter value will be discovered</html>";
	private final String TOOLTIP_EXTRACT_FIELD_NAME = "<html>Parameter Name will be used as Extract Field Name.</html>";
	private final String TOOLTIP_STATIC_VALUE = "<html>The defined value will be used</html>";
	private final String TOOLTIP_FROM_TO_STRING = "<html>The value between the \"From\" and \"To\" String will be extracted.<br>The desired value can be marked in message editor and directly<br>set as From-To String by the context menu.</html>";
	private final String TOOLTIP_PROMPT_FOR_INPUT = "<html>Value can be entered manually if request has a Parameter with corresponding name</html>";
	private final PlaceholderTextArea nameTextField;
	private final JButton removeButton;
	private final JComboBox<String> tokenValueComboBox;
	private final PlaceholderTextArea genericTextField;
	private String placeholderCache = "";
	private EnumSet<TokenLocation> tokenLocationSet = EnumSet.allOf(TokenLocation.class); 
	private EnumSet<AutoExtractLocation> autoExtractLocationSet = AutoExtractLocation.getDefaultSet();
	private EnumSet<FromToExtractLocation> fromToExtractLocationSet = FromToExtractLocation.getDefaultSet();
	private final ArrayList<JLabel> headerJLabelList = new ArrayList<JLabel>();
	private boolean caseSensitiveTokenName = true;
	private boolean addTokenIfNotExists = false;
	private boolean removeToken = false;
	private boolean urlEncoded = true;
	private boolean urlDecoded = false;
	public String aliases = "";
	
	public TokenPanel() {
		setLayout(new GridBagLayout());
		GridBagConstraints c = new GridBagConstraints();
		c.gridx = 0;
		c.gridy = 0;
		c.fill = GridBagConstraints.NONE;
		c.gridwidth = 1;
		c.insets = new Insets(10, 5, 0, 5);
		
		addHeader("Parameter Name", c);
		nameTextField = new PlaceholderTextArea(1, 20);
		nameTextField.setToolTipText(TOOLTIP_EXTRACT_TOKEN_NAME);
		nameTextField.putClientProperty("html.disable", null);
		nameTextField.setPlaceholder("Enter Parameter Name (Wildcard *)...");
		add(nameTextField, c);
		
		c.gridx++;
		addHeader("Parameter Value", c);
		String[] tokenValueItems = {OPTION_AUTO_EXTRACT, OPTION_STATIC_VALUE, OPTION_FROM_TO_STRING, OPTION_PROMPT_FOR_INPUT};
		tokenValueComboBox = new JComboBox<String>(tokenValueItems);
		tokenValueComboBox.setToolTipText(TOOLTIP_VALUE_EXTRACTION);
		tokenValueComboBox.putClientProperty("html.disable", null);
		add(tokenValueComboBox, c);
		
		
		c.gridx++;
		addHeader("Static Value / From To String", c);
		genericTextField = new PlaceholderTextArea(1, 27);
		genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
		genericTextField.putClientProperty("html.disable", null);
		genericTextField.setPlaceholder("");
		genericTextField.setEnabled(false);
		add(genericTextField, c);
		
		c.gridx++;
		JButton settingsButton = new JButton();
		settingsButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("settings.png")));
		settingsButton.addActionListener(e -> new TokenSettingsDialog(this));
		add(settingsButton, c);
		
		c.gridx++;
		removeButton = new JButton();
		removeButton.setIcon(new ImageIcon(this.getClass().getClassLoader().getResource("delete.png")));
		add(removeButton, c);
		
		tokenValueComboBox.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				valueComboBoxChanged(tokenValueComboBox.getSelectedItem().toString());
			}
		});
	}
	
	private void addHeader(String name, GridBagConstraints c) {
		c.gridy = 0;
		JLabel label = new JLabel(name);
		add(label, c);
		headerJLabelList.add(label);
		c.gridy = 1;
	}
	
	public void setHeaderVisible(boolean visible) {
		for(JLabel label : headerJLabelList) {
			label.setVisible(visible);
		}
	}
	
	private void valueComboBoxChanged(String newOption) {	
		genericTextField.setEnabled(true);	
		if(newOption.equals(OPTION_AUTO_EXTRACT)) {
			genericTextField.setEnabled(false);
			genericTextField.setPlaceholder("");
			genericTextField.setToolTipText(TOOLTIP_EXTRACT_FIELD_NAME);
			genericTextField.putClientProperty("html.disable", null);
		}
		if(newOption.equals(OPTION_STATIC_VALUE)) {
			genericTextField.setPlaceholder(PLACEHOLDER_STATIC_VALUE);
			genericTextField.setToolTipText(TOOLTIP_STATIC_VALUE);
			genericTextField.putClientProperty("html.disable", null);
		}
		if(newOption.equals(OPTION_FROM_TO_STRING)) {
			genericTextField.setPlaceholder(PLACEHOLDER_FROM_TO_STRING);
			genericTextField.setToolTipText(TOOLTIP_FROM_TO_STRING);
			genericTextField.putClientProperty("html.disable", null);
			// Set Default Value for generic Text Field from to option
			if(genericTextField.getText().equals("")) {
				genericTextField.setText("from [] to []");
			}
		}
		if(newOption.equals(OPTION_PROMPT_FOR_INPUT)) {
			genericTextField.setEnabled(false);
			genericTextField.setPlaceholder("");
			genericTextField.setToolTipText(TOOLTIP_PROMPT_FOR_INPUT);
			genericTextField.putClientProperty("html.disable", null);
		}
		genericTextField.repaint();
	}

	public void setFieldsEnabledDisabled() {
		if (removeToken) {
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
		return removeToken;
	}

	public void setIsRemoveToken(boolean isRemoveToken) {
		removeToken = isRemoveToken;
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
			// Always choose token Name as Extract Field Name
			//return genericTextField.getText();
			return nameTextField.getText();
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

	public boolean isSelectedItem(String item) {
		return tokenValueComboBox.getSelectedItem().equals(item);
	}
	
	public void setAutoExtractFieldName(String extractFieldName) {
		tokenValueComboBox.setSelectedItem(OPTION_AUTO_EXTRACT);
		valueComboBoxChanged(OPTION_AUTO_EXTRACT);
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

	public boolean isCaseSensitiveTokenName() {
		return caseSensitiveTokenName;
	}

	public void setCaseSensitiveTokenName(boolean caseSensitiveTokenName) {
		this.caseSensitiveTokenName = caseSensitiveTokenName;
	}

	public String getAliases() {
		return this.aliases;
	}
	public void setAliases(String aliases) {
		this.aliases = aliases;
	}

	public boolean isAddTokenIfNotExists() {
		return addTokenIfNotExists;
	}

	public void setAddTokenIfNotExists(boolean addTokenIfNotExists) {
		this.addTokenIfNotExists = addTokenIfNotExists;
	}

	public boolean isUrlEncoded() {
		return urlEncoded;
	}

	public void setUrlEncoded(boolean urlEncoded) {
		this.urlEncoded = urlEncoded;
	}

	public boolean isUrlDecoded() {
		return urlDecoded;
	}

	public void setUrlDecoded(boolean urlDecoded) {
		this.urlDecoded = urlDecoded;
	}
}