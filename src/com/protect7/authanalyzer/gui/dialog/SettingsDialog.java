package com.protect7.authanalyzer.gui.dialog;

import com.protect7.authanalyzer.gui.util.PlaceholderTextField;
import com.protect7.authanalyzer.util.Globals;
import com.protect7.authanalyzer.util.Setting;
import com.protect7.authanalyzer.util.Setting.Item;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;

public class SettingsDialog extends JDialog {
	
	private static final long serialVersionUID = -1481627857573067086L;	
	private final GridLayout layout;
	
	public SettingsDialog(Component parent) {
		setTitle(Globals.EXTENSION_NAME + " - Settings");
		JPanel dialogPanel = (JPanel) getContentPane();
		dialogPanel.setBorder(new EmptyBorder(10, 10, 10, 10));
		layout = new GridLayout(1, 2, 5, 5);
		dialogPanel.setLayout(layout);
		
		for(Item item : Setting.Item.values()) {
			addSettingElement(item);
		}

		add(new JLabel(""));
		JButton closeButton = new JButton("OK");
		closeButton.addActionListener(e -> dispose());
		JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
		buttonPanel.add(closeButton);
		add(buttonPanel);
		
		setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);	
		setVisible(true);
		pack();
		setLocationRelativeTo(parent);
	}
	
	private void addSettingElement(Item item) {
		layout.setRows(layout.getRows()+1);
		add(new JLabel(item.getDescription() + ": "));
		if(item.getType() == Setting.Type.ARRAY || item.getType() == Setting.Type.STRING) {
			PlaceholderTextField inputField = new PlaceholderTextField();
			String currentValue = Setting.getValueAsString(item);
			inputField.setText(currentValue);
			inputField.addFocusListener(new FocusAdapter() {
				@Override
				public void focusLost(FocusEvent e) {
					super.focusLost(e);
					Setting.setValue(item, inputField.getText());
				}
			});
			add(inputField);
		}
		if(item.getType() == Setting.Type.BOOLEAN) {
			JCheckBox checkBox = new JCheckBox();
			boolean currentValue = Setting.getValueAsBoolean(item);
			checkBox.setSelected(currentValue);
			checkBox.addActionListener(e -> Setting.setValue(item, String.valueOf(checkBox.isSelected())));
			add(checkBox);
		}
		if(item.getType() == Setting.Type.INTEGER) {
			JSpinner integerField = new JSpinner();
			((SpinnerNumberModel) integerField.getModel()).setMinimum(item.getRange().getMinimum());
			((SpinnerNumberModel) integerField.getModel()).setMaximum(item.getRange().getMaximum());
			((SpinnerNumberModel) integerField.getModel()).setStepSize(1);
			int currentValue = Setting.getValueAsInteger(item);
			integerField.setValue(currentValue);
			integerField.addChangeListener(e -> Setting.setValue(item, String.valueOf(integerField.getValue())));
			add(integerField);
		}
	}
}