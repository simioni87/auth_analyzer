package com.protect7.authanalyzer.gui;

import java.awt.Color;
import java.awt.Component;

import javax.swing.JTable;
import javax.swing.table.DefaultTableCellRenderer;

import com.protect7.authanalyzer.util.BypassConstants;

public class BypassCellRenderer extends DefaultTableCellRenderer {

	private static final long serialVersionUID = 1L;

	@Override
	public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus,
			int row, int column) {
		final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
		if (value instanceof BypassConstants) {
			if (value.equals(BypassConstants.BYPASSED)) {
				c.setBackground(new Color(255, 10, 10));
			}
			if (value.equals(BypassConstants.POTENTIAL_BYPASSED)) {
				c.setBackground(new Color(255,165,0));
			}
			if (value.equals(BypassConstants.NOT_BYPASSED)) {
				c.setBackground(new Color(80, 220, 80));
			}

		}
		return c;
	}

}
