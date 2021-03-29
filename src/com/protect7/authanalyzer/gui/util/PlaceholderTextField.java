package com.protect7.authanalyzer.gui.util;

import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;

import javax.swing.JTextField;

public class PlaceholderTextField extends JTextField {

	private static final long serialVersionUID = 5734794485649557381L;
	private String placeholder;

    public PlaceholderTextField() {
    	super();
    }
    
	public PlaceholderTextField(final int pColumns) {
        super(pColumns);
    }

    @Override
    protected void paintComponent(final Graphics pG) {
        super.paintComponent(pG);

        if (placeholder == null || placeholder.length() == 0 || getText().length() > 0) {
            return;
        }

        final Graphics2D g = (Graphics2D) pG;
        g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g.setColor(getDisabledTextColor());
        g.drawString(placeholder, getInsets().left, pG.getFontMetrics().getMaxAscent() + getInsets().top);
    }

    public void setPlaceholder(String placeholder) {
        this.placeholder = placeholder;
    }
    
    public String getPlaceholder() {
    	return placeholder;
    }

}