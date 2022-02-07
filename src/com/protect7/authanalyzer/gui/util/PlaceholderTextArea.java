package com.protect7.authanalyzer.gui.util;

import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.BorderFactory;
import javax.swing.JTextArea;
import javax.swing.JToolTip;
import javax.swing.border.Border;

public class PlaceholderTextArea extends JTextArea {

	private static final long serialVersionUID = 5734794485649557381L;
	private String placeholder;

    public PlaceholderTextArea() {
    	super();
    	init();
    }
    
    public PlaceholderTextArea(int rows, int columns) {
    	super(rows, columns);
    	init();
    }

    public JToolTip createToolTip()
    {
	    JToolTip tip = new JToolTip();
	    tip.setComponent(this);
	    tip.putClientProperty("html.disable", null);
	    return tip;
    }

    private void init() {
    	Border border = BorderFactory.createLineBorder(Color.LIGHT_GRAY);
    	setBorder(BorderFactory.createCompoundBorder(border, BorderFactory.createEmptyBorder(2, 5, 2, 5)));
    	setLineWrap(true);
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
