package com.protect7.authanalyzer.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JTabbedPane;
import javax.swing.Timer;

import burp.BurpExtender;

public class GenericHelper {
	
	public static void uiUpdateAnimation(Component component, Color animationColor) {
		Color foregroundColor = component.getForeground();
		if(component != null && foregroundColor != null && foregroundColor.getRGB() != animationColor.getRGB()) {
			component.setForeground(animationColor);
			Timer timer = new Timer(5000, new ActionListener() {
				
				@Override
				public void actionPerformed(ActionEvent e) {
					component.setForeground(foregroundColor);
				}
			});
			timer.setRepeats(false);
			timer.start();
		}
	}
	
	public static void animateBurpExtensionTab() {
		if(BurpExtender.mainPanel.getParent() != null && BurpExtender.mainPanel.getParent() instanceof JTabbedPane) {
			JTabbedPane burpTabbedPane = (JTabbedPane) BurpExtender.mainPanel.getParent();
			for(int i=0; i<burpTabbedPane.getTabCount(); i++) {
				if(burpTabbedPane.getTitleAt(i).equals(BurpExtender.EXTENSION_NAME)) {
					Color animationColor = new Color(240, 110, 0);
					Color currentColor = burpTabbedPane.getForegroundAt(i);
					final int id = i;
					if(currentColor != null && currentColor.getRGB() != animationColor.getRGB()) {
						burpTabbedPane.setBackgroundAt(i, animationColor);
						Timer timer = new Timer(5000, e -> {
							// JTabbedPane Title Color must be changed with 'setBackgorundAt' for some reason
							burpTabbedPane.setBackgroundAt(id, currentColor);
						});
						timer.setRepeats(false);
						timer.start();
					}
				}
			}
		}
	}
	
	public static Color getErrorBgColor() {
		return new Color(255, 102, 102);
	}
}