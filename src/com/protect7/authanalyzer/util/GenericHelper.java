package com.protect7.authanalyzer.util;

import java.awt.Color;
import java.awt.Component;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JFrame;
import javax.swing.JTabbedPane;
import javax.swing.Timer;
import com.protect7.authanalyzer.filter.RequestFilter;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.util.Setting.Item;
import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class GenericHelper {
	
	public static void repeatRequests(IHttpRequestResponse[] messages, ConfigurationPanel configurationPanel) {
		if(configurationPanel.isPaused()) {
			configurationPanel.pauseButtonPressed();
		}
		if(!CurrentConfig.getCurrentConfig().isRunning()) {
			configurationPanel.startStopButtonPressed();
		}
		if(CurrentConfig.getCurrentConfig().isRunning()) {
			boolean applyFilters = Setting.getValueAsBoolean(Item.APPLY_FILTER_ON_MANUAL_REPEAT);
			for(IHttpRequestResponse message : messages) {
				boolean isFiltered = false;
				if(applyFilters) {
					IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(message);
					IResponseInfo responseInfo = null;
					if(message.getResponse() != null) {
						responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(message.getResponse());
					}
					for(int i=0; i<CurrentConfig.getCurrentConfig().getRequestFilterList().size(); i++) {
						RequestFilter filter = CurrentConfig.getCurrentConfig().getRequestFilterAt(i);
						if(filter.filterRequest(BurpExtender.callbacks, IBurpExtenderCallbacks.TOOL_PROXY, requestInfo, responseInfo)) {
							isFiltered = true;
							break;
						}
					}
				}
				if(!isFiltered) {
					CurrentConfig.getCurrentConfig().performAuthAnalyzerRequest(message);
				}
			}
		}
	}
	
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
				if(burpTabbedPane.getTitleAt(i).equals(Globals.EXTENSION_NAME)) {
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
	
	public static String getArrayAsString(String[] array) {
		String arrayAsString = "";
		if (array != null) {
			for (String arrayPart : array) {
				if (arrayAsString.equals("")) {
					arrayAsString = arrayPart;
				} else {
					arrayAsString += ", " + arrayPart;
				}
			}
		}
		return arrayAsString;
	}
	
	public static JFrame getBurpFrame() {
        for (Frame f : Frame.getFrames()) {
            if (f.isVisible() && f.getTitle().startsWith(("Burp Suite"))) {
                return (JFrame) f;
            }
        }
        return null;
    }
}