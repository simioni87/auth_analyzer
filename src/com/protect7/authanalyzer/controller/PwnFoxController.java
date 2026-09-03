package com.protect7.authanalyzer.controller;

/**
 * Creates and updates one Auth Analyzer session per PwnFox container. PwnFox tags every request of a Firefox
 * container with the X-PwnFox-Color header. The configured headers (Authorization, Cookie or any custom one)
 * of such a request are taken over as "Header(s) to Replace" of the session named after the color. Re-logging
 * in a container therefore refreshes the corresponding session automatically.
 * 
 * If the PwnFox Burp extension is loaded before the Auth Analyzer it strips the color header and sets the Burp
 * highlight instead, hence the highlight is used as fallback.
 */

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.gui.entity.SessionPanel;
import com.protect7.authanalyzer.gui.main.ConfigurationPanel;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.Setting;
import burp.BurpExtender;
import burp.IHttpRequestResponse;

public class PwnFoxController {

	private static final String COLOR_HEADER_NAME = "X-PwnFox-Color";
	private static final List<String> PWNFOX_COLORS = Arrays.asList("red", "orange", "yellow", "green", "cyan",
			"blue", "pink", "magenta", "gray");
	private static final Pattern VALID_COLOR = Pattern.compile("[a-zA-Z0-9_-]{1,20}");
	// Holds the last taken over headers per color to not touch the GUI on every single request
	private final ConcurrentHashMap<String, String> lastHeadersByColor = new ConcurrentHashMap<>();

	public void process(IHttpRequestResponse messageInfo) {
		if (!Setting.getValueAsBoolean(Setting.Item.PWNFOX_AUTO_SESSION) || messageInfo.getRequest() == null) {
			return;
		}
		List<String> headers = BurpExtender.callbacks.getHelpers().analyzeRequest(messageInfo).getHeaders();
		String color = getColor(messageInfo, headers);
		if (color == null) {
			return;
		}
		String headersToReplace = getHeadersToReplace(headers);
		if (headersToReplace.equals("") || headersToReplace.equals(lastHeadersByColor.put(color, headersToReplace))) {
			return;
		}
		SwingUtilities.invokeLater(() -> applyToSession(color, headersToReplace));
	}

	private String getColor(IHttpRequestResponse messageInfo, List<String> headers) {
		String color = getHeaderValue(headers, COLOR_HEADER_NAME);
		if (color != null) {
			// The header is browser controlled, hence only accept values which are valid session names
			return VALID_COLOR.matcher(color).matches() && !color.equals("Original") ? color : null;
		}
		String highlight = messageInfo.getHighlight();
		if (highlight != null && PWNFOX_COLORS.contains(highlight.toLowerCase())) {
			return highlight.toLowerCase();
		}
		return null;
	}

	private String getHeadersToReplace(List<String> headers) {
		String headersToReplace = "";
		for (String headerName : Setting.getValueAsArray(Setting.Item.PWNFOX_HEADERS_TO_EXTRACT)) {
			if (!headerName.equals("")) {
				// Header can occur more than once (e.g. multiple Set-Cookie style custom headers)
				for (String header : headers) {
					if (isHeader(header, headerName)) {
						if (!headersToReplace.equals("")) {
							headersToReplace += "\n";
						}
						headersToReplace += header.trim();
					}
				}
			}
		}
		return headersToReplace;
	}

	private String getHeaderValue(List<String> headers, String headerName) {
		for (String header : headers) {
			if (isHeader(header, headerName)) {
				return header.split(":", 2)[1].trim();
			}
		}
		return null;
	}

	private boolean isHeader(String header, String headerName) {
		String[] headerKeyValuePair = header.split(":", 2);
		return headerKeyValuePair.length == 2 && headerKeyValuePair[0].trim().equalsIgnoreCase(headerName);
	}

	private void applyToSession(String sessionName, String headersToReplace) {
		ConfigurationPanel configurationPanel = BurpExtender.mainPanel.getConfigurationPanel();
		SessionPanel sessionPanel = configurationPanel.getSessionPanelByName(sessionName);
		if (sessionPanel == null) {
			if (CurrentConfig.getCurrentConfig().isRunning()) {
				BurpExtender.callbacks.printOutput("PwnFox: Can not create session '" + sessionName
						+ "' while the Auth Analyzer is running. Stop the Auth Analyzer to pick up the container.");
				return;
			}
			if (configurationPanel.createSession(sessionName, headersToReplace) == null) {
				lastHeadersByColor.remove(sessionName);
				return;
			}
			BurpExtender.callbacks.printOutput("PwnFox: Created session '" + sessionName + "'");
		} else {
			sessionPanel.setHeadersToReplaceText(headersToReplace);
		}
		// Update the running session as well, otherwise the new headers apply only after a restart
		Session session = CurrentConfig.getCurrentConfig().getSessionByName(sessionName);
		if (session != null) {
			session.setHeadersToReplace(headersToReplace);
			session.getStatusPanel().updateHeadersToReplace(session);
		}
	}
}
