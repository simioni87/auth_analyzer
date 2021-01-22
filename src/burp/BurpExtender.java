package burp;

import java.awt.Component;

import javax.swing.JTabbedPane;

import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.MainPanel;
import com.protect7.authanalyzer.util.Version;

public class BurpExtender implements IBurpExtender, ITab {

	public static final String EXTENSION_NAME = "Auth Analyzer";
	public static MainPanel mainPanel;
	public static IBurpExtenderCallbacks callbacks;
	public static JTabbedPane burpTabbedPane = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName("Auth Analyzer");
		mainPanel = new MainPanel();
		callbacks.addSuiteTab(this);
		HttpListener httpListener = new HttpListener();
		callbacks.registerHttpListener(httpListener);
		callbacks.registerProxyListener(httpListener);
		callbacks.printOutput("Auth Analyzer successfully started");
		callbacks.printOutput("Version " + Version.VERSION);
		callbacks.printOutput("Created by Simon Reinhart");
		callbacks.printOutput("Protect7 GmbH");
		callbacks.printOutput("www.protect7.com");
	}

	@Override
	public String getTabCaption() {
		return EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}
}