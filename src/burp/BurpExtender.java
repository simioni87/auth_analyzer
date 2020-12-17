package burp;

import java.awt.Component;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.MainPanel;
import com.protect7.authanalyzer.util.Version;

public class BurpExtender implements IBurpExtender, ITab {

	private MainPanel panel;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		callbacks.setExtensionName("Auth Analyzer");
		panel = new MainPanel(callbacks);
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(new HttpListener(callbacks));
		callbacks.printOutput("Auth Analyzer successfully started");
		callbacks.printOutput("Version " + Version.VERSION);
		callbacks.printOutput("Created by Simon Reinhart");
		callbacks.printOutput("Protect7 GmbH");
		callbacks.printOutput("www.protect7.com");
	}

	@Override
	public String getTabCaption() {
		return "Auth Analyzer";
	}

	@Override
	public Component getUiComponent() {
		return panel;
	}

}