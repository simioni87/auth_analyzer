package burp;

import java.awt.Component;
import java.io.PrintWriter;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.MainPanel;
import com.protect7.authanalyzer.util.Version;

public class BurpExtender implements IBurpExtender, ITab {

	private MainPanel panel;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		// Extension needs Jsoup and Gson Library
		callbacks.setExtensionName("Auth Analyzer");
		panel = new MainPanel(callbacks);
		callbacks.addSuiteTab(this);
		callbacks.registerHttpListener(new HttpListener(callbacks));
		PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
		stdout.println("Auth Analyzer successfully started");
		stdout.println("Version " + Version.VERSION);
		stdout.println("Protect7 GmbH");
		stdout.println("www.protect7.com");
		stdout.close();
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