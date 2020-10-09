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
		try {
			Class.forName("org.jsoup.Jsoup");
			Class.forName("com.google.gson.JsonObject");
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

		} catch (ClassNotFoundException e) {
			PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
			stdout.println("Failed to start Auth Analyzer");
			stdout.println("Jsoup and / or Gson library missing. Add Jsoup / Gson library to use Auth Analyzer.");
			stdout.println("1. Download lib (jsoup and gson)");
			stdout.println("2. Link lib in Burp: Extender -> Options -> Java Environment");
			stdout.println("");
			stdout.println("Unload Auth Anayzer");
			stdout.close();
			callbacks.unloadExtension();
		}
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