package burp;

import java.awt.Component;
import javax.swing.JFrame;
import javax.swing.JMenu;
import javax.swing.JMenuBar;
import javax.swing.JTabbedPane;
import javax.swing.SwingUtilities;
import com.protect7.authanalyzer.controller.HttpListener;
import com.protect7.authanalyzer.gui.main.MainPanel;
import com.protect7.authanalyzer.gui.util.AuthAnalyzerMenu;
import com.protect7.authanalyzer.util.DataStorageProvider;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.Globals;

public class BurpExtender implements IBurpExtender, ITab, IExtensionStateListener {

	public static MainPanel mainPanel;
	private JMenu authAnalyzerMenu = null;
	public static IBurpExtenderCallbacks callbacks;
	public static JTabbedPane burpTabbedPane = null;

	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
		BurpExtender.callbacks = callbacks;
		callbacks.setExtensionName(Globals.EXTENSION_NAME);
		mainPanel = new MainPanel();
		callbacks.addSuiteTab(this);
		addAuthAnalyzerMenu();
		HttpListener httpListener = new HttpListener();
		callbacks.registerHttpListener(httpListener);
		callbacks.registerProxyListener(httpListener);
		callbacks.registerExtensionStateListener(this);
		callbacks.printOutput(Globals.EXTENSION_NAME + " successfully started");
		callbacks.printOutput("Version " + Globals.VERSION);
		callbacks.printOutput("Created by Simon Reinhart");
	}

	@Override
	public String getTabCaption() {
		return Globals.EXTENSION_NAME;
	}

	@Override
	public Component getUiComponent() {
		return mainPanel;
	}
	
	private void addAuthAnalyzerMenu() {
		SwingUtilities.invokeLater(new Runnable() {
			
			@Override
			public void run() {
				JFrame burpFrame = GenericHelper.getBurpFrame();
				if(burpFrame != null) {
					authAnalyzerMenu = new AuthAnalyzerMenu(Globals.EXTENSION_NAME);
					JMenuBar burpMenuBar = burpFrame.getJMenuBar();
					burpMenuBar.add(authAnalyzerMenu, burpMenuBar.getMenuCount() - 1);
				}
			}
		});

	}

	@Override
	public void extensionUnloaded() {
		if(authAnalyzerMenu != null && authAnalyzerMenu.getParent() != null) {
			authAnalyzerMenu.getParent().remove(authAnalyzerMenu);
		}
		try {
			mainPanel.getConfigurationPanel().createSessionObjects(false);
			DataStorageProvider.saveSetup();
		}
		catch (Exception e) {
			callbacks.printOutput("INFO: Session Setup not stored due to invalid data.");
		}
	}
}