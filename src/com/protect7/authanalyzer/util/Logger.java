package com.protect7.authanalyzer.util;

import java.io.PrintWriter;
import java.text.SimpleDateFormat;
import java.util.Date;

public class Logger {
	
	private static Logger mInstance = null;
	private final PrintWriter stdout;
	
	public Logger(PrintWriter stdout) {
		this.stdout = stdout;
	}
	
	public static synchronized Logger getLogInstance(PrintWriter stdout) {
		if(mInstance == null) {
			mInstance = new Logger(stdout);
		}
		return mInstance;
	}

	public synchronized void writeLog(SEVERITY severity, String message) {
		String logInfo = new SimpleDateFormat("yyyy-MM-dd k:mm:ss").format(new Date()) + 
				" " + severity.toString();
		stdout.println(logInfo + "   " + message);
	}
	
	public synchronized void writeMarker() {
		stdout.println("--------------------------------------------");
	}
	
	public enum SEVERITY {
		INFO,
		WARNING,
		ERROR
	}
}