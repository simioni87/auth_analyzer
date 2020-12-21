package com.protect7.authanalyzer.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumSet;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class DataExporter {

	private static DataExporter mInstance = new DataExporter();

	public static synchronized DataExporter getDataExporter() {
		return mInstance;
	}

	public void createXML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Content>");
			
			// Write Body
			for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
				writer.write("<Message>");
				IHttpRequestResponse originalRequestResponse = requestResponse.getRequestResponse();
				StringBuffer row = new StringBuffer();
				IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequestResponse);
				for (MainColumn column : mainColumns) {
					row.append("<"+column.getName().replace(" ", "_")+">"+
							setIntoCDATA(getCellValue(column, requestResponse.getId(), originalRequestInfo, originalRequestResponse))+
				"</"+column.getName().replace(" ", "_")+">\n");
				}
				IResponseInfo originalResponseInfo = BurpExtender.callbacks.getHelpers()
						.analyzeResponse(originalRequestResponse.getResponse());
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						row.append("<Original_"+column.getName().replace(" ", "_")+">"+
								setIntoCDATA(getCellValue(column, requestResponse.getId(), originalResponseInfo, originalRequestResponse, null))+
					"</Original_"+column.getName().replace(" ", "_")+">\n");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap().get(requestResponse.getId());
					IResponseInfo sessionResponseInfo = BurpExtender.callbacks.getHelpers()
							.analyzeResponse(sessionRequestResponse.getRequestResponse().getResponse());
					for (SessionColumn column : sessionColumns) {
						row.append("<"+session.getName().replace(" ", "_")+"_"+column.getName().replace(" ", "_")+">"+setIntoCDATA(getCellValue(column, requestResponse.getId(), sessionResponseInfo,
								sessionRequestResponse.getRequestResponse(), sessionRequestResponse.getStatus()))+
								"</"+session.getName().replace(" ", "_")+"_"+column.getName().replace(" ", "_")+">\n");
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</Message>\n");
			}
			writer.write("</Content>");
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	public void createHTML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<html><style>\r\n" + 
					"table{table-layout:auto;width:100%;font-family: Arial, sans-serif;}\r\n" + 
					"th{padding-top:12px;padding-bottom:12px;text-align:left;background-color:#747272;color:white;}\r\n" + 
					"tr:nth-child(even){background-color:#f2f2f2;}td,th{border:1px solid #ddd;padding:8px;}\r\n" + 
					"div{max-width:600px;height:300px;overflow-y:auto;word-wrap:break-word;}\r\n" + 
					"</style><table><tr>");
			// Write Title
			StringBuffer titleRow = new StringBuffer();
			for (MainColumn column : mainColumns) {
				titleRow.append("<th>"+encodeHTML(column.getName())+"</th>");
			}
			for (SessionColumn column : sessionColumns) {
				if (column != SessionColumn.BYPASS_STATUS) {
					titleRow.append("<th>"+encodeHTML( "Original " + column.getName())+"</th>");
				}
			}
			for (Session session : sessions) {
				for (SessionColumn column : sessionColumns) {
					titleRow.append("<th>"+encodeHTML(session.getName() + " " + column.getName())+"</th>");
				}
			}
			titleRow.deleteCharAt(titleRow.length() - 1);
			writer.write(titleRow.toString());
			writer.write("<tr>\n");

			// Write Body
			for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
				writer.write("<tr>");
				IHttpRequestResponse originalRequestResponse = requestResponse.getRequestResponse();
				StringBuffer row = new StringBuffer();
				IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequestResponse);
				for (MainColumn column : mainColumns) {
					row.append("<td><div>"+encodeHTML(getCellValue(column, requestResponse.getId(), originalRequestInfo, originalRequestResponse))+"</div></td>");
				}
				IResponseInfo originalResponseInfo = BurpExtender.callbacks.getHelpers()
						.analyzeResponse(originalRequestResponse.getResponse());
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						row.append("<td><div>"+encodeHTML(getCellValue(column, requestResponse.getId(), originalResponseInfo, originalRequestResponse, null))+"</div></td>");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap().get(requestResponse.getId());
					IResponseInfo sessionResponseInfo = BurpExtender.callbacks.getHelpers()
							.analyzeResponse(sessionRequestResponse.getRequestResponse().getResponse());
					for (SessionColumn column : sessionColumns) {
						row.append("<td><div class='message'>"+encodeHTML(getCellValue(column, requestResponse.getId(), sessionResponseInfo,
								sessionRequestResponse.getRequestResponse(), sessionRequestResponse.getStatus()))+"</div></td>");
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</tr>\n");
			}
			writer.write("</table>Generated by Auth Analyzer Version " + Version.VERSION + "</html>");
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private String encodeHTML(String text) {
		return text.replaceAll("<", "&lt;").replace("\n", "<br>");
	}
	
	private String setIntoCDATA(String text) {
		return "<![CDATA["+text.replace("]]>", "]]><![CDATA[")+"]]>";
	}
	
	private String getCellValue(MainColumn column, Integer id, IRequestInfo requestInfo,
			IHttpRequestResponse requestResponse) {

		switch (column) {
		case ID:
			return String.valueOf(id);
		case METHOD:
			return requestInfo.getMethod();
		case HOST:
			return requestResponse.getHttpService().getHost();
		case PATH:
			if (requestInfo.getUrl().getQuery() == null) {
				return requestInfo.getUrl().getPath();
			} else {
				return requestInfo.getUrl().getPath() + "?" + requestInfo.getUrl().getQuery();
			}
		default:
			return null;
		}
	}

	private String getCellValue(SessionColumn column, Integer id, IResponseInfo responseInfo,
			IHttpRequestResponse requestResponse, BypassConstants bypassStatus) {

		switch (column) {
		case BYPASS_STATUS:
			return bypassStatus.toString();
		case REQUEST:
			return new String(requestResponse.getRequest());
		case RESPONSE:
			return new String(requestResponse.getResponse());
		case STATUS_CODE:
			return String.valueOf(responseInfo.getStatusCode());
		case CONTENT_LENGTH:
			return String.valueOf(requestResponse.getResponse().length - responseInfo.getBodyOffset());
		default:
			return null;
		}
	}

	public enum MainColumn {

		ID("ID"), METHOD("Method"), HOST("Host"), PATH("Path");

		private final String name;

		public String getName() {
			return this.name;
		}

		private MainColumn(String name) {
			this.name = name;
		}
	}

	public enum SessionColumn {

		BYPASS_STATUS("Bypass Status"), STATUS_CODE("Status Code"), 
		CONTENT_LENGTH("Content Length"), REQUEST("Request"), RESPONSE("Response");

		private String name;

		// getter method
		public String getName() {
			return this.name;
		}

		private SessionColumn(String name) {
			this.name = name;
		}
	}
}