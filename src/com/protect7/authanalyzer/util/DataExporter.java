package com.protect7.authanalyzer.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Base64;
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

	public boolean createXML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns,
			boolean doBase64Encode) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?><Content>");

			// Write Body
			for (OriginalRequestResponse requestResponse : originalRequestResponseList) {
				writer.write("<Message>");
				IHttpRequestResponse originalRequestResponse = requestResponse.getRequestResponse();
				StringBuffer row = new StringBuffer();
				IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers()
						.analyzeRequest(originalRequestResponse);
				for (MainColumn column : mainColumns) {
					row.append("<"
							+ column.getName().replace(" ", "_") + ">" + setIntoCDATA(getCellValue(column,
									requestResponse.getId(), originalRequestInfo, originalRequestResponse, requestResponse.getComment()))
							+ "</" + column.getName().replace(" ", "_") + ">\n");
				}
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						String data;
						if ((column == SessionColumn.REQUEST || column == SessionColumn.RESPONSE) && doBase64Encode) {
							data = Base64.getEncoder().encodeToString(getCellValue(column, requestResponse.getId(),
									originalRequestResponse, null).getBytes());
						} else {
							data = setIntoCDATA(getCellValue(column, requestResponse.getId(),
									originalRequestResponse, null));
						}
						row.append("<Original_" + column.getName().replace(" ", "_") + ">" + data + "</Original_"
								+ column.getName().replace(" ", "_") + ">\n");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap()
							.get(requestResponse.getId());
					for (SessionColumn column : sessionColumns) {
						String data;
						if ((column == SessionColumn.REQUEST || column == SessionColumn.RESPONSE) && doBase64Encode) {
							data = Base64.getEncoder()
									.encodeToString(setIntoCDATA(getCellValue(column, requestResponse.getId(),
											sessionRequestResponse.getRequestResponse(),
											sessionRequestResponse.getStatus())).getBytes());
						} else {
							data = setIntoCDATA(getCellValue(column, requestResponse.getId(),
									sessionRequestResponse.getRequestResponse(), sessionRequestResponse.getStatus()));
						}
						row.append("<" + session.getName().replace(" ", "_") + "_" + column.getName().replace(" ", "_")
								+ ">" + data + "</" + session.getName().replace(" ", "_") + "_"
								+ column.getName().replace(" ", "_") + ">\n");
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</Message>\n");
			}
			writer.write("</Content>");
			writer.close();
		} catch (IOException e) {
			BurpExtender.callbacks.printError("Error. Can not write data to XML file. " + e.getMessage());
			return false;
		}
		return true;
	}

	public boolean createHTML(File file, ArrayList<OriginalRequestResponse> originalRequestResponseList,
			ArrayList<Session> sessions, EnumSet<MainColumn> mainColumns, EnumSet<SessionColumn> sessionColumns) {
		try {
			FileWriter writer = new FileWriter(file);
			writer.write("<html><style>\r\n" + "table{table-layout:auto;width:100%;font-family: Arial, sans-serif;}\r\n"
					+ "th{padding-top:12px;padding-bottom:12px;text-align:left;background-color:#747272;color:white;}\r\n"
					+ "tr:nth-child(even){background-color:#f2f2f2;}td,th{border:1px solid #ddd;padding:8px;}\r\n"
					+ "div{max-width:600px;max-height:300px;overflow-y:auto;word-wrap:break-word;}\r\n"
					+ "</style><table><tr>");
			// Write Title
			StringBuffer titleRow = new StringBuffer();
			for (MainColumn column : mainColumns) {
				titleRow.append("<th>" + encodeHTML(column.getName()) + "</th>");
			}
			for (SessionColumn column : sessionColumns) {
				if (column != SessionColumn.BYPASS_STATUS) {
					titleRow.append("<th>" + encodeHTML("Original " + column.getName()) + "</th>");
				}
			}
			for (Session session : sessions) {
				for (SessionColumn column : sessionColumns) {
					titleRow.append("<th>" + encodeHTML(session.getName() + " " + column.getName()) + "</th>");
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
				IRequestInfo originalRequestInfo = null;
				if(originalRequestResponse != null) {
					originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequestResponse);
				}
				for (MainColumn column : mainColumns) {
					row.append("<td><div>" + encodeHTML(
							getCellValue(column, requestResponse.getId(), originalRequestInfo, originalRequestResponse, requestResponse.getComment()))
							+ "</div></td>");
				}
				for (SessionColumn column : sessionColumns) {
					if (column != SessionColumn.BYPASS_STATUS) {
						row.append("<td><div>" + encodeHTML(getCellValue(column, requestResponse.getId(),
								originalRequestResponse, null)) + "</div></td>");
					}
				}
				for (Session session : sessions) {
					AnalyzerRequestResponse sessionRequestResponse = session.getRequestResponseMap()
							.get(requestResponse.getId());
					for (SessionColumn column : sessionColumns) {
						String startTag = "<td><div class='message'>" ;
						String cellValue = getCellValue(column, requestResponse.getId(),
								sessionRequestResponse.getRequestResponse(),
								sessionRequestResponse.getStatus());
						String endTag = "</div></td>";
						if(column == SessionColumn.BYPASS_STATUS) {
							if(cellValue.equals(BypassConstants.SAME.getName())) {
								startTag = "<td style='background-color: rgba(255, 0, 0, 0.3)'><div class='message'>" ;
							}
							if(cellValue.equals(BypassConstants.SIMILAR.getName())) {
								startTag = "<td style='background-color:rgba(255, 165, 0, 0.3)'><div class='message'>" ;
							}
							if(cellValue.equals(BypassConstants.DIFFERENT.getName())) {
								startTag = "<td style='background-color:rgba(0, 255, 0, 0.3)'><div class='message'>" ;
							}
						}
						row.append(startTag + encodeHTML(cellValue) + endTag);
					}
				}
				row.deleteCharAt(row.length() - 1);
				writer.write(row.toString());
				writer.write("</tr>\n");
			}
			writer.write("</table><br>Generated by "+ Globals.EXTENSION_NAME +" Version " + Globals.VERSION + "</html>");
			writer.close();
		} catch (IOException e) {
			BurpExtender.callbacks.printError("Error. Can not write data to HTML file. " + e.getMessage());
			return false;
		}
		return true;
	}

	private String encodeHTML(String text) {
		return text.replaceAll("<", "&lt;").replace("\n", "<br>");
	}

	private String setIntoCDATA(String text) {
		return "<![CDATA[" + text.replace("]]>", "]]><![CDATA[") + "]]>";
	}

	private String getCellValue(MainColumn column, Integer id, IRequestInfo requestInfo,
			IHttpRequestResponse requestResponse, String comment) {
		switch (column) {
		case ID:
			return String.valueOf(id);
		case METHOD:
			return requestInfo.getMethod();
		case COMMENT:
			return comment;
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

	private String getCellValue(SessionColumn column, Integer id,
			IHttpRequestResponse requestResponse, BypassConstants bypassStatus) {
		IResponseInfo responseInfo = null;
		if(requestResponse != null && requestResponse.getResponse() != null) {
			responseInfo = BurpExtender.callbacks.getHelpers()
					.analyzeResponse(requestResponse.getResponse());
		}
		switch (column) {
		case BYPASS_STATUS:
			return bypassStatus.getName();
		case REQUEST:
			if(requestResponse != null && requestResponse.getRequest() != null) {
				return new String(requestResponse.getRequest());
			}
			else {
				return "";
			}
		case RESPONSE:
			if(requestResponse != null  && requestResponse.getResponse() != null) {
				return new String(requestResponse.getResponse());
			}
			else {
				return "";
			}
		case STATUS_CODE:
			if(responseInfo != null) {
				return String.valueOf(responseInfo.getStatusCode());
			}
			else {
				return "-1";
			}
		case CONTENT_LENGTH:
			if(responseInfo != null && requestResponse.getResponse() != null) {
				return String.valueOf(requestResponse.getResponse().length - responseInfo.getBodyOffset());
			}
			else {
				return "-1";
			}
		default:
			return null;
		}
	}

	public enum MainColumn {

		ID("ID"), METHOD("Method"), HOST("Host"), PATH("Path"), COMMENT("Comment");

		private final String name;

		public String getName() {
			return this.name;
		}

		private MainColumn(String name) {
			this.name = name;
		}
	}

	public enum SessionColumn {

		BYPASS_STATUS("Bypass Status"), STATUS_CODE("Status Code"), CONTENT_LENGTH("Content Length"),
		REQUEST("Request"), RESPONSE("Response");

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