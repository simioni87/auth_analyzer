package com.protect7.authanalyzer.controller;

/**
 * The RequestController processes each HTTP message which is not previously rejected due to filter specification. The RequestController
 * extracts the defined values (CSRF Token and Grep Rules) and modifies the given HTTP Message for each session. Furthermore, the
 * RequestController is responsible for analyzing the response and declare the BYPASS status according to the specified definitions.
 * 
 * @author Simon Reinhart
 */

import java.net.URL;
import java.util.Arrays;
import java.util.List;
import com.protect7.authanalyzer.entities.AnalyzerRequestResponse;
import com.protect7.authanalyzer.entities.OriginalRequestResponse;
import com.protect7.authanalyzer.entities.Session;
import com.protect7.authanalyzer.entities.Token;
import com.protect7.authanalyzer.entities.TokenPriority;
import com.protect7.authanalyzer.util.BypassConstants;
import com.protect7.authanalyzer.util.CurrentConfig;
import com.protect7.authanalyzer.util.ExtractionHelper;
import com.protect7.authanalyzer.util.GenericHelper;
import com.protect7.authanalyzer.util.RequestModifHelper;
import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IRequestInfo;
import burp.IResponseInfo;

public class RequestController {

	public void analyze(IHttpRequestResponse originalRequestResponse) {
		
		// Fail-Safe - Check if messageInfo can be processed
		if (originalRequestResponse == null || originalRequestResponse.getRequest() == null) {
			BurpExtender.callbacks.printError("Cannot analyze request with null values.");
		} else {
			int mapId = CurrentConfig.getCurrentConfig().getNextMapId();
			IRequestInfo originalRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(originalRequestResponse);
			IResponseInfo originalResponseInfo = null;
			if(originalRequestResponse.getResponse() != null) {
				originalResponseInfo = BurpExtender.callbacks.getHelpers()
				.analyzeResponse(originalRequestResponse.getResponse());
			}
			for (Session session : CurrentConfig.getCurrentConfig().getSessions()) {
				boolean isFiltered = false;
				if(!session.getStatusPanel().isRunning()) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to paused session.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				}
				else if (session.isFilterRequestsWithSameHeader()
						&& isSameHeader(originalRequestInfo.getHeaders(), session)) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to same header.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				} 
				else if(session.isRestrictToScope() && !scopeMatches(originalRequestInfo.getUrl(), session)) {
					AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
							null, BypassConstants.NA, "Filtered due to scope restriction.", -1, -1);
					session.putRequestResponse(mapId, analyzerRequestResponse);
					session.getStatusPanel().incrementAmountOfFitleredRequests();
					isFiltered = true;
				} 
				if(!isFiltered) {
				
					// Handle Session
					TokenPriority tokenPriority = new TokenPriority();
					byte[] modifiedRequest = RequestModifHelper.getModifiedRequest(originalRequestResponse.getRequest(), session, tokenPriority);
					// Analyze modifiedRequest
					IRequestInfo modifiedRequestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(modifiedRequest);
					byte[] modifiedMessageBody = Arrays.copyOfRange(modifiedRequest,
							modifiedRequestInfo.getBodyOffset(), modifiedRequest.length);

					List<String> modifiedHeaders = RequestModifHelper.getModifiedHeaders(modifiedRequestInfo.getHeaders(), session);
					byte[] message = BurpExtender.callbacks.getHelpers().buildHttpMessage(modifiedHeaders, modifiedMessageBody);

					// Perform modified request
					IHttpRequestResponse sessionRequestResponse = BurpExtender.callbacks
							.makeHttpRequest(originalRequestResponse.getHttpService(), message);
				
					// Analyze Response of modified Request
					if (sessionRequestResponse.getRequest() != null && sessionRequestResponse.getResponse() != null) {
						IResponseInfo sessionResponseInfo = BurpExtender.callbacks.getHelpers()
								.analyzeResponse(sessionRequestResponse.getResponse());
						// Extract Token Values if applicable
						for (Token token : session.getTokens()) {
							boolean success = false;
							if (token.isAutoExtract()) {
								success = ExtractionHelper.extractCurrentTokenValue(sessionRequestResponse.getResponse(), sessionResponseInfo, token);
							}
							if (token.isFromToString()) {
								success = ExtractionHelper.extractTokenWithFromToString(sessionRequestResponse.getResponse(), sessionResponseInfo, token);
							}
							if(success) {
								session.getStatusPanel().updateTokenStatus(token);
								// Token value successfully extracted. Set TokenRequestResponse for renew feature.
								if(token.getRequestResponse() == null || token.getPriority() <= tokenPriority.getPriority()) {
									token.setRequestResponse(sessionRequestResponse);
									token.setPriority(tokenPriority.getPriority());
								}
							}
						}
						if(originalRequestResponse.getResponse() != null) {
							BypassConstants bypassConstant = analyzeResponse(originalRequestResponse.getResponse(),
									sessionRequestResponse.getResponse(), originalResponseInfo, sessionResponseInfo);
							AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
									sessionRequestResponse, bypassConstant, null, sessionResponseInfo.getStatusCode(),
									sessionRequestResponse.getResponse().length - sessionResponseInfo.getBodyOffset());
							session.putRequestResponse(mapId, analyzerRequestResponse);
						}
						else {
							AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
									sessionRequestResponse, BypassConstants.NA, null, sessionResponseInfo.getStatusCode(),
									sessionRequestResponse.getResponse().length - sessionResponseInfo.getBodyOffset());
							session.putRequestResponse(mapId, analyzerRequestResponse);
						}
					} else {
						AnalyzerRequestResponse analyzerRequestResponse = new AnalyzerRequestResponse(
								null, BypassConstants.NA, "Session Request / Response is null. Probably no response "
										+ "received from server.", -1, -1);
						session.putRequestResponse(mapId, analyzerRequestResponse);
					}
				}
			}
			String url = "";
			if(originalRequestInfo.getUrl().getQuery() == null) {
				url = originalRequestInfo.getUrl().getPath();
			}
			else {
				url = originalRequestInfo.getUrl().getPath() + "?" + originalRequestInfo.getUrl().getQuery();
			}
			String infoText = null;
			if(originalRequestResponse.getResponse() == null) {
				infoText = "Request Dropped. No Response to show.";
			}
			int originalStatusCode = -1;
			int originalResponseContentLength = -1;
			if(originalResponseInfo != null) {
				originalStatusCode = originalResponseInfo.getStatusCode();
				originalResponseContentLength = originalRequestResponse.getResponse().length - originalResponseInfo.getBodyOffset();
			}
			OriginalRequestResponse requestResponse = new OriginalRequestResponse(mapId, originalRequestResponse, 
					originalRequestInfo.getMethod(), url, infoText, originalStatusCode, originalResponseContentLength);
			CurrentConfig.getCurrentConfig().getTableModel().addNewRequestResponse(requestResponse);		
			GenericHelper.animateBurpExtensionTab();
		}
	}
	
	private boolean scopeMatches(URL url, Session session) {
		URL scopeUrl = session.getScopeUrl();
		if(scopeUrl != null) {
			if(url.getHost().equals(scopeUrl.getHost()) && url.getProtocol().equals(scopeUrl.getProtocol()) &&
					(url.getPath().equals(scopeUrl.getPath()) || scopeUrl.getPath().equals("") || scopeUrl.getPath().equals("/"))) {
				return true;
			}
		}
		return false;
	}

	public boolean isSameHeader(List<String> headers, Session session) {
		String[] headersToReplace = session.getHeadersToReplace().split("\n");
		for (String headerToReplace : headersToReplace) {
			if (!headers.contains(headerToReplace)) {
				return false;
			}
		}
		return true;
	}


	/*
	 * Bypass if: - Both Responses have same Response Body and Status Code
	 * 
	 * Potential Bypass if: - Both Responses have same Response Code - Both
	 * Responses have +-5% of response body length
	 *
	 */
	public BypassConstants analyzeResponse(byte[] originalResponse, byte[] sessionResponse,
			IResponseInfo originalResponseInfo, IResponseInfo sessionResponseInfo) {
		byte[] originalResponseBody = Arrays.copyOfRange(originalResponse, originalResponseInfo.getBodyOffset(),
				originalResponse.length);
		byte[] sessionResponseBody = Arrays.copyOfRange(sessionResponse, sessionResponseInfo.getBodyOffset(),
				sessionResponse.length);
		if (Arrays.equals(originalResponseBody, sessionResponseBody)
				&& (originalResponseInfo.getStatusCode() == sessionResponseInfo.getStatusCode() || !CurrentConfig.getCurrentConfig().isRespectResponseCodeForSameStatus())) {
			return BypassConstants.SAME;
		}
		if (originalResponseInfo.getStatusCode() == sessionResponseInfo.getStatusCode() || !CurrentConfig.getCurrentConfig().isRespectResponseCodeForSimilarStatus()) {
			int range = originalResponseBody.length / (100/CurrentConfig.getCurrentConfig().getDerivationForSimilarStatus());
			int difference = originalResponseBody.length - sessionResponseBody.length;
			// Check if difference is in range
			if (difference <= range && difference >= -range) {
				return BypassConstants.SIMILAR;
			}
		}
		return BypassConstants.DIFFERENT;
	}
}
