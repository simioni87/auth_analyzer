package org.oxff.entities;

import burp.IHttpRequestResponse;
import com.protect7.authanalyzer.util.BypassConstants;
import org.oxff.util.HttpMessageUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@SuppressWarnings({"unused", "SameParameterValue"})
public class SessionHTTPData{
    private String sessionName;

    private String requestHeaders;
    private String requestBody;
    private Boolean requestBodyIsBase64;

    private int requestContentLength;

    // response data
    private String responseHeaders;
    private String responseBody;
    private Boolean responseBodyIsBase64;
    private int responseContentLength;

    private int responseStatusCode;
    private BypassConstants status;

    public SessionHTTPData(IHttpRequestResponse httpRequestResponse, String sessionName, List<String> requestHeaderList, byte[] requestBodyBytes, int requestContentLength,
                           List<String> responseHeaderList, byte[] responseBodyBytes, int responseContentLength,
                           int responseStatusCode, BypassConstants status) {
        this.sessionName = sessionName;
        this.status = status;

        // write data from headerList to headers
        StringBuilder requestHeadersSb = new StringBuilder();
        for (String header : requestHeaderList) {
            requestHeadersSb.append(header);
            requestHeadersSb.append("\n");
        }
        this.requestHeaders = requestHeadersSb.toString();

        // Check if Content-Type header exists and indicates binary data

        if (HttpMessageUtil.requestContainsFile(httpRequestResponse)) {
            // Binary data, encode bodyBytes using Base64
            this.requestBody = Base64.getEncoder().encodeToString(requestBodyBytes);
            this.requestBodyIsBase64 = true;
        } else {
            // Text data, convert bodyBytes to string with proper encoding
            this.requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
            this.requestBodyIsBase64 = false;
        }

        this.requestContentLength = requestContentLength;


        // write response data to responseHeaders and responseBody
        StringBuilder responseHeadersSb = new StringBuilder();
        for (String header : responseHeaderList) {
            responseHeadersSb.append(header);
            responseHeadersSb.append("\n");
        }
        this.responseHeaders = responseHeadersSb.toString();

        // Check if Content-Type header exists and indicates binary data
        if (HttpMessageUtil.responseContainsFile(httpRequestResponse)) {
            this.responseBody = Base64.getEncoder().encodeToString(responseBodyBytes);
            this.responseBodyIsBase64 = true;
        }else{
            // Text data, convert bodyBytes to string with proper encoding
            this.responseBody = new String(responseBodyBytes, StandardCharsets.UTF_8);
            this.responseBodyIsBase64 = false;
        }

        this.responseContentLength =  responseContentLength;
        this.responseStatusCode = responseStatusCode;

    }

    private String getHeaderValue(List<String> headerList, String headerName) {
        for (String header : headerList) {
            if (header.toLowerCase(Locale.ROOT).startsWith(headerName.toLowerCase(Locale.ROOT) + ":")) {
                return header.substring(headerName.length() + 1).trim();
            }
        }
        return null;
    }

    public BypassConstants getStatus() {
        return status;
    }

    public void setStatus(BypassConstants status) {
        this.status = status;
    }

    public String getSessionName() {
        return sessionName;
    }

    public void setSessionName(String sessionName) {
        this.sessionName = sessionName;
    }

    public String getRequestHeaders() {
        return requestHeaders;
    }

    public void setRequestHeaders(String requestHeaders) {
        this.requestHeaders = requestHeaders;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }

    public int getRequestContentLength() {
        return requestContentLength;
    }

    public void setRequestContentLength(int requestContentLength) {
        this.requestContentLength = requestContentLength;
    }

    public String getResponseHeaders() {
        return responseHeaders;
    }

    public void setResponseHeaders(String responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public int getResponseContentLength() {
        return responseContentLength;
    }

    public void setResponseContentLength(int responseContentLength) {
        this.responseContentLength = responseContentLength;
    }

    public int getResponseStatusCode() {
        return responseStatusCode;
    }

    public void setResponseStatusCode(int responseStatusCode) {
        this.responseStatusCode = responseStatusCode;
    }

    public Boolean getRequestBodyIsBase64() {
        return requestBodyIsBase64;
    }

    public void setRequestBodyIsBase64(Boolean requestBodyIsBase64) {
        this.requestBodyIsBase64 = requestBodyIsBase64;
    }

    public Boolean getResponseBodyIsBase64() {
        return responseBodyIsBase64;
    }

    public void setResponseBodyIsBase64(Boolean responseBodyIsBase64) {
        this.responseBodyIsBase64 = responseBodyIsBase64;
    }
}
