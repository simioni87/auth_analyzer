package org.oxff.entities;

import burp.IHttpRequestResponse;
import org.oxff.util.HttpMessageUtil;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

public class ExportAuthAnalyzerDataItem {
    private int id;
    private String method;
    private String host;
    private int port;
    private String path;

    private String requestHeaders;

    private int requestContentLength;

    private String requestBody;
    private Boolean  requestBodyIsBase64;


    // response data

    private String responseHeaders;
    private int responseContentLength;
    private String responseBody;
    private Boolean  responseBodyIsBase64;
    private int responseStatusCode;

    private String comment;

//    private HTTPData rawHTTPData;

    private List<SessionHTTPData> sessionHTTPDataList;

    public ExportAuthAnalyzerDataItem(){

    }

    public ExportAuthAnalyzerDataItem(IHttpRequestResponse rawHttpRequestResponse, int id, String method, String host, int port, String path,
                                      List<String> requestHeaderList, byte[] requestBodyBytes,
                                      int requestContentLength,
                                      List<String> responseHeaderList, byte[] responseBodyBytes,
                                      int responseContentLength, int responseStatusCode,
                                      String comment) {
        this.id = id;
        this.method = method;
        this.host = host;
        this.path = path;
//        this.rawHTTPData = rawHTTPData;
        this.port = port;
        this.comment = comment;


        // write data from headerList to headers
        StringBuilder requestHeadersSb = new StringBuilder();
        for (String header : requestHeaderList) {
            requestHeadersSb.append(header);
            requestHeadersSb.append("\n");
        }
        this.requestHeaders = requestHeadersSb.toString();

        // Check if Content-Type header exists and indicates binary data
        String requestContentTypeHeader = getHeaderValue(requestHeaderList, "Content-Type");
        if (HttpMessageUtil.requestContainsFile(rawHttpRequestResponse)) {
            // Binary data, encode bodyBytes using Base64
            this.requestBody = Base64.getEncoder().encodeToString(requestBodyBytes);
            requestBodyIsBase64 = true;
        } else {
            // Text data, convert bodyBytes to string with proper encoding
            this.requestBody = new String(requestBodyBytes, determineCharset(requestHeaderList));
            requestBodyIsBase64 = false;
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
        String responseContentTypeHeader = getHeaderValue(responseHeaderList, "Content-Type");
        if (HttpMessageUtil.responseContainsFile(rawHttpRequestResponse)) {
            this.responseBody = Base64.getEncoder().encodeToString(responseBodyBytes);
            responseBodyIsBase64 = true;
        }else{
            // Text data, convert bodyBytes to string with proper encoding
            this.responseBody = new String(responseBodyBytes, determineCharset(responseHeaderList));
            responseBodyIsBase64 = false;
        }

        this.responseContentLength =  responseBodyBytes.length;
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

    private Charset determineCharset(List<String> headerList) {
        // Try to detect the charset based on the Content-Type header
        String contentTypeHeader = getHeaderValue(headerList, "Content-Type");
        if (contentTypeHeader != null) {
            String[] parts = contentTypeHeader.split(";");
            for (String part : parts) {
                if (part.trim().toLowerCase(Locale.ROOT).startsWith("charset=")) {
                    String charsetName = part.trim().substring(8);
                    try {
                        return Charset.forName(charsetName);
                    } catch (IllegalArgumentException e) {
                        // Invalid charset name, continue to next part
                    }
                }
            }
        }

        // Fallback to default charset if charset is not specified or invalid
        return StandardCharsets.UTF_8;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getHost() {
        return host;
    }

    public void setHost(String host) {
        this.host = host;
    }

    public int getPort() {
        return port;
    }

    public void setPort(int port) {
        this.port = port;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getRequestHeaders() {
        return requestHeaders;
    }

    public void setRequestHeaders(List<String> requestHeaderList) {
        StringBuilder requestHeadersSb = new StringBuilder();
        for (String header : requestHeaderList) {
            requestHeadersSb.append(header);
            requestHeadersSb.append("\n");
        }
        this.requestHeaders = requestHeadersSb.toString();
    }

    public int getRequestContentLength() {
        return requestContentLength;
    }

    public void setRequestContentLength(int requestContentLength) {
        this.requestContentLength = requestContentLength;
    }

    public String getRequestBody() {
        return requestBody;
    }

    public void setRequestBody(String requestBody) {
        this.requestBody = requestBody;
    }

    public String getResponseHeaders() {
        return responseHeaders;
    }

    public void setResponseHeaders(List<String> responseHeaderList) {
        StringBuilder responseHeadersSb = new StringBuilder();
        for (String header : responseHeaderList) {
            responseHeadersSb.append(header);
            responseHeadersSb.append("\n");
        }
        this.responseHeaders = responseHeadersSb.toString();
    }

    public int getResponseContentLength() {
        return responseContentLength;
    }

    public void setResponseContentLength(int responseContentLength) {
        this.responseContentLength = responseContentLength;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public int getResponseStatusCode() {
        return responseStatusCode;
    }

    public void setResponseStatusCode(int responseStatusCode) {
        this.responseStatusCode = responseStatusCode;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public List<SessionHTTPData> getSessionsHTTPDataList() {
        return sessionHTTPDataList;
    }

    public void setSessionsHTTPDataList(List<SessionHTTPData> sessionHTTPData) {
        this.sessionHTTPDataList = sessionHTTPData;
    }

    public void setRequestHeaders(String requestHeaders) {
        this.requestHeaders = requestHeaders;
    }

    public Boolean getRequestBodyIsBase64() {
        return requestBodyIsBase64;
    }

    public void setRequestBodyIsBase64(Boolean requestBodyIsBase64) {
        this.requestBodyIsBase64 = requestBodyIsBase64;
    }

    public void setResponseHeaders(String responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    public Boolean getResponseBodyIsBase64() {
        return responseBodyIsBase64;
    }

    public void setResponseBodyIsBase64(Boolean responseBodyIsBase64) {
        this.responseBodyIsBase64 = responseBodyIsBase64;
    }
}
