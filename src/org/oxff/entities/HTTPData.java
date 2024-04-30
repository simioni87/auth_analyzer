package org.oxff.entities;


import burp.IHttpRequestResponse;
import org.oxff.util.HttpMessageUtil;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Locale;

@SuppressWarnings("unused")
public class HTTPData {

    // request data
    private String requestHeaders;
    private String requestBody;
    private Boolean  isRequestBodyBase64Encoded;

    private int requestContentLength;

    // response data
    private String responseHeaders;
    private String responseBody;
    private  Boolean isResponseBodyBase64Encoded;
    private int responseContentLength;

    private int responseStatusCode;



    public HTTPData(IHttpRequestResponse httpRequestResponse, List<String> requestHeaderList, byte[] requestBodyBytes, int requestContentLength,
                    List<String> responseHeaderList, byte[] responseBodyBytes,
                    int responseStatusCode) {
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
            this.isRequestBodyBase64Encoded = true;
        } else {
            // Text data, convert bodyBytes to string with proper encoding
            this.requestBody = new String(requestBodyBytes, StandardCharsets.UTF_8);
            this.isRequestBodyBase64Encoded = false;
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
            this.isResponseBodyBase64Encoded = true;
        }else{
            // Text data, convert bodyBytes to string with proper encoding
            this.responseBody =  new String(responseBodyBytes, StandardCharsets.UTF_8);
            this.isResponseBodyBase64Encoded = false;
        }

        this.responseContentLength =  responseBodyBytes.length;
        this.responseStatusCode = responseStatusCode;
    }

    @SuppressWarnings("SameParameterValue")
    private String getHeaderValue(List<String> headerList, String headerName) {
        for (String header : headerList) {
            if (header.toLowerCase(Locale.ROOT).startsWith(headerName.toLowerCase(Locale.ROOT) + ":")) {
                return header.substring(headerName.length() + 1).trim();
            }
        }
        return null;
    }

    // getter and setter method
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

    public int getResponseStatusCode() {
        return responseStatusCode;
    }

    public void setResponseStatusCode(int responseStatusCode) {
        this.responseStatusCode = responseStatusCode;
    }

    @SuppressWarnings("unused")
    public int getRequestContentLength() {
        return requestContentLength;
    }

    @SuppressWarnings("unused")
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

    public Boolean getRequestBodyBase64Encoded() {
        return isRequestBodyBase64Encoded;
    }

    public void setRequestBodyBase64Encoded(Boolean requestBodyBase64Encoded) {
        isRequestBodyBase64Encoded = requestBodyBase64Encoded;
    }

    public Boolean getResponseBodyBase64Encoded() {
        return isResponseBodyBase64Encoded;
    }

    public void setResponseBodyBase64Encoded(Boolean responseBodyBase64Encoded) {
        isResponseBodyBase64Encoded = responseBodyBase64Encoded;
    }
}
