package org.oxff.util;

import burp.*;
import org.oxff.entities.HTTPData;
import org.oxff.entities.SessionHTTPData;
import com.protect7.authanalyzer.util.BypassConstants;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public class BurpSuiteHTTPDataHelper {
    public static byte[] getRequestBodyBytes(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null){
            return null;
        }
        IRequestInfo requestInfo = BurpExtender.callbacks.getHelpers().analyzeRequest(httpRequestResponse);
        int bodyOffset = requestInfo.getBodyOffset();
        byte[] requestBytes = httpRequestResponse.getRequest();
        if (requestBytes == null){
            return null;
        }
        int requestBodyLength = requestBytes.length - bodyOffset;
        byte[] requestBodyBytes = new byte[requestBodyLength];
        System.arraycopy(requestBytes, bodyOffset, requestBodyBytes, 0, requestBodyLength);
        return requestBodyBytes;
    }

    public static String getRequestBodyString(IHttpRequestResponse httpRequestResponse) {
        byte[] requestBodyBytes = getRequestBodyBytes(httpRequestResponse);
        if (requestBodyBytes == null){
            return null;
        }
        return new String(requestBodyBytes, StandardCharsets.UTF_8);
    }

    public static byte[] getResponseBodyBytes(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse.getResponse() == null || httpRequestResponse.getResponse().length == 0){
            return null;
        }

        byte[] responseBytes = httpRequestResponse.getResponse();
        IResponseInfo responseInfo = BurpExtender.callbacks.getHelpers().analyzeResponse(responseBytes);
        int bodyOffset = responseInfo.getBodyOffset();
        int responseBodyLength = responseBytes.length - bodyOffset;
        byte[] responseBodyBytes = new byte[responseBodyLength];
        System.arraycopy(responseBytes, bodyOffset, responseBodyBytes, 0, responseBodyLength);
        return responseBodyBytes;
    }

    public static String getResponseBodyString(IHttpRequestResponse httpRequestResponse) {
        byte[] responseBodyBytes = getResponseBodyBytes(httpRequestResponse);
        if (responseBodyBytes == null){
            return null;
        }
        return new String(responseBodyBytes, StandardCharsets.UTF_8);
    }

    public static HTTPData createHTTPData(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null){
            return null;
        }

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpRequestResponse);
        if (requestInfo == null){
            return null;
        }
        byte[] requestBodyBytes = getRequestBodyBytes(httpRequestResponse);
        int requestContentLength = requestBodyBytes.length;
        List<String> requestHeaderList = requestInfo.getHeaders();

        byte[] responseBytes = httpRequestResponse.getResponse();

        List<String> responseHeaderList = null;
        byte[] responseBodyBytes = null;
        int responseContentLength = -1;
        int responseStatusCode = -1;

        if (responseBytes == null ||  responseBytes.length == 0){
            responseHeaderList = new ArrayList<>();
            responseBodyBytes = new byte[0];
            responseContentLength =  0;
        }else{
            IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(responseBytes);
            if (responseInfo == null){
                responseHeaderList = new ArrayList<>();
                responseBodyBytes = new byte[0];
                responseContentLength =  0;
            }else{
                responseHeaderList = responseInfo.getHeaders();
                responseStatusCode = responseInfo.getStatusCode();
                responseBodyBytes = getResponseBodyBytes(httpRequestResponse);
                if (responseBodyBytes == null){
                    responseBodyBytes = new byte[0];
                    responseContentLength = 0;
                }else{
                    responseContentLength = responseBodyBytes.length;
                }
            }
        }

        HTTPData httpData = new HTTPData(httpRequestResponse,requestHeaderList,  requestBodyBytes, requestContentLength,
                responseHeaderList, responseBodyBytes, responseContentLength);

        return httpData;
    }

    public static SessionHTTPData createSessionsHTTPData(String sessionName, IHttpRequestResponse httpRequestResponse, BypassConstants status){
        if (httpRequestResponse == null){
            return null;
        }

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpRequestResponse);
        if (requestInfo == null){
            return null;
        }
        byte[] requestBodyBytes = getRequestBodyBytes(httpRequestResponse);
        int requestContentLength = requestBodyBytes.length;
        List<String> requestHeaderList = requestInfo.getHeaders();


        byte[] responseBytes = httpRequestResponse.getResponse();

        List<String> responseHeaderList = null;
        byte[] responseBodyBytes = null;
        int responseContentLength = -1;
        int responseStatusCode = -1;

        if (responseBytes == null){
            requestHeaderList = new ArrayList<>();
            responseBodyBytes = new byte[0];
            responseContentLength =  0;
            responseStatusCode = 0;
        }else{
            IResponseInfo responseInfo  = BurpExtender.helpers.analyzeResponse(responseBytes);
            responseHeaderList = responseInfo.getHeaders();
            responseStatusCode = responseInfo.getStatusCode();
            responseBodyBytes = getResponseBodyBytes(httpRequestResponse);
            if (responseBodyBytes == null){
                responseBodyBytes = new byte[0];
                responseContentLength = 0;
            }else{
                responseContentLength = responseBodyBytes.length;
            }
        }

        SessionHTTPData sessionHTTPData = new SessionHTTPData(httpRequestResponse, sessionName, requestHeaderList,  requestBodyBytes, requestContentLength,
                responseHeaderList, responseBodyBytes, responseContentLength, responseStatusCode, status);

        return sessionHTTPData;

    }
}
