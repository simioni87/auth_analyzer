package org.oxff.util;

import burp.*;
import org.apache.tika.Tika;

import java.io.ByteArrayOutputStream;

@SuppressWarnings("ALL")
public class HttpMessageUtil {

    public static boolean requestContainsFile(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || httpRequestResponse.getRequest() == null) {
            return false;
        }

        IRequestInfo requestInfo = BurpExtender.helpers.analyzeRequest(httpRequestResponse);
        byte[] requestBytes = httpRequestResponse.getRequest();
        String contentTypeHeader = getHeaderValue(requestInfo.getHeaders(), "Content-Type");
        String transferEncodingHeader = getHeaderValue(requestInfo.getHeaders(), "Transfer-Encoding");

        if (contentTypeHeader != null && contentTypeHeader.toLowerCase().contains("multipart/form-data")) {

            byte[] pattern = "filename=\"".getBytes();
            return optimizedSearch(requestBytes, pattern);
        }
        // 2. Binary data in POST Body
        if (contentTypeHeader != null && contentTypeHeader.toLowerCase().contains("application/octet-stream")) {
            // Implement specific logic to check for binary data
            return checkForBinaryData(requestBytes);
        }

        // 4. URL Parameters
        if (requestInfo.getMethod().equals("GET") && requestInfo.getUrl().getQuery() != null) {
            return true; // This assumes files could be transferred via URL parameters
        }

        // 5. Chunked Transfer Encoding
        if (transferEncodingHeader != null && transferEncodingHeader.equalsIgnoreCase("chunked")) {
            // Implement logic to handle chunked transfer encoding
            return checkForChunkedData(requestBytes);
        }

        return false;
    }

    private static boolean checkForBinaryData(byte[] requestBytes) {
        // 使用 Tika 检测 MIME 类型
        Tika tika = new Tika();
        String detectedType = tika.detect(requestBytes);
        // 检测到的类型不是纯文本，则可能包含文件
        return !detectedType.equals("text/plain");
    }

    private static boolean checkForChunkedData(byte[] data) {
        // 由于分块数据需要首先重新组装，这里仅提供一个框架
        byte[] combinedData = reassembleChunkedData(data);
        if (combinedData != null) {
            return checkForBinaryData(combinedData);
        }
        return false;
    }

    private static byte[] reassembleChunkedData(byte[] data) {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        int index = 0;

        while (index < data.length) {
            int nextNewlineIndex = indexOf(data, "\r\n", index);
            if (nextNewlineIndex == -1) {
                break; // 没有找到新的行，退出循环
            }

            String chunkSizeLine = new String(data, index, nextNewlineIndex - index);
            int chunkSize;
            try {
                chunkSize = Integer.parseInt(chunkSizeLine.trim(), 16);
            } catch (NumberFormatException e) {
                break; // 无效的块大小，退出循环
            }

            if (chunkSize == 0) {
                break; // 最后一个块，结束处理
            }

            index = nextNewlineIndex + 2; // 跳过 \r\n
            int chunkEnd = index + chunkSize;
            if (chunkEnd > data.length) {
                break; // 数据不完整，退出循环
            }

            outputStream.write(data, index, chunkSize);
            index = chunkEnd + 2; // 跳过块末尾的 \r\n
        }

        return outputStream.toByteArray();
    }

    private static int indexOf(byte[] data, String pattern, int start) {
        byte[] patternBytes = pattern.getBytes();
        outerLoop:
        for (int i = start; i < data.length - patternBytes.length + 1; i++) {
            for (int j = 0; j < patternBytes.length; j++) {
                if (data[i + j] != patternBytes[j]) {
                    continue outerLoop;
                }
            }
            return i;
        }
        return -1;
    }

    private static boolean optimizedSearch(byte[] array, byte[] pattern) {
        if (shouldUseLinearSearch(array, pattern)) {
            return linearSearch(array, pattern);
        } else if (shouldUseKMP(array, pattern)) {
            return kmpSearch(array, pattern);
        } else {
            // 这里可以添加更多的算法选择逻辑，例如 Boyer-Moore 算法
            return linearSearch(array, pattern); // 默认回退到线性搜索
        }
    }

    private static boolean shouldUseLinearSearch(byte[] array, byte[] pattern) {
        return array.length < 1000 && pattern.length < 10;
    }

    private static boolean shouldUseKMP(byte[] array, byte[] pattern) {
        return pattern.length > 20 || array.length > 10000;
    }

    private static boolean linearSearch(byte[] array, byte[] pattern) {
        for (int i = 0; i <= array.length - pattern.length; i++) {
            boolean found = true;
            for (int j = 0; j < pattern.length; j++) {
                if (array[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return true;
        }
        return false;
    }

    private static boolean kmpSearch(byte[] array, byte[] pattern) {
        int[] lps = computeLPSArray(pattern);
        int i = 0;
        int j = 0;

        while (i < array.length) {
            if (pattern[j] == array[i]) {
                j++;
                i++;
            }
            if (j == pattern.length) {
                return true;
            } else if (i < array.length && pattern[j] != array[i]) {
                if (j != 0) {
                    j = lps[j - 1];
                } else {
                    i = i + 1;
                }
            }
        }
        return false;
    }

    private static int[] computeLPSArray(byte[] pattern) {
        int[] lps = new int[pattern.length];
        int len = 0;
        int i = 1;
        lps[0] = 0;

        while (i < pattern.length) {
            if (pattern[i] == pattern[len]) {
                len++;
                lps[i] = len;
                i++;
            } else {
                if (len != 0) {
                    len = lps[len - 1];
                } else {
                    lps[i] = len;
                    i++;
                }
            }
        }
        return lps;
    }

    public static boolean responseContainsFile(IHttpRequestResponse httpRequestResponse) {
        if (httpRequestResponse == null || httpRequestResponse.getResponse() == null) {
            return false;
        }

        IResponseInfo responseInfo = BurpExtender.helpers.analyzeResponse(httpRequestResponse.getResponse());
        String contentDispositionHeader = getHeaderValue(responseInfo.getHeaders(), "Content-Disposition");

        return contentDispositionHeader != null && contentDispositionHeader.toLowerCase().contains("attachment");
    }

    private static String getHeaderValue(java.util.List<String> headers, String headerName) {
        for (String header : headers) {
            if (header.toLowerCase().startsWith(headerName.toLowerCase())) {
                return header.substring(header.indexOf(':') + 1).trim();
            }
        }
        return null;
    }

    public static String encodeHTML(String text) {
        return text.replaceAll("<", "&lt;").replace("\n", "<br>");
    }
}