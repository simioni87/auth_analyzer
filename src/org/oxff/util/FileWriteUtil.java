package org.oxff.util;

import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;

public class FileWriteUtil {
    /**
     * 将大字符串分块写入到文件中
     *
     * @param data 要写入的字符串
     * @param filePath 目标文件的路径
     * @param chunkSize 每个写入块的大小（字符数）
     * @throws IOException 如果发生IO异常
     */
    public static void writeLargeStringToFile(String data, String filePath, int chunkSize) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            int length = data.length();
            for (int start = 0; start < length; start += chunkSize) {
                int end = Math.min(start + chunkSize, length);
                writer.write(data, start, end - start);
            }
        }
    }

    /**
     * 将字符串写入到指定的文件中
     *
     * @param data 要写入的字符串
     * @param filePath 目标文件的路径
     * @throws IOException 如果发生IO异常
     */
    public static void writeStringToFile(String data, String filePath) throws IOException {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            writer.write(data);
        }
    }
}
