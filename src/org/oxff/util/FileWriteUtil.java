package org.oxff.util;

import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

public class FileWriteUtil {
    /**
     * 将大字符串分块写入文件。
     * 该方法用于处理大型字符串，避免一次性加载整个字符串到内存中导致的内存溢出问题。
     * 通过将字符串分块写入，可以有效地减少内存使用，提高程序的稳定性和性能。
     *
     * @param data 要写入文件的大型字符串。
     * @param filePath 文件的路径，字符串将被写入此文件。
     * @param chunkSize 每次写入的块大小，以字符数为单位。
     * @throws IOException 如果在写入文件过程中发生IO错误。
     */
    /**
     * 将大字符串分块写入到文件中
     *
     * @param data 要写入的字符串
     * @param filePath 目标文件的路径
     * @param chunkSize 每个写入块的大小（字符数）
     * @throws IOException 如果发生IO异常
     */
    public static void writeLargeStringToFile(String data, String filePath, int chunkSize) throws IOException {
        // 参数校验
        if (data == null) {
            throw new IllegalArgumentException("Data to be written cannot be null.");
        }
        if (filePath == null || filePath.isEmpty()) {
            throw new IllegalArgumentException("File path cannot be null or empty.");
        }
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("Chunk size must be a positive integer.");
        }

        // 使用BufferedWriter提高写入性能，通过OutputStreamWriter处理字符编码，确保写入文件的字符编码正确。
        // 这里明确指出文件是否应该以追加模式打开，取决于函数的预期用途。
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filePath), StandardCharsets.UTF_8))) {
            int length = data.length();
            // 分块写入字符串。循环遍历字符串，每次写入一个指定大小的块。
            for (int start = 0; start < length; start += chunkSize) {
                // 确定当前块的结束位置，确保不超过字符串的末尾。
                int end = Math.min(start + chunkSize, length);
                // 写入当前块的内容到文件。
                writer.write(data, start, end - start);
            }
        } catch (IOException e) {
            // 在这里，虽然异常最终还是抛出，但可以添加日志记录或其他错误处理逻辑。
            // 例如，使用日志框架记录异常信息（需要导入相应的日志库）：
            // Logger.getLogger(YourClass.class.getName()).log(Level.SEVERE, "Error writing to file: " + filePath, e);
            throw e; // 继续向上抛出异常，保持函数签名的异常声明不变。
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
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(filePath, true), StandardCharsets.UTF_8))) {
            writer.write(data);
        }
    }
}
