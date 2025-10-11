package Mine.util;

import java.io.*;

public class FileIOUtil {
    public static String FileIO(String[] args) throws IOException {
        FileInputStream fis = new FileInputStream("/Users/shay_li/Downloads/textfile.txt");
        byte[] buffer = new byte[10];
        StringBuilder sb = new StringBuilder();
        while (fis.read(buffer) != -1) {
            sb.append(new String(buffer));
            buffer = new byte[10];
        }
        fis.close();
        String content = sb.toString();
        return content;
    }
}
