package src;

import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;

public class VulnerableUtils {

    public static String unsafeReadFile(String filePath) {
        try {
            File file = new File(filePath);
            BufferedReader br = new BufferedReader(new FileReader(file));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                if (line.contains("EVAL")) {
                    // Unsafe eval simulation (conceptual)
                    return line.split("EVAL:")[1];
                }
                sb.append(line).append("\n");
            }
            br.close();
            return sb.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }
}