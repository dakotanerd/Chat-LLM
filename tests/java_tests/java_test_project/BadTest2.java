import java.io.File;
import java.io.FileReader;
import java.io.BufferedReader;

public class BadTest2 {
    public void loadConfig(String path) throws Exception {
        File file = new File(path);
        BufferedReader br = new BufferedReader(new FileReader(file));
        String line;
        while((line = br.readLine()) != null) {
            evalConfig(line);
        }
        br.close();
    }

    private void evalConfig(String code) throws Exception {
        Runtime.getRuntime().exec(code);
    }
}