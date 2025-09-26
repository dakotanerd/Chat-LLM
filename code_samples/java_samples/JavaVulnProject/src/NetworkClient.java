package src;

import java.net.HttpURLConnection;
import java.net.URL;

public class NetworkClient {

    public static void sendData(String urlStr, String data) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.getOutputStream().write(data.getBytes());
            conn.getInputStream().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void insecureSendData(String urlStr, String data) {
        try {
            URL url = new URL(urlStr);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setDoOutput(true);
            conn.setSSLSocketFactory(null); // Insecure: disables TLS verification
            conn.getOutputStream().write(data.getBytes());
            conn.getInputStream().close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}