import java.security.MessageDigest;

public class GoodTest3 {
    public static String hashPassword(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes("UTF-8"));
        StringBuilder sb = new StringBuilder();
        for(byte b : hash) sb.append(String.format("%02x", b));
        return sb.toString();
    }
}