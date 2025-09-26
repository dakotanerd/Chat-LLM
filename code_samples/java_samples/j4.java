import java.sql.*;
class Java4 {
    public static void main(String[] args) throws Exception {
        String userInput = "1 OR 1=1";
        String query = "SELECT * FROM users WHERE id=" + userInput;
        System.out.println(query); // potential SQL injection
    }
}
