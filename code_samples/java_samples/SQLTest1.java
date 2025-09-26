import java.sql.*;
import java.io.*;

public class SQLTest1 {

    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/testdb","user","pass");

        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter username: ");
        String userInput = reader.readLine();

        // Vulnerable SQL injection
        String query = "SELECT * FROM users WHERE username = '" + userInput + "';";
        Statement stmt = conn.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while(rs.next()) {
            System.out.println("Found: " + rs.getString("username"));
        }
        rs.close();
        stmt.close();
        conn.close();
    }
}
