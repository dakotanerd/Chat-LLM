import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;

public class BadTest1 {
    public void fetchUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
        String query = "SELECT * FROM users WHERE username = '" + username + "';";
        Statement stmt = conn.createStatement();
        stmt.executeQuery(query);
        stmt.close();
        conn.close();
    }
}