import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;

public class GoodTest2 {
    public void fetchUser(String username) throws Exception {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "user", "pass");
        String query = "SELECT * FROM users WHERE username = ?";
        PreparedStatement ps = conn.prepareStatement(query);
        ps.setString(1, username);
        ps.executeQuery();
        ps.close();
        conn.close();
    }
}