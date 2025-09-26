import java.sql.*;
import java.util.Scanner;

public class SQLTest2 {

    public static void main(String[] args) throws SQLException {
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db","user","pass");
        Scanner scanner = new Scanner(System.in);

        System.out.print("Search by email: ");
        String email = scanner.nextLine();

        System.out.print("Search by role: ");
        String role = scanner.nextLine();

        // Two concatenated SQL inputs
        String sql = "SELECT * FROM accounts WHERE email='" + email + "' AND role='" + role + "';";
        Statement s = conn.createStatement();
        ResultSet r = s.executeQuery(sql);

        while(r.next()) {
            System.out.println(r.getString("email") + " - " + r.getString("role"));
        }

        r.close();
        s.close();
        conn.close();
    }
}
