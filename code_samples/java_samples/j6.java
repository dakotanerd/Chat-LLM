import java.io.*;
import java.util.*;
import java.sql.*;

class User {
    int id;
    String username;
    String password; // Vulnerable: storing passwords in plaintext

    User(int id, String username, String password) {
        this.id = id;
        this.username = username;
        this.password = password;
    }

    void printUser() {
        System.out.println("ID: " + id + ", Username: " + username);
    }
}

public class VulnTest {

    private static List<User> users = new ArrayList<>();

    public static void main(String[] args) {
        addSampleUsers();

        // Vulnerability 1: SQL Injection
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter username to search: ");
            String input = reader.readLine();
            
            String query = "SELECT * FROM users WHERE username = '" + input + "';";
            System.out.println("Executing query: " + query);
            // Pretend execution
            // Statement stmt = connection.createStatement();
            // ResultSet rs = stmt.executeQuery(query);

        } catch (IOException e) {
            e.printStackTrace();
        }

        // Vulnerability 2: Unsafe file handling
        try {
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.print("Enter filename to read: ");
            String filename = reader.readLine();

            File file = new File(filename); // Unsafe: no path validation
            BufferedReader fileReader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = fileReader.readLine()) != null) {
                System.out.println(line);
            }
            fileReader.close();

        } catch (IOException e) {
            e.printStackTrace();
        }

        // Print all users
        for (User u : users) {
            u.printUser();
        }
    }

    static void addSampleUsers() {
        users.add(new User(1, "Alice", "password123"));
        users.add(new User(2, "Bob", "secret!"));
        users.add(new User(3, "Charlie", "qwerty"));
    }
}
