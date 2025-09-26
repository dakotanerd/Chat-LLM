import java.io.*;
import java.util.*;
import java.sql.*;

class User {
    int id;
    String username;
    String passwordHash;

    User(int id, String username, String passwordHash) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
    }

    void printUser() {
        System.out.println("ID: " + id + ", Username: " + username);
    }
}

public class SafeTest {

    private static List<User> users = new ArrayList<>();

    public static void main(String[] args) {
        addSampleUsers();

        // Safe file reading: only read files from "data" folder
        try {
            File file = new File("data/sample.txt");
            BufferedReader reader = new BufferedReader(new FileReader(file));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        // Safe printing of users
        for (User u : users) {
            u.printUser();
        }
    }

    static void addSampleUsers() {
        users.add(new User(1, "Alice", hashPassword("password123")));
        users.add(new User(2, "Bob", hashPassword("secret!")));
        users.add(new User(3, "Charlie", hashPassword("qwerty")));
    }

    static String hashPassword(String password) {
        return Integer.toHexString(password.hashCode()); // simple hash example
    }
}
