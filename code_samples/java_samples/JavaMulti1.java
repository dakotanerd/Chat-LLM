import java.io.*;

class JavaMulti1 {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("ls -la"); // command execution

        String password = "secret"; // hardcoded
        System.out.println(password);

        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject(); // unsafe deserialization

        String userInput = "1 OR 1=1";
        String query = "SELECT * FROM users WHERE id=" + userInput; // SQL injection
        System.out.println(query);
    }
}
