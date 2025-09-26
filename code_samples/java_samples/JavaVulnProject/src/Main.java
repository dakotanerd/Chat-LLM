package src;

public class Main {

    public static void main(String[] args) {
        UserManager manager = new UserManager();
        User admin = new User("admin", SecureUtils.hashPassword("admin123"));
        User guest = new User("guest", SecureUtils.hashPassword("guest123"));

        manager.addUser(admin);
        manager.addUser(guest);

        manager.saveUsers("users.dat");
        manager.loadUsers("users.dat");

        TransactionProcessor tp = new TransactionProcessor();
        for (User u : manager.getUsers()) {
            tp.processTransaction(u, 500);        // Vulnerable
            tp.safeProcessTransaction(u, 100);   // Safe
        }

        NetworkClient.sendData("http://localhost:8080", "Hello");          // Safe
        NetworkClient.insecureSendData("https://example.com", "Secret");   // Unsafe
    }
}