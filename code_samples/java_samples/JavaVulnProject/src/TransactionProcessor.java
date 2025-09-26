package src;

public class TransactionProcessor {

    public void processTransaction(User user, double amount) {
        try {
            // Vulnerable: command injection via Runtime.exec
            String command = "echo Processing " + amount + " for " + user.getUsername();
            Runtime.getRuntime().exec(command);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void safeProcessTransaction(User user, double amount) {
        // Safe method: just print in Java
        System.out.println("Processing " + amount + " for " + user.getUsername());
    }
}