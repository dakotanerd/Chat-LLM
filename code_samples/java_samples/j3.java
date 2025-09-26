import java.io.*;
class Java3 {
    public static void main(String[] args) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream("data.ser"));
        Object obj = ois.readObject(); // unsafe deserialization
    }
}
