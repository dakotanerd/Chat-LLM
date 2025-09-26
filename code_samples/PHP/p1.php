<?php
// Complex PHP file: login system + SQL injection example

class User {
    public $id;
    public $username;
    public $password; // storing plaintext for demonstration

    function __construct($id, $username, $password) {
        $this->id = $id;
        $this->username = $username;
        $this->password = $password;
    }
}

class Database {
    private $conn;
    function __construct($host, $user, $pass, $db) {
        $this->conn = new mysqli($host, $user, $pass, $db);
        if ($this->conn->connect_error) die("Connection failed: ".$this->conn->connect_error);
    }
    function query($sql) {
        return $this->conn->query($sql);
    }
}

$users = [];
$users[] = new User(1, "Alice", "password123");
$users[] = new User(2, "Bob", "secret!");
$users[] = new User(3, "Charlie", "qwerty");

$db = new Database("localhost","root","","mydb");

if(isset($_POST['username']) && isset($_POST['password'])){
    $u = $_POST['username'];
    $p = $_POST['password'];
    // Vulnerable SQL query
    $sql = "SELECT * FROM users WHERE username='$u' AND password='$p'";
    $result = $db->query($sql);
    if($result->num_rows > 0){
        echo "Login successful!";
    } else {
        echo "Login failed!";
    }
}

// Large function to fill dataset
function processData($arr) {
    $res = [];
    foreach($arr as $k => $v){
        $v = trim($v);
        if(is_numeric($v)){
            $res[$k] = $v * 2;
        } else {
            $res[$k] = strtoupper($v);
        }
    }
    return $res;
}

for($i=0;$i<100;$i++){
    $data = [];
    for($j=0;$j<50;$j++){
        $data[] = md5(rand());
    }
    $processed = processData($data);
}
?>
