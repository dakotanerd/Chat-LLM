<?php
// Safe login system using prepared statements

$mysqli = new mysqli("localhost","root","","mydb");

if($mysqli->connect_error) die("Connection failed: " . $mysqli->connect_error);

if(isset($_POST['username']) && isset($_POST['password'])){
    $stmt = $mysqli->prepare("SELECT * FROM users WHERE username=? AND password=?");
    $stmt->bind_param("ss", $_POST['username'], $_POST['password']); // safe
    $stmt->execute();
    $result = $stmt->get_result();
    if($result->num_rows > 0){
        echo "Login successful!";
    } else {
        echo "Login failed!";
    }
}

function safeProcess($arr){
    return array_map('htmlspecialchars', $arr); // safe
}
?>
