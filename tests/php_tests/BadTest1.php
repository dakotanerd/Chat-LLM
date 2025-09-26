<?php
// Vulnerable login system with SQL injection

if(isset($_POST['username']) && isset($_POST['password'])){
    $u = $_POST['username'];
    $p = $_POST['password'];
    $query = "SELECT * FROM users WHERE username='$u' AND password='$p'"; // SQL injection
    echo "Query: $query";
}

// Hardcoded password
$adminPass = "SuperSecret123"; // unsafe

?>
