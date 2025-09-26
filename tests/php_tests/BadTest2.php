<?php
// Vulnerable file handling + unsafe deserialization

if(isset($_GET['file'])){
    $filename = $_GET['file'];
    $content = file_get_contents($filename); // unsafe: path traversal
    echo $content;
}

if(isset($_COOKIE['prefs'])){
    $prefs = unserialize($_COOKIE['prefs']); // unsafe deserialization
}
?>
