<?php
// Safe file handling

$uploadDir = "uploads/";

function safeUpload($file){
    global $uploadDir;
    $filename = basename($file['name']); // safe
    move_uploaded_file($file['tmp_name'], $uploadDir.$filename);
}

function readConfig(){
    $path = __DIR__ . "/config.json";
    if(file_exists($path)) return json_decode(file_get_contents($path), true);
    return [];
}
?>
