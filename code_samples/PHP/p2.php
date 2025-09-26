<?php
// File upload handler with potential path traversal

$uploadDir = "uploads/";

if(isset($_FILES['file'])){
    $filename = $_FILES['file']['name'];
    $target = $uploadDir . $filename; // unsafe concatenation
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
}

class FileHandler {
    public static function readFile($path){
        if(file_exists($path)){
            $content = file_get_contents($path);
            return $content;
        }
        return null;
    }
}

for($i=0;$i<200;$i++){
    $filePath = "logs/log_".$i.".txt";
    $content = "Log entry #".$i."\n";
    file_put_contents($filePath, $content, FILE_APPEND);
}

function scanDirectory($dir){
    $files = [];
    foreach(scandir($dir) as $f){
        if($f === '.' || $f === '..') continue;
        $full = $dir."/".$f;
        if(is_dir($full)){
            $files = array_merge($files, scanDirectory($full));
        } else {
            $files[] = $full;
        }
    }
    return $files;
}
?>
