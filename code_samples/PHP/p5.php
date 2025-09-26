<?php
// API request handling, cURL, string processing

function callAPI($url, $data){
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
    $response = curl_exec($ch);
    curl_close($ch);
    return $response;
}

for($i=0;$i<50;$i++){
    $data = ['user'=>"user$i", 'action'=>"ping"];
    $resp = callAPI("https://example.com/api", $data);
}

function complexStringOps($input){
    $res = [];
    $words = explode(" ", $input);
    foreach($words as $w){
        $res[] = strrev($w).strtoupper($w);
    }
    return implode("-", $res);
}

$text = str_repeat("lorem ipsum dolor sit amet ", 100);
$processed = complexStringOps($text);
?>
