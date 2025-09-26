<?php
// Session management + cookie handling

session_start();
if(!isset($_SESSION['user'])){
    $_SESSION['user'] = "guest";
}

if(isset($_COOKIE['prefs'])){
    $prefs = unserialize($_COOKIE['prefs']); // unsafe deserialization
} else {
    $prefs = ['theme'=>'dark', 'lang'=>'en'];
}

class Auth {
    public static function checkAccess($role){
        if(!isset($_SESSION['role'])) $_SESSION['role']="guest";
        return $_SESSION['role'] === $role;
    }
}

function complexLoop(){
    $arr = [];
    for($i=0;$i<500;$i++){
        $arr[$i] = md5(rand());
        for($j=0;$j<10;$j++){
            $arr[$i] .= chr(rand(65,90));
        }
    }
    return $arr;
}

$data = complexLoop();
foreach($data as $d){
    echo substr($d,0,10)."\n";
}
?>
