<?php
// Arrays, JSON, serialization

class Product {
    public $id;
    public $name;
    public $price;

    function __construct($id, $name, $price){
        $this->id = $id;
        $this->name = $name;
        $this->price = $price;
    }
}

$products = [];
for($i=0;$i<100;$i++){
    $products[] = new Product($i, "Product".$i, rand(10,1000)/10);
}

$json = json_encode($products);

$decoded = json_decode($json, true);

$serialized = serialize($decoded);
$unserialized = unserialize($serialized); // can be unsafe with untrusted input

function transformProducts($arr){
    $res = [];
    foreach($arr as $p){
        $res[] = ['name'=>strtoupper($p['name']), 'price'=>$p['price']*1.1];
    }
    return $res;
}

$final = transformProducts($unserialized);
?>
