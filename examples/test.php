<?php 

include '../../autoload.php';

use RainSunshineCloud\JWT;

//登录时首次加载
$res = JWT::instance()->refresh(100)->expire(100)->addPayload('sdfkj','kdfjk')->addPripayload('java','kjd')->encode();

$res = "ZXlKMGVYQmxJam9pU2xkVUlpd2lZV3huYnlJNkluTm9ZVEkxTmlJc0luTjBJam94TlRZM056WXhOVFkzTENKbGRDSTZNVFUyTnpjMk1UWTJOeXdpWm5RaU9qRTFOamMzTmpFMk5qZDkuZXlKelpHWnJhaUk2SW10a1ptcHJJbjA9LmluQU9yaEZZQ0JyTzJyZjB4UDErYlE9PS4yM2IwYmI0Nzg0ZmYwMmM0MWM1MmYzOWRmZTk5N2Q5ZTM0MTU4ZDk3ZjVjMWU3Y2YxZDcxYjU2ZGJkNTMxNTIx";
//jwt解密
$jwt = JWT::instance();

var_dump($jwt->decode($res));

//jwt加密
$res = $jwt->encode('ksdjfksdfj');

var_dump($res);
var_dump($jwt->decode($res));
