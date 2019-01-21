<?php 

include '../../../autoload.php';

use RainSunshineCloud\JWT;

//登录时首次加载
$res = JWT::first('sdfkj','wrekjsdkf');


/**
 jwt 必须是对象，否则请自行存储refreshtime，现在是直接临时存放在对象内，若不使用当前对象则无法encode
 refreshtime 是自登陆后到refresh有效期到达的时间
 endtime 是自该token发出到expire有效期到达的时间
 */


//jwt解密
$jwt = new JWT();
var_dump($jwt->refresh(10)->expire(10)->decode($res));

//jwt加密
$res = $jwt->encode('ksdjfksdfj');

var_dump($res);
var_dump($jwt->decode($res));
