### 这是一个JWT的封装类

#### 用法

```
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


```


#### 更新点
- 采用单例模式
- 采用内部自行判断是否为第一次encode（有一次decode则为不是第一次encode）
- 数据自行添加，不是encode时再添加，setPayload addPayload setPriPayload addPriPayload


#### 注意点

- 使用单例模式，直接内部自行判断是否为第一次颁发token
- refreshtime 是自登陆后到refresh有效期到达的时间
- endtime 是自该token发出到expire有效期到达的时间
- refreshtime >= endtime >= starttime
- encode 第二个参数为私有参数加密，即进行对称加密