<?php
namespace RainSunshineCloud;

class JWT 
{
	private static $algo = 'sha256';
	private static $keys = 'sdfs';
	private static $openssl_algo = 'AES-256-CBC';
	private static $oppenssl_key = 'sdfsdfsasdfsfsserwedsfsdfsdfewerwf';
	private static $iv = '1q3w12121d2e4242';
	private static $type = 'JWT';
	//当前token有效期
	private $expire = 300;
	//token有效期
	private $refresh = 72000;

	private $endTime = 0;
	private $startTime = 0;
	//必须记住的refreshTime
	private $refreshTime = 0;
	
	/**
	 * 第一次生成
	 * @param  [type] $payload         [description]
	 * @param  [type] $private_payload [description]
	 * @return [type]                  [description]
	 */
	public static function first($payload,$private_payload = null)
	{
		$res = New self();
		return $res->encode($payload,$private_payload,true);
	}

	public function encode($payload,$private_payload = null,bool $is_first = false)
	{
		$res = '';
		//生成有效期
		$this->startTime = $_SERVER['REQUEST_TIME'];
		$this->endTime = $this->startTime + $this->expire;
		$this->refreshTime = $is_first ? $this->startTime + $this->refresh : $this->getRefreshTime($is_first);

		if ($this->refreshTime <= $_SERVER['REQUEST_TIME']) {
			throw new JWTException('encode 失败',1001);
		}
		$header = [
			'type' 	=> self::$type,
			'algo' 	=> self::$algo,
			'st'  	=> $this->startTime,
			'et' 	=> $this->endTime,
			'ft' 	=> $this->refreshTime,
		];
	
		$res .= self::enHeader($header);
		$res .= '.'.self::enPayload($payload);
		
		if ($private_payload){
			$res .= '.'.self::enPrivatePayload($private_payload);
		}

		$res .= '.'.self::enSignature($res);
		return str_replace(['+','/','='],['-','_',''],base64_encode($res));
	}

	/**
	 * 解密
	 * @param  [type] $token [description]
	 * @return [type]        [description]
	 */
	public function decode(string $token)
	{
		$token = self::urlsafe_b64decode($token);

		if ($token == false) {
			throw new JWTException('decode 失败',1001);
		}

		$res = explode('.',$token);
		$count = count($res);

		if ( $count == 3) {
			$payload = self::dePayload($res[1]);
			$sign = self::deSignature($res);
			$header = $this->deHeader($res[0]);
			return $payload;
		} else if ($count == 4) {
			$payload = self::dePayload($res[1]);
			$sign = self::deSignature($res);
			$header = $this->deHeader($res[0]);
			$private = self::dePrivatePayload($res[2]);
			return [
				'public' => $payload,
				'private' => $private,
			];
		} else {
			throw new JWTException('decode 失败',1001);
		}
	}

	/**
	 * header信息
	 * @param  array  $header [description]
	 * @return [type]         [description]
	 */
	private static function enHeader(array $header):string
	{
		$header = json_encode($header);

		if ($header === false) {
			throw new JWTException('header 加密失败',1001);
		}

		$res = base64_encode($header);

		if ($res === false) {
			throw new JWTException('header 加密失败',1001);
		}

		return $res;
	}

	/**
	 * 解密
	 * @param  string $header [description]
	 * @return [type]         [description]
	 */
	private function deHeader(string $header)
	{
		$header = base64_decode($header);

		if ($header === false) {
			throw new JWTException('header 解密失败',1001);
		}

		$res = json_decode($header,true); 

		if (!$res) {
			throw new JWTException('header 解密失败',1001);
		}

		if (empty($res['type']) || $res['type'] != self::$type) {
			throw new JWTException('header 解密失败',1001);
		}

		if (empty($res['type']) || $res['algo'] != self::$algo) {
			throw new JWTException('header 解密失败',1001);
		}

		if (empty($res['st']) || $_SERVER['REQUEST_TIME'] < $res['st'] || empty($res['et']) || empty($res['ft'])) {
			throw new JWTException('header 解密失败',1001);
		}

		if ($_SERVER['REQUEST_TIME'] > $res['ft'] || $_SERVER['REQUEST_TIME'] > $res['et']) {
			throw new JWTException('token 过期',1002);
		}

		$this->startTime = $res['st'];
		$this->endTime = $res['et'];
		$this->setRefreshTime($res['ft']);
		return $res;
	}

	/**
	 * 公共信息
	 * payload
	 * @return [type] [description]
	 */
	private static function enPayload($payload)
	{
		if (is_array($payload) || is_object($payload)) {
			$payload = json_encode($header);

			if ($payload === false) {
				throw new JWTException('payload 加密失败',1001);
			}
		}

		$res = base64_encode($payload);

		if ($res === false) {
			throw new JWTException('payload 加密失败',1001);
		}

		return $res;
	}

	/**
	 * 解密公共信息
	 * @param  string $payload [description]
	 * @return [type]          [description]
	 */
	private static function dePayload(string $payload)
	{
		$payload = base64_decode($payload);

		if ($payload === false) {
			throw new JWTException('payload 解密失败',1001);
		}

		$res = json_decode($payload,true); 

		if (is_null($res)) {
			return $payload;
		}

		return $res;
	}

	/**
	 * 签名
	 * @param  string $sign [description]
	 * @return [type]       [description]
	 */
	private static function enSignature(string $sign)
	{
		$res = \hash_hmac(self::$algo,$sign,self::$keys);

		if ($res === false) {
			throw new JWTException('sign 加密失败',1001);
		}

		return $res;
	}

	/**
	 * 验证签名
	 * @param  array  $token [description]
	 * @return [type]        [description]
	 */
	private static function deSignature(array $token)
	{
		$sign = array_pop($token);
		$en_sign = self::enSignature(join('.',$token));

		if ($sign !== $en_sign) {
			throw new JWTException('sign 解密失败',1001);
		}

		return true;
	}

	/**
	 * 加密敏感信息
	 * @param  [type] $content [description]
	 * @return [type]          [description]
	 */
	private static function enPrivatePayload($content)
	{
		if (is_array($content) || is_object($content)) {
			$content = json_encode($content);

			if ($content == false) {
				throw new JWTException('private_payload 加密失败',1001);
			}
		}
		$tag = '';
	    $content = openssl_encrypt($content,self::$openssl_algo,self::$oppenssl_key,0, self::$iv);
	    
	    if ($content == false) {
			throw new JWTException('private_payload 加密失败',1001);
		}

	    return $content;
	}

	/**
	 * 加密
	 */
	private static function dePrivatePayload(string $content)
	{
		$content = openssl_decrypt($content,self::$openssl_algo,self::$oppenssl_key, 0, self::$iv);
		if ($content == false) {
			throw new JWTException('private_payload 解密失败',1001);
		}

		$res = json_decode($content,true);
		if (is_null($res)) {
			return $content;
		} 

		return $res;
	}

	/**
	 * 设置签名加密秘钥
	 * @param [type] $keys [description]
	 */
	public static function setKeys(string $keys)
	{
		self::$keys = $keys;
	}

	/**
	 * 设置私有信息加密向量
	 * @param [type] $iv [description]
	 */
	public static function setIv(string $iv)
	{
		self::$iv = $iv;
	}

	/**
	 * 设置私有信息加密的秘钥
	 * @param [type] $keys [description]
	 */
	public static function setSslKeys(string $keys)
	{
		self::$oppenssl_key = $keys;
	}

	/**
	 * 设置签名加密方法
	 * @param [type] $algo [description]
	 */
	public static function setAlgo(string $algo)
	{
		self::$algo = $algo;
	}

	/**
	 * 这是私有信息加密方法
	 * @param [type] $algo [description]
	 */
	public static function setSslAlgo(string $algo)
	{
		self::$openssl_algo = $algo;
	}

	/**
	 * 安全base
	 * @param  [type] $string [description]
	 * @return [type]         [description]
	 */
	private static function urlsafe_b64decode(string $data) {

   		$data = str_replace(array('-','_'),array('+','/'),$data);
   		$mod4 = strlen($data) % 4;

   		if ($mod4) {
       		$data .= substr('====', $mod4);
   		}
   		
   		return base64_decode($data);
 	}

 	public function expire(int $time)
 	{
 		$this->expire = $time;
 		return $this;
 	}

 	public function refresh(int $time)
 	{
 		$this->refresh = $time;
 		return $this;
 	}

 	//获取有效时间
 	public function getRefreshTime() 
 	{
 		return $this->refreshTime;
 	}
 	//获取设置有效时间
 	public function setRefreshTime($refresh_time) 
 	{
 		$this->refreshTime = $refresh_time;

 	}

}

class JWTException extends \Exception
{
	
}