<?php
namespace RainSunshineCloud;

class JWT 
{
	private  $algo = 'sha256';
	private  $keys = 'sdfs';
	private  $openssl_algo = 'AES-256-CBC';
	private  $oppenssl_key = 'sdfsdfsasdfsfsserwedsfsdfsdfewerwf';
	private  $iv = '1q3w12121d2e4242';
	private  $type = 'JWT';
	private  $is_first = true;
	private static $self_obj = null;
	//payload
	private  $pri_payload = [];
	private  $payload = [];
	//当前token有效期
	private $expire = 300;
	//token有效期
	private $refresh = 72000;

	private $endTime = 0;
	private $startTime = 0;
	//必须记住的refreshTime
	private $refreshTime = 0;

	public function encode()
	{
		$res = '';
		//生成有效期
		$this->startTime = $_SERVER['REQUEST_TIME'];
		$this->endTime = $this->startTime + $this->expire;
		$this->refreshTime = $this->is_first ? $this->startTime + $this->refresh : $this->getRefreshTime();
		$header = [
			'type' 	=> $this->type,
			'algo' 	=> $this->algo,
			'st'  	=> $this->startTime,
			'et' 	=> $this->endTime,
			'ft' 	=> $this->refreshTime,
		];
	
		$res .= $this->enHeader($header);
		$res .= '.'.$this->enPayload();
		
		if ($this->pri_payload){
			$res .= '.'.$this->enPrivatePayload();
		}

		$res .= '.'.$this->enSignature($res);
		return str_replace(['+','/','='],['-','_',''],base64_encode($res));
	}

	/**
	 * 解密
	 * @param  [type] $token [description]
	 * @return [type]        [description]
	 */
	public function decode(string $token)
	{
		$this->is_first = false;
		$token = $this->urlsafe_b64decode($token);

		if ($token == false) {
			throw new JWTException('decode 失败',1001);
		}

		$res = explode('.',$token);
		$count = count($res);

		if ( $count == 3) {
			$payload = $this->dePayload($res[1]);
			$sign = $this->deSignature($res);
			$header = $this->deHeader($res[0]);
			return $payload;
		} else if ($count == 4) {
			$payload = $this->dePayload($res[1]);
			$sign = $this->deSignature($res);
			$header = $this->deHeader($res[0]);
			$private = $this->dePrivatePayload($res[2]);
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
	private function enHeader(array $header):string
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

		if (empty($res['type']) || $res['type'] != $this->type) {
			throw new JWTException('header 解密失败',1001);
		}

		if (empty($res['type']) || $res['algo'] != $this->algo) {
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
	private function enPayload()
	{
		$payload = $this->payload;
		if (is_array($payload) || is_object($payload)) {
			$payload = json_encode($payload);

			if ($payload === false) {
				throw new JWTException('payload 加密失败:'.json_last_error(),1001);
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
	private function dePayload(string $payload)
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
	private function enSignature(string $sign)
	{
		$res = \hash_hmac($this->algo,$sign,$this->keys);

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
	private function deSignature(array $token)
	{
		$sign = array_pop($token);
		$en_sign = $this->enSignature(join('.',$token));

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
	private function enPrivatePayload()
	{
		$content = $this->pri_payload;

		if (is_array($content) || is_object($content)) {
			$content = json_encode($content);

			if ($content == false) {
				throw new JWTException('private_payload 加密失败',1001);
			}
		}
		$tag = '';
	    $content = openssl_encrypt($content,$this->openssl_algo,$this->oppenssl_key,0, $this->iv);
	    
	    if ($content == false) {
			throw new JWTException('private_payload 加密失败',1001);
		}

	    return $content;
	}

	/**
	 * 加密
	 */
	private function dePrivatePayload(string $content)
	{
		$content = openssl_decrypt($content,$this->openssl_algo,$this->oppenssl_key, 0, $this->iv);
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
		$this->keys = $keys;
		return $this;
	}

	/**
	 * 设置私有信息加密向量
	 * @param [type] $iv [description]
	 */
	public static function setIv(string $iv)
	{
		$this->iv = $iv;
		return $this;
	}

	/**
	 * 设置私有信息加密的秘钥
	 * @param [type] $keys [description]
	 */
	public function setSslKeys(string $keys)
	{
		$this->oppenssl_key = $keys;
		return $this;
	}

	/**
	 * 设置签名加密方法
	 * @param [type] $algo [description]
	 */
	public function setAlgo(string $algo)
	{
		$this->algo = $algo;
		return $this;
	}

	/**
	 * 这是私有信息加密方法
	 * @param [type] $algo [description]
	 */
	public function setSslAlgo(string $algo)
	{
		$this->openssl_algo = $algo;
		return $this;
	}

	/**
	 * 安全base
	 * @param  [type] $string [description]
	 * @return [type]         [description]
	 */
	private function urlsafe_b64decode(string $data) {

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
 		return $this;

 	}
	
	protected function __construct()
	{

	}

	public function addPayload(string $key,$value)
	{

		$this->payload[$key] = $value;
		return $this;
	}

	public function addPriPayload(string $key,$value)
	{
		$this->pri_payload[$key] = $value;
		return $this;
	}

	public function setPayload($payload)
	{
		$this->payload = $payload;
		return $this;
	}

	public function setPriPayload($payload)
	{
		$this->pri_payload= $payload;
		return $this;
	}


	/**
	 * 单例
	 * @return [type] [description]
	 */
	public static function instance()
	{
		if (!self::$self_obj) {
			self::$self_obj = new self();
		}
		
		return self::$self_obj;
	}

}

class JWTException extends \Exception
{
	
}
