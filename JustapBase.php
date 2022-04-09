<?php

namespace payment;

use think\Exception;

class JustapBase {
    //请求渠道
    // const CHANNEL_ALIPAY_SCAN = 'AlipayScan';//: 支付宝条码支付
    // const CHANNEL_ALIPAY_FACE = 'AlipayFace';//: 支付宝刷脸支付
    const CHANNEL_ALIPAY_QR = 'AlipayQR';//: 支付宝扫码支付
    const CHANNEL_ALIPAY_APP = 'AlipayApp'; //: 支付宝 App 支付
    const CHANNEL_ALIPAY_WAP = 'AlipayWap'; //: 支付宝手机网站支付
    const CHANNEL_ALIPAY_PAGE = 'AlipayPage'; //: 支付宝电脑网站支付
    const CHANNEL_ALIPAY_LITE = 'AlipayLite';//: 支付宝小程序支付
    const CHANNEL_WECHATPAY_APP = 'WechatpayApp'; //: 微信 App 支付
    const CHANNEL_WECHATPAY_H5 = 'WechatpayH5'; //: 微信 H5 支付
    const CHANNEL_WECHATPAY_NATIVE = 'WechatpayNative';//: 微信 Native 支付
    const CHANNEL_WECHATPAY_LITE = 'WechatpayLite';//: 微信小程序支付
     const CHANNEL_WECHATPAY_JSAPI = 'WechatpayJSAPI';//: 微信 JSAPI 支付
    // const CHANNEL_WECHATPAY_FACE = 'WechatpayFace';//: 刷脸支付
    // const CHANNEL_WECHATPAY_SCAN = 'WechatpayScan';//: 微信付款码支付

    protected $config = [];
    protected $client;

    public function __construct($params = [])
    {
        $this->config = $params;
    }

    function initSdk() {
        $server = JustapConfiguration::getDefaultConfiguration();
        $server->setApiKey($this->config['justap_secret_key']);
        $server->setHost('https://trade.justap.cn');
        $server->setPrivateKey($this->config['justap_merchant_private_key']);
        $server->setUserAgent('justap-php-sdk/shopxo');
        $sdk = new JustapSdk();
        $sdk->setConfig($server);
        $sdk->setClient(new CurlHttpClient());
        $this->client = $sdk;
    }

    public function doPay($channel = '', $params = []) {
        $this->initSdk();

        $allKeys = array_keys($this->config);
        $requiredItems = ['justap_app_id', 'justap_secret_key', 'justap_public_key', 'justap_merchant_private_key'];

        // 配置信息
        if (empty($this->config) || count(array_intersect($requiredItems, $allKeys)) != count($requiredItems)) {
            return DataReturn('支付缺少配置', -1);
        }

        $params['notify_url'] = str_replace('127.0.0.1', 'wuzhuo-local.stg.cmzz.net', $params['notify_url']);
        $params['call_back_url'] = str_replace('127.0.0.1', 'wuzhuo-local.stg.cmzz.net', $params['call_back_url']);

        $creatChargeParams = [
            'app_id'            => $this->config['justap_app_id'],
            'merchant_trade_id' => $params['order_no'], //交易单号
            'channel'           => $channel,
            'amount'            => floatval($params['total_price']),
            'client_ip'         => GetClientIP(),
            'currency'          => 'CNY',
            'subject'           => $params['name'],
            'body'              => $params['name'],
            'extra' => '',
//            'metadata' => [
//                'user_id' => $params['user']['id'],
//                'username' => $params['user']['username'],
//                'nickname' => $params['user']['nickname'],
//            ],
            'ttl'               => $this->orderAutoCloseTime(),
            'description'       => $params['name'],
            'notify_url'        => $params['notify_url'],
            'callback_url'     => $params['call_back_url'],
            'notification_area' => 'CN',
        ];

        $resp = [];
        switch ($channel) {
            case self::CHANNEL_ALIPAY_APP:
                $creatChargeParams['extra'] = [
                    'alipay_app' => new \stdClass()
                ];
                $resp = $this->client->createCharge($creatChargeParams);
                break;
            case self::CHANNEL_ALIPAY_LITE:
                $creatChargeParams['extra'] = [
                    'alipay_lite' => new \stdClass()
                ];
                $resp = $this->client->createCharge($creatChargeParams);
                break;
            case self::CHANNEL_ALIPAY_PAGE:
                $creatChargeParams['extra'] = [
                    'alipay_page' => new \stdClass()
                ];
                $resp = $this->client->createCharge($creatChargeParams);
                break;
            case self::CHANNEL_ALIPAY_WAP:
                $creatChargeParams['extra'] = [
                    'alipay_wap' => new \stdClass()
                ];
                $resp = $this->client->createCharge($creatChargeParams);
                break;
            case self::CHANNEL_ALIPAY_QR:
                $creatChargeParams['extra'] = [
                    'alipay_qr' => new \stdClass()
                ];
                break;
            case self::CHANNEL_WECHATPAY_APP:
                $creatChargeParams['extra'] = [
                    'wechatpay_app' => new \stdClass()
                ];
                break;
            case self::CHANNEL_WECHATPAY_H5:
                $creatChargeParams['extra'] = [
                    'wechatpay_h5' => new \stdClass()
                ];
                break;
            case self::CHANNEL_WECHATPAY_NATIVE:
                $creatChargeParams['extra'] = [
                    'wechatpay_native' => new \stdClass()
                ];
                $resp = $this->client->createCharge($creatChargeParams);
                break;
            case self::CHANNEL_WECHATPAY_LITE:
                $creatChargeParams['extra'] = [
                    'wechatpay_lite' => [
                        'payer' => [
                            'openid' => $params['openid'],
                        ]
                    ]
                ];
                break;
            case self::CHANNEL_WECHATPAY_JSAPI:
                $creatChargeParams['extra'] = [
                    'wechatpay_jsapi' => [
                        'payer' => [
                            'openid' => $params['openid'],
                        ]
                    ]
                ];
                break;
            default:
                return DataReturn('渠道['.$channel.']暂未支付', -1);
        }

        if (strpos($resp['headers'][0], '200') < 0) {
            return DataReturn('支付接口下单失败', -1);
        }

        $body = json_decode($resp['body'], true);
        if (isset($body['code']) && $body['code'] != 0) {
            throw new \Exception($body['message']);
        }

        return $body;
    }

    public function Config()
    {
        // 基础信息
        $base = [
            'name'          => '开源聚合支付',  // 插件名称
            'version'       => 'v1.0.0',  // 插件版本
            'apply_version' => '不限',  // 适用系统版本描述
            'apply_terminal' => ['pc', 'h5', 'ios', 'android', 'alipay', 'weixin'], // 适用终端 默认全部 ['pc', 'h5', 'ios', 'android', 'alipay', 'weixin', 'baidu', 'toutiao']
            'desc'          => '<h1>开源聚合(TM)支付</h1>
<p style="margin-top: 10px;">不论是使用微信、支付宝，不论是在App、小程序、公众号哪种载体，一点接入所有主流支付渠道，开源聚合(TM)支付给你最简单、快捷的接入体验，彻底告别繁琐的支付接入流程。</p>
<div style="margin-top: 10px;"><a href="https://justap.cn" target="_blank">立即免费申请</a></div>
',
            'author'        => '开源聚合支付',  // 开发者
            'author_url'    => 'https://justap.cn',  // 开发者主页
        ];

        // 配置信息
        $element = [
            [
                'element'       => 'input',
                'type'          => 'text',
                'default'       => '',
                'name'          => 'justap_app_id',
                'placeholder'   => 'App ID',
                'title'         => '开源聚合支付 APP ID',
                'is_required'   => 1,
                'message'       => '请填写开源聚合支付平台商家APP ID',
            ],
            [
                'element'       => 'input',
                'type'          => 'text',
                'default'       => '',
                'name'          => 'justap_secret_key',
                'placeholder'   => 'App Secret',
                'title'         => '开源聚合支付平台商家 App Secret',
                'is_required'   => 1,
                'message'       => '请填写开源聚合支付平台商家App Secret',
            ],
            [
                'element'       => 'textarea',
                'default'       => '',
                'name'          => 'justap_public_key',
                'placeholder'   => '开源聚合支付平台公钥',
                'title'         => '开源聚合支付平台公钥',
                'is_required'   => 1,
                'message'       => '请填写开源聚合支付平台公钥',
            ],
            [
                'element'       => 'textarea',
                'default'       => '',
                'name'          => 'justap_merchant_private_key',
                'placeholder'   => '商家私钥',
                'title'         => '商家私钥',
                'is_required'   => 1,
                'message'       => '请填写商家私钥',
            ]
        ];

        return [
            'base'      => $base,
            'element'   => $element,
        ];
    }

    /**
     * 同步返回
     * justap 不通过同步方式返回支付结果。忽略处理
     * @param $params
     * @return array
     */
    public function Respond($params = []) {
        $data = empty($_POST) ? $_GET :  array_merge($_GET, $_POST);
        ksort($data);

        $data['trade_no']       = $data['merchant_trade_id'];        // 支付平台 - 订单号
        $data['out_trade_no']   = $data['charge_no'];    // 本系统发起支付的 - 订单号

        return DataReturn('请进入[我的订单]查看支付结果', 0, $data);
    }

    /**
     * 异步通知
     * 接收来自服务器的支付结果，以此为准
     * @param $params
     * @return array|void
     */
    public function Notify($params = []) {
        $this->initSdk();

        // 来自 justap 的通知数据是 json 格式
        $data = json_decode(file_get_contents('php://input'), true);
        if (isset($data['is_encrypted']) && $data['is_encrypted']) {
            if (!$this->config['justap_public_key']) {
                return DataReturn('缺少配置', -1);
            }

            $decrypted = decrypt_RSA($this->config['justap_public_key'], $data['data']);
            if (!$decrypted) {
                return DataReturn('解密失败', -1);
            }

            $data['data'] = json_decode($decrypted, true);
        }

        $notifyData = $data['data'];
        // TradeType_CHARGE_PAID 支付通知
        if ($notifyData['trade_type'] == 2) {
            if ($notifyData['is_paid']) {
                return DataReturn('支付成功', 0, $this->ReturnPaidData($notifyData));
            }
        }

        // TradeType_CHARGE_REFUND  退款通知
        if ($notifyData['trade_type'] == 3) {

        }
    }

    public function Refund($params = []) {

    }

    public function SuccessReturn($params = [])
    {
        if (empty($params)) {
            $params = input();
        }

        return 'success';
    }

    public function ErrorReturn($params = [])
    {
        throw new Exception('支付失败');
    }

    public function OrderAutoCloseTime()
    {
        return intval(MyC('common_order_close_limit_time', 30, true)) * 60;
    }

    private function ReturnPaidData($data)
    {
        // 返回数据固定基础参数
        $data['trade_no']       = $data['charge_no'];        // 支付平台 - 订单号
        $data['buyer_user']     = "";       // 支付平台 - 用户
        $data['out_trade_no']   = $data['merchant_trade_id'];    // 本系统发起支付的 - 订单号
        $data['subject']        = ''; // 本系统发起支付的 - 商品名称
        $data['pay_price']      = $data['amount_total'];    // 本系统发起支付的 - 总价

        return $data;
    }
}

function encrypt_RSA($plainData, $privatePEMKey)
{
    $encrypted = '';
    $plainData = str_split($plainData, 200);

    foreach($plainData as $chunk)
    {
        $partialEncrypted = '';
        $encryptionOk = openssl_private_encrypt($chunk, $partialEncrypted, $privatePEMKey, OPENSSL_PKCS1_PADDING);
        if($encryptionOk === false){
            return false;
        }
        $encrypted .= $partialEncrypted;
    }

    return base64_encode($encrypted);
}

function decrypt_RSA($publicPEMKey, $data)
{
    $decrypted = '';
    $data = str_split(base64_decode($data), 256);
    foreach($data as $chunk)
    {
        $partial = '';
        $decryptionOK = openssl_public_decrypt($chunk, $partial, $publicPEMKey, OPENSSL_PKCS1_PADDING);
        if($decryptionOK === false){
            return false;
        }
        $decrypted .= $partial;
    }

    return $decrypted;
}
