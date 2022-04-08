<?php

namespace payment;

class JustapWechatPay extends JustapBase {
    public function Config() {
        $config = parent::Config();
        $config['base']['name'] .= '-微信支付';
        $config['base']['apply_terminal'] = ['pc', 'h5', 'ios', 'android', 'weixin'];

        return $config;
    }

    public function Pay($params = []) {
        // 参数
        if(empty($params))
        {
            return DataReturn('参数不能为空', -1);
        }

        // 配置信息
        if(empty($this->config))
        {
            return DataReturn('支付缺少配置', -1);
        }

        // 微信中打开
        if(APPLICATION_CLIENT_TYPE == 'pc' && IsWeixinEnv() && (empty($params['user']) || empty($params['user']['weixin_web_openid'])))
        {
            exit(header('location:'.PluginsHomeUrl('weixinwebauthorization', 'pay', 'index', input())));
        }

        $channel = '';
        $openId = '';
        if (APPLICATION_CLIENT_TYPE == 'weixin') {
            $openid = isset($params['user']['weixin_openid']) ? $params['user']['weixin_openid'] : '';
        } else {
            $openid = isset($params['user']['weixin_web_openid']) ? $params['user']['weixin_web_openid'] : '';
        }

        switch(APPLICATION_CLIENT_TYPE) {
            // web
            case 'pc' :
            case 'h5' :
                if(IsMobile())
                {
                    // real h5
                    if (IsWeixinEnv()) {
                        $channel = self::CHANNEL_WECHATPAY_JSAPI;
                    } else {
                        $channel = self::CHANNEL_WECHATPAY_NATIVE;
                    }
                } else {
                    $channel = self::CHANNEL_WECHATPAY_NATIVE;
                }

                break;

            case 'weixin':
                $channel = self::CHANNEL_WECHATPAY_JSAPI;
                break;
            // 指的是app支付
            case 'app' :
            case 'ios' :
            case 'android' :
                $channel = self::CHANNEL_WECHATPAY_APP;
                break;

            default :
                return DataReturn('支付类型不匹配', -1);
        }

        $params['openid'] = $openId;
        $resp = $this->doPay($channel, $params);
        if ($resp['data']['failure_code'] !== "0") {
            return DataReturn($resp['data']['failure_msg'], -1);
        }

        $redirect_url = empty($params['redirect_url']) ? __MY_URL__ : $params['redirect_url'];
        switch ($channel) {
            case self::CHANNEL_WECHATPAY_NATIVE:
                $codeUrl = $resp['data']['extra']['wechatpay_native']['qr_code'];
                $codeUrl = urlencode(base64_encode($codeUrl));
                if(APPLICATION == 'app')
                {
                    $data = [
                        'qrcode_url'    => MyUrl('index/qrcode/index', ['content'=>$codeUrl]),
                        'order_no'      => $params['order_no'],
                        'name'          => '微信支付',
                        'msg'           => '打开微信APP扫一扫进行支付',
                        'check_url'     => $params['check_url'],
                    ];
                } else {
                    $pay_params = [
                        'url'       => $codeUrl,
                        'order_no'  => $params['order_no'],
                        'name'      => urlencode('微信支付'),
                        'msg'       => urlencode('打开微信APP扫一扫进行支付'),
                        'check_url' => urlencode(base64_encode($params['check_url'])),
                    ];
                    $data = MyUrl('index/pay/qrcode', $pay_params);
                }

                return DataReturn('success', 0, $data);
                break;

            case self::CHANNEL_WECHATPAY_JSAPI:
                $pay_data = $resp['data']['extra']['wechatpay_jsapi']['jsapi_config'];

                // 微信中
                if(APPLICATION == 'web' && IsWeixinEnv())
                {
                    $html = $this->PayHtml($pay_data, $redirect_url);
                    die($html);
                } else {
                    return DataReturn('success', 0, $pay_data);
                }
                break;
            case self::CHANNEL_WECHATPAY_H5:
                $redirect_url = urlencode($redirect_url);
                $redirect_url =  $resp['data']['extra']['wechatpay_h5']['pay_url']. '&redirect_url='.$redirect_url;
                return DataReturn('success', 0, $redirect_url);
                break;
            case self::CHANNEL_WECHATPAY_APP:
                $pay_data = $resp['data']['extra']['wechatpay_app']['app_config'];
                return  DataReturn('success', 0, $pay_data);
                break;

            default:
                break;
        }

        return [];
    }

    /**
     * 支付代码
     * @author   Devil
     * @blog     http://gong.gg/
     * @version  1.0.0
     * @datetime 2019-05-25T00:07:52+0800
     * @param    [array]                   $pay_data     [支付信息]
     * @param    [string]                  $redirect_url [支付结束后跳转url]
     */
    private function PayHtml($pay_data, $redirect_url)
    {
        // 支付代码
        return '<html>
            <head>
                <meta http-equiv="content-type" content="text/html;charset=utf-8"/>
                <title>微信安全支付</title>
                <meta name="apple-mobile-web-app-capable" content="yes">
                <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1, maximum-scale=1">
                <body style="text-align:center;padding-top:10%;">
                    <p style="color:#999;">正在支付中...</p>
                    <p style="color:#f00;margin-top:20px;">请不要关闭页面！</p>
                </body>
                <script type="text/javascript">
                    function onBridgeReady()
                    {
                       WeixinJSBridge.invoke(
                            \'getBrandWCPayRequest\', {
                                "appId":"'.$pay_data['appId'].'",
                                "timeStamp":"'.$pay_data['timeStamp'].'",
                                "nonceStr":"'.$pay_data['nonceStr'].'",
                                "package":"'.$pay_data['package'].'",     
                                "signType":"'.$pay_data['signType'].'",
                                "paySign":"'.$pay_data['paySign'].'"
                            },
                            function(res) {
                                window.location.href = "'.$redirect_url.'";
                            }
                        ); 
                    }
                    if(typeof WeixinJSBridge == "undefined")
                    {
                       if( document.addEventListener )
                       {
                           document.addEventListener("WeixinJSBridgeReady", onBridgeReady, false);
                       } else if (document.attachEvent)
                       {
                           document.attachEvent("WeixinJSBridgeReady", onBridgeReady); 
                           document.attachEvent("onWeixinJSBridgeReady", onBridgeReady);
                       }
                    } else {
                       onBridgeReady();
                    }
                </script>
            </head>
        </html>';
    }
}