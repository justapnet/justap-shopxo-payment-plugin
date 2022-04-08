<?php
namespace payment;

class JustapAlipay extends JustapBase {
    public function Config(): array
    {
        $config = parent::Config();
        $config['base']['name'] .= '-支付宝';
        $config['base']['apply_terminal'] = ['pc', 'h5', 'ios', 'android'];
        return $config;
    }

    public function Pay($params = []): array
    {
        if(empty($params)) {
            return DataReturn('参数不能为空', -1);
        }

        if(empty($this->config)) {
            return DataReturn('支付缺少配置', -1);
        }

        $channel = '';
        switch(APPLICATION_CLIENT_TYPE) {
            case 'pc' :
            case 'h5' :
                if(IsMobile())
                {
                    $channel = self::CHANNEL_ALIPAY_WAP;
                } else {
                    $channel = self::CHANNEL_ALIPAY_PAGE;
                }

                $resp = $this->doPay($channel, $params);
                if ($resp['data']['failure_code'] == 0) {
                    if (isset($resp['data']['extra']) && isset($resp['data']['extra']['alipay_page']) && isset($resp['data']['extra']['alipay_page']['pay_url'])) {
                        $payUrl = $resp['data']['extra']['alipay_page']['pay_url'];
                        return DataReturn('success', 0, $payUrl);
                    }
                }

                return DataReturn('下单失败['.APPLICATION_CLIENT_TYPE.'], '. $resp['data']['failure_msg'], -1);
                break;

            // 指的是app支付
            case 'ios' :
            case 'android' :
                $channel = self::CHANNEL_ALIPAY_APP;
                $resp = $this->doPay($channel, $params);
                if ($resp['data']['failure_code'] == 0) {
                    if (isset($resp['data']['extra']) && isset($resp['data']['extra']['alipay_app']) && isset($resp['data']['extra']['alipay_app']['pay_param'])) {
                        $payParam = $resp['data']['extra']['alipay_page']['pay_param'];
                        return DataReturn('success', 0, $payParam);
                    }
                }
                return DataReturn('下单失败['.APPLICATION_CLIENT_TYPE.'], '. $resp['data']['failure_msg'], -1);
                break;

            default :
                return DataReturn('没有相关支付模块['.APPLICATION_CLIENT_TYPE.']', -1);
        }

        return DataReturn('没有相关支付模块['.APPLICATION_CLIENT_TYPE.']', -1);
    }
}