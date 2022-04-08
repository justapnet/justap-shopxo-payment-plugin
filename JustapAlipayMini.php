<?php

namespace payment;

class JustapAlipayMini extends JustapBase {
    public function Config(): array
    {
        $config = parent::Config();
        $config['base']['name'] .= '-支付宝小程序';
        $config['base']['apply_terminal'] = ['alipay'];

        return $config;
    }

    public function Pay($params = []): array
    {
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

        if (!IsAlipayEnv()) {
            return DataReturn('没有相关支付模块['.APPLICATION_CLIENT_TYPE.']', -1);
        }

        $channel = self::CHANNEL_ALIPAY_LITE;
        $resp = $this->doPay($channel, $params);
        if ($resp['data']['failure_code'] == 0) {
            if (isset($resp['data']['extra'])
                && isset($resp['data']['extra']['alipay_lite'])
                && isset($resp['data']['extra']['alipay_lite']['trade_no'])
            ) {
                $tradeNo = $resp['data']['extra']['alipay_lite']['trade_no'];
                return DataReturn('处理成功', 0, $tradeNo);
            }
        }

        // 直接返回支付信息
        return DataReturn('下单失败', -1000);
    }
}