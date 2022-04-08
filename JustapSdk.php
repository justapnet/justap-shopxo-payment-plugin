<?php

namespace payment;

class JustapSdk {
    private $conf;
    private $httpClient;

    public function setConfig(JustapConfiguration $conf) {
        $this->conf = $conf;
    }

    public function setClient(CurlHttpClient $client) {
        $this->httpClient = $client;
    }

    public function createCharge($params) {
        $headers = ['Content-Type' => 'application/json'];
        $this->genSign($params, $headers);
        $uri = $this->conf->getHost().'/transaction/v1/charges';
        $httpBody = json_encode($params);
        return $this->httpClient->send($uri, $headers, 'post', $httpBody, []);
    }

    public function genSign($params, &$headers = []) {
        $httpBody = json_encode($params);
        $requestTime = time();
        $nonceStr = $this->rand_chars(20);
        $bodyMd5 = md5($httpBody . $requestTime . $nonceStr);
        $dataToBeSign = $bodyMd5 . $nonceStr;
        try {
            $signResult = openssl_sign($dataToBeSign, $requestSignature, $this->conf->getPrivateKey(), 'sha256');
        } catch (\Throwable $e) {
            exit($e->getMessage());
            throw new \Exception("Justapay Plugin Err: Generate signature failed");
        }

        if (!$signResult) {
            throw new \Exception("Justapay Plugin Err: Generate signature failed");
        }

        $headers = array_merge($headers, [
            'X-Justap-Api-Key' => $this->conf->getApiKey(),
            'X-Justap-Signature' =>  base64_encode($requestSignature),
            'X-Justap-Request-Time' => $requestTime,
            'X-Justap-Nonce' => $nonceStr,
            'X-Justap-Body-Hash' => $bodyMd5,
        ]);
    }

    function rand_chars($n)
    {
        $characters = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $randomString = '';

        for ($i = 0; $i < $n; $i++) {
            $index = rand(0, strlen($characters) - 1);
            $randomString .= $characters[$index];
        }

        return $randomString;
    }
}
