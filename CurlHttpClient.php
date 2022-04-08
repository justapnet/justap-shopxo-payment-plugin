<?php

namespace payment;

class CurlHttpClient {
    public function send($uri, $headerOptions, $method, $body, array $options): array
    {
//        if (!extension_loaded('curl')) {
//            throw new \payment\ClientException('curl extension is not loaded.');
//        }

        $ch = curl_init();
        $options = $this->buildOptions($uri, $headerOptions, $method, $body, $options);
        curl_setopt_array($ch, $options);

        /** @var string|false $body */
        $body = $this->exec($ch);
        if ($body === false) {
            $errorCode = curl_errno($ch);
            $error = curl_error($ch);
            curl_close($ch);

            $message = "cURL Error ({$errorCode}) {$error}";
            $errorNumbers = [
                CURLE_FAILED_INIT,
                CURLE_URL_MALFORMAT,
                CURLE_URL_MALFORMAT_USER,
            ];
            if (in_array($errorCode, $errorNumbers, true)) {
                throw new \Exception($message);
            }
            throw new \Exception($message);
        }

        $responses = $this->createResponse($ch, $body);
        curl_close($ch);

        return $responses;
    }

    public function buildOptions($uri, $headerOptions, $method, $body, array $options): array
    {
        $headers = [];
        foreach ($headerOptions as $key => $values) {
            if (is_array($values)) {
                $headers[] = $key . ': ' . implode(', ', $values);
            } else {
                $headers[] = $key . ': ' . $values;
            }
        }

        $out = [
            CURLOPT_URL => (string)$uri,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER => true,
            CURLOPT_HTTPHEADER => $headers,
        ];
        switch (strtoupper($method)) {
            case 'GET':
                $out[CURLOPT_HTTPGET] = true;
                break;

            case 'POST':
                $out[CURLOPT_POST] = true;
                break;

            case 'HEAD':
                $out[CURLOPT_NOBODY] = true;
                break;

            default:
                $out[CURLOPT_POST] = true;
                $out[CURLOPT_CUSTOMREQUEST] = $method;
                break;
        }

        $out[CURLOPT_POSTFIELDS] = $body;
        // GET requests with bodies require custom request to be used.
        if ($out[CURLOPT_POSTFIELDS] !== '' && isset($out[CURLOPT_HTTPGET])) {
            $out[CURLOPT_CUSTOMREQUEST] = 'get';
        }
        if ($out[CURLOPT_POSTFIELDS] === '') {
            unset($out[CURLOPT_POSTFIELDS]);
        }

//        if (empty($options['ssl_cafile'])) {
//            $options['ssl_cafile'] = CaBundle::getBundledCaBundlePath();
//        }

        if (!empty($options['ssl_verify_host'])) {
            // Value of 1 or true is deprecated. Only 2 or 0 should be used now.
            $options['ssl_verify_host'] = 2;
        }
        $optionMap = [
            'timeout' => CURLOPT_TIMEOUT,
            'ssl_verify_peer' => CURLOPT_SSL_VERIFYPEER,
            'ssl_verify_host' => CURLOPT_SSL_VERIFYHOST,
            'ssl_cafile' => CURLOPT_CAINFO,
            'ssl_local_cert' => CURLOPT_SSLCERT,
            'ssl_passphrase' => CURLOPT_SSLCERTPASSWD,
        ];
        foreach ($optionMap as $option => $curlOpt) {
            if (isset($options[$option])) {
                $out[$curlOpt] = $options[$option];
            }
        }
        if (isset($options['proxy']['proxy'])) {
            $out[CURLOPT_PROXY] = $options['proxy']['proxy'];
        }
        if (isset($options['proxy']['username'])) {
            $password = !empty($options['proxy']['password']) ? $options['proxy']['password'] : '';
            $out[CURLOPT_PROXYUSERPWD] = $options['proxy']['username'] . ':' . $password;
        }
        if (isset($options['curl']) && is_array($options['curl'])) {
            // Can't use array_merge() because keys will be re-ordered.
            foreach ($options['curl'] as $key => $value) {
                $out[$key] = $value;
            }
        }

        return $out;
    }

    protected function createResponse($handle, $responseData): array
    {
        /** @psalm-suppress PossiblyInvalidArgument */
        $headerSize = curl_getinfo($handle, CURLINFO_HEADER_SIZE);
        $headers = trim(substr($responseData, 0, $headerSize));
        $body = substr($responseData, $headerSize);

        return [
            'headers' => explode("\r\n", $headers),
            'body' => $body
        ];
    }

    /**
     * Execute the curl handle.
     *
     * @param resource|\CurlHandle $ch Curl Resource handle
     * @return string|bool
     * @psalm-suppress UndefinedDocblockClass
     */
    protected function exec($ch)
    {
        /** @psalm-suppress PossiblyInvalidArgument */
        return curl_exec($ch);
    }
}

class ClientException extends \Exception {}
class RequestException extends \Exception {}
class NetworkException extends \Exception {}