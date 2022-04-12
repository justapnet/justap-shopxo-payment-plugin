<?php

namespace payment;


// -----------------------------------------------------------------
// 以下代码所有开源聚合支付插件相同
// -----------------------------------------------------------------

// -----------------------------
// class CaBundleJustapWechatPay
// -----------------------------
if  (!class_exists('CaBundleJustapWechatPay')) {

    /**
     * @author Chris Smith <chris@cs278.org>
     * @author Jordi Boggiano <j.boggiano@seld.be>
     */
    class CaBundleJustapWechatPay
    {
        /** @var string|null */
        private static $caPath;
        /** @var array<string, bool> */
        private static $caFileValidity = array();
        /** @var bool|null */
        private static $useOpensslParse;

        /**
         * Returns the system CA bundle path, or a path to the bundled one
         *
         * This method was adapted from Sslurp.
         * https://github.com/EvanDotPro/Sslurp
         *
         * (c) Evan Coury <me@evancoury.com>
         *
         * For the full copyright and license information, please see below:
         *
         * Copyright (c) 2013, Evan Coury
         * All rights reserved.
         *
         * Redistribution and use in source and binary forms, with or without modification,
         * are permitted provided that the following conditions are met:
         *
         *     * Redistributions of source code must retain the above copyright notice,
         *       this list of conditions and the following disclaimer.
         *
         *     * Redistributions in binary form must reproduce the above copyright notice,
         *       this list of conditions and the following disclaimer in the documentation
         *       and/or other materials provided with the distribution.
         *
         * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
         * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
         * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
         * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
         * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
         * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
         * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
         * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
         * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
         * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
         *
         * @return string          path to a CA bundle file or directory
         */
        public static function getSystemCaRootBundlePath($logger = null)
        {
            if (self::$caPath !== null) {
                return self::$caPath;
            }
            $CaBundleJustapWechatPayPaths = array();

            // If SSL_CERT_FILE env variable points to a valid certificate/bundle, use that.
            // This mimics how OpenSSL uses the SSL_CERT_FILE env variable.
            $CaBundleJustapWechatPayPaths[] = self::getEnvVariable('SSL_CERT_FILE');

            // If SSL_CERT_DIR env variable points to a valid certificate/bundle, use that.
            // This mimics how OpenSSL uses the SSL_CERT_FILE env variable.
            $CaBundleJustapWechatPayPaths[] = self::getEnvVariable('SSL_CERT_DIR');

            $CaBundleJustapWechatPayPaths[] = ini_get('openssl.cafile');
            $CaBundleJustapWechatPayPaths[] = ini_get('openssl.capath');

            $otherLocations = array(
                '/etc/pki/tls/certs/ca-bundle.crt', // Fedora, RHEL, CentOS (ca-certificates package)
                '/etc/ssl/certs/ca-certificates.crt', // Debian, Ubuntu, Gentoo, Arch Linux (ca-certificates package)
                '/etc/ssl/ca-bundle.pem', // SUSE, openSUSE (ca-certificates package)
                '/usr/local/share/certs/ca-root-nss.crt', // FreeBSD (ca_root_nss_package)
                '/usr/ssl/certs/ca-bundle.crt', // Cygwin
                '/opt/local/share/curl/curl-ca-bundle.crt', // OS X macports, curl-ca-bundle package
                '/usr/local/share/curl/curl-ca-bundle.crt', // Default cURL CA bunde path (without --with-ca-bundle option)
                '/usr/share/ssl/certs/ca-bundle.crt', // Really old RedHat?
                '/etc/ssl/cert.pem', // OpenBSD
                '/usr/local/etc/ssl/cert.pem', // FreeBSD 10.x
                '/usr/local/etc/openssl/cert.pem', // OS X homebrew, openssl package
                '/usr/local/etc/openssl@1.1/cert.pem', // OS X homebrew, openssl@1.1 package
            );

            foreach($otherLocations as $location) {
                $otherLocations[] = dirname($location);
            }

            $CaBundleJustapWechatPayPaths = array_merge($CaBundleJustapWechatPayPaths, $otherLocations);

            foreach ($CaBundleJustapWechatPayPaths as $CaBundleJustapWechatPay) {
                if ($CaBundleJustapWechatPay && self::caFileUsable($CaBundleJustapWechatPay, $logger)) {
                    return self::$caPath = $CaBundleJustapWechatPay;
                }

                if ($CaBundleJustapWechatPay && self::caDirUsable($CaBundleJustapWechatPay, $logger)) {
                    return self::$caPath = $CaBundleJustapWechatPay;
                }
            }

            return self::$caPath = static::getBundledCaBundleJustapWechatPayPath(); // Bundled CA file, last resort
        }

        /**
         * Returns the path to the bundled CA file
         *
         * In case you don't want to trust the user or the system, you can use this directly
         *
         * @return string path to a CA bundle file
         */
        public static function getBundledCaBundleJustapWechatPayPath()
        {
            $CaBundleJustapWechatPayFile = __DIR__.'/../res/cacert.pem';

            // cURL does not understand 'phar://' paths
            // see https://github.com/composer/ca-bundle/issues/10
            if (0 === strpos($CaBundleJustapWechatPayFile, 'phar://')) {
                $tempCaBundleJustapWechatPayFile = tempnam(sys_get_temp_dir(), 'openssl-ca-bundle-');
                if (false === $tempCaBundleJustapWechatPayFile) {
                    throw new \RuntimeException('Could not create a temporary file to store the bundled CA file');
                }

                file_put_contents(
                    $tempCaBundleJustapWechatPayFile,
                    file_get_contents($CaBundleJustapWechatPayFile)
                );

                register_shutdown_function(function() use ($tempCaBundleJustapWechatPayFile) {
                    @unlink($tempCaBundleJustapWechatPayFile);
                });

                $CaBundleJustapWechatPayFile = $tempCaBundleJustapWechatPayFile;
            }

            return $CaBundleJustapWechatPayFile;
        }

        /**
         * Validates a CA file using opensl_x509_parse only if it is safe to use
         *
         * @param string          $filename
         *
         * @return bool
         */
        public static function validateCaFile($filename, $logger = null)
        {
            static $warned = false;

            if (isset(self::$caFileValidity[$filename])) {
                return self::$caFileValidity[$filename];
            }

            $contents = file_get_contents($filename);

            // assume the CA is valid if php is vulnerable to
            // https://www.sektioneins.de/advisories/advisory-012013-php-openssl_x509_parse-memory-corruption-vulnerability.html
            if (!static::isOpensslParseSafe()) {
                if (!$warned && $logger) {
                    $logger->warning(sprintf(
                        'Your version of PHP, %s, is affected by CVE-2013-6420 and cannot safely perform certificate validation, we strongly suggest you upgrade.',
                        PHP_VERSION
                    ));
                    $warned = true;
                }

                $isValid = !empty($contents);
            } elseif (is_string($contents) && strlen($contents) > 0) {
                $contents = preg_replace("/^(\\-+(?:BEGIN|END))\\s+TRUSTED\\s+(CERTIFICATE\\-+)\$/m", '$1 $2', $contents);
                if (null === $contents) {
                    // regex extraction failed
                    $isValid = false;
                } else {
                    $isValid = (bool) openssl_x509_parse($contents);
                }
            } else {
                $isValid = false;
            }

            if ($logger) {
                $logger->debug('Checked CA file '.realpath($filename).': '.($isValid ? 'valid' : 'invalid'));
            }

            return self::$caFileValidity[$filename] = $isValid;
        }

        /**
         * Test if it is safe to use the PHP function openssl_x509_parse().
         *
         * This checks if OpenSSL extensions is vulnerable to remote code execution
         * via the exploit documented as CVE-2013-6420.
         *
         * @return bool
         */
        public static function isOpensslParseSafe()
        {
            if (null !== self::$useOpensslParse) {
                return self::$useOpensslParse;
            }

            if (PHP_VERSION_ID >= 50600) {
                return self::$useOpensslParse = true;
            }

            // Vulnerable:
            // PHP 5.3.0 - PHP 5.3.27
            // PHP 5.4.0 - PHP 5.4.22
            // PHP 5.5.0 - PHP 5.5.6
            if (
                (PHP_VERSION_ID < 50400 && PHP_VERSION_ID >= 50328)
                || (PHP_VERSION_ID < 50500 && PHP_VERSION_ID >= 50423)
                || PHP_VERSION_ID >= 50507
            ) {
                // This version of PHP has the fix for CVE-2013-6420 applied.
                return self::$useOpensslParse = true;
            }

            if (defined('PHP_WINDOWS_VERSION_BUILD')) {
                // Windows is probably insecure in this case.
                return self::$useOpensslParse = false;
            }

            $compareDistroVersionPrefix = function ($prefix, $fixedVersion) {
                $regex = '{^'.preg_quote($prefix).'([0-9]+)$}';

                if (preg_match($regex, PHP_VERSION, $m)) {
                    return ((int) $m[1]) >= $fixedVersion;
                }

                return false;
            };

            // Hard coded list of PHP distributions with the fix backported.
            if (
                $compareDistroVersionPrefix('5.3.3-7+squeeze', 18) // Debian 6 (Squeeze)
                || $compareDistroVersionPrefix('5.4.4-14+deb7u', 7) // Debian 7 (Wheezy)
                || $compareDistroVersionPrefix('5.3.10-1ubuntu3.', 9) // Ubuntu 12.04 (Precise)
            ) {
                return self::$useOpensslParse = true;
            }

            // Symfony Process component is missing so we assume it is unsafe at this point
            return self::$useOpensslParse = false;

            // This is where things get crazy, because distros backport security
            // fixes the chances are on NIX systems the fix has been applied but
            // it's not possible to verify that from the PHP version.
            //
            // To verify exec a new PHP process and run the issue testcase with
            // known safe input that replicates the bug.

            // Based on testcase in https://github.com/php/php-src/commit/c1224573c773b6845e83505f717fbf820fc18415
            // changes in https://github.com/php/php-src/commit/76a7fd893b7d6101300cc656058704a73254d593
            $cert = 'LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUVwRENDQTR5Z0F3SUJBZ0lKQUp6dThyNnU2ZUJjTUEwR0NTcUdTSWIzRFFFQkJRVUFNSUhETVFzd0NRWUQKVlFRR0V3SkVSVEVjTUJvR0ExVUVDQXdUVG05eVpISm9aV2x1TFZkbGMzUm1ZV3hsYmpFUU1BNEdBMVVFQnd3SApTOE9Ed3Jac2JqRVVNQklHQTFVRUNnd0xVMlZyZEdsdmJrVnBibk14SHpBZEJnTlZCQXNNRmsxaGJHbGphVzkxCmN5QkRaWEowSUZObFkzUnBiMjR4SVRBZkJnTlZCQU1NR0cxaGJHbGphVzkxY3k1elpXdDBhVzl1WldsdWN5NWsKWlRFcU1DZ0dDU3FHU0liM0RRRUpBUlliYzNSbFptRnVMbVZ6YzJWeVFITmxhM1JwYjI1bGFXNXpMbVJsTUhVWQpaREU1TnpBd01UQXhNREF3TURBd1dnQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBCkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEKQUFBQUFBQVhEVEUwTVRFeU9ERXhNemt6TlZvd2djTXhDekFKQmdOVkJBWVRBa1JGTVJ3d0dnWURWUVFJREJOTwpiM0prY21obGFXNHRWMlZ6ZEdaaGJHVnVNUkF3RGdZRFZRUUhEQWRMdzRQQ3RteHVNUlF3RWdZRFZRUUtEQXRUClpXdDBhVzl1UldsdWN6RWZNQjBHQTFVRUN3d1dUV0ZzYVdOcGIzVnpJRU5sY25RZ1UyVmpkR2x2YmpFaE1COEcKQTFVRUF3d1liV0ZzYVdOcGIzVnpMbk5sYTNScGIyNWxhVzV6TG1SbE1Tb3dLQVlKS29aSWh2Y05BUWtCRmh0egpkR1ZtWVc0dVpYTnpaWEpBYzJWcmRHbHZibVZwYm5NdVpHVXdnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCCkR3QXdnZ0VLQW9JQkFRRERBZjNobDdKWTBYY0ZuaXlFSnBTU0RxbjBPcUJyNlFQNjV1c0pQUnQvOFBhRG9xQnUKd0VZVC9OYSs2ZnNnUGpDMHVLOURaZ1dnMnRIV1dvYW5TYmxBTW96NVBINlorUzRTSFJaN2UyZERJalBqZGhqaAowbUxnMlVNTzV5cDBWNzk3R2dzOWxOdDZKUmZIODFNTjJvYlhXczROdHp0TE11RDZlZ3FwcjhkRGJyMzRhT3M4CnBrZHVpNVVhd1Raa3N5NXBMUEhxNWNNaEZHbTA2djY1Q0xvMFYyUGQ5K0tBb2tQclBjTjVLTEtlYno3bUxwazYKU01lRVhPS1A0aWRFcXh5UTdPN2ZCdUhNZWRzUWh1K3ByWTNzaTNCVXlLZlF0UDVDWm5YMmJwMHdLSHhYMTJEWAoxbmZGSXQ5RGJHdkhUY3lPdU4rblpMUEJtM3ZXeG50eUlJdlZBZ01CQUFHalFqQkFNQWtHQTFVZEV3UUNNQUF3CkVRWUpZSVpJQVliNFFnRUJCQVFEQWdlQU1Bc0dBMVVkRHdRRUF3SUZvREFUQmdOVkhTVUVEREFLQmdnckJnRUYKQlFjREFqQU5CZ2txaGtpRzl3MEJBUVVGQUFPQ0FRRUFHMGZaWVlDVGJkajFYWWMrMVNub2FQUit2SThDOENhRAo4KzBVWWhkbnlVNGdnYTBCQWNEclk5ZTk0ZUVBdTZacXljRjZGakxxWFhkQWJvcHBXb2NyNlQ2R0QxeDMzQ2tsClZBcnpHL0t4UW9oR0QySmVxa2hJTWxEb214SE83a2EzOStPYThpMnZXTFZ5alU4QVp2V01BcnVIYTRFRU55RzcKbFcyQWFnYUZLRkNyOVRuWFRmcmR4R1ZFYnY3S1ZRNmJkaGc1cDVTanBXSDErTXEwM3VSM1pYUEJZZHlWODMxOQpvMGxWajFLRkkyRENML2xpV2lzSlJvb2YrMWNSMzVDdGQwd1lCY3BCNlRac2xNY09QbDc2ZHdLd0pnZUpvMlFnClpzZm1jMnZDMS9xT2xOdU5xLzBUenprVkd2OEVUVDNDZ2FVK1VYZTRYT1Z2a2NjZWJKbjJkZz09Ci0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K';
            $script = <<<'EOT'

error_reporting(-1);
$info = openssl_x509_parse(base64_decode('%s'));
var_dump(PHP_VERSION, $info['issuer']['emailAddress'], $info['validFrom_time_t']);

EOT;
            $script = '<'."?php\n".sprintf($script, $cert);

            return self::$useOpensslParse = false;

            $output = preg_split('{\r?\n}', trim($process->getOutput()));
            $errorOutput = trim($process->getErrorOutput());

            if (
                is_array($output)
                && count($output) === 3
                && $output[0] === sprintf('string(%d) "%s"', strlen(PHP_VERSION), PHP_VERSION)
                && $output[1] === 'string(27) "stefan.esser@sektioneins.de"'
                && $output[2] === 'int(-1)'
                && preg_match('{openssl_x509_parse\(\): illegal (?:ASN1 data type for|length in) timestamp in - on line \d+}', $errorOutput)
            ) {
                // This PHP has the fix backported probably by a distro security team.
                return self::$useOpensslParse = true;
            }

            return self::$useOpensslParse = false;
        }

        /**
         * Resets the static caches
         * @return void
         */
        public static function reset()
        {
            self::$caFileValidity = array();
            self::$caPath = null;
            self::$useOpensslParse = null;
        }

        /**
         * @param  string $name
         * @return string|false
         */
        private static function getEnvVariable($name)
        {
            if (isset($_SERVER[$name])) {
                return (string) $_SERVER[$name];
            }

            if (PHP_SAPI === 'cli' && ($value = getenv($name)) !== false && $value !== null) {
                return (string) $value;
            }

            return false;
        }

        /**
         * @param  string|false $certFile
         * @return bool
         */
        private static function caFileUsable($certFile, $logger = null)
        {
            return $certFile
                && static::isFile($certFile, $logger)
                && static::isReadable($certFile, $logger)
                && static::validateCaFile($certFile, $logger);
        }

        /**
         * @param  string|false $certDir
         * @return bool
         */
        private static function caDirUsable($certDir, $logger = null)
        {
            return $certDir
                && static::isDir($certDir, $logger)
                && static::isReadable($certDir, $logger)
                && static::glob($certDir . '/*', $logger);
        }

        /**
         * @param  string $certFile
         * @return bool
         */
        private static function isFile($certFile, $logger = null)
        {
            $isFile = @is_file($certFile);
            if (!$isFile && $logger) {
                $logger->debug(sprintf('Checked CA file %s does not exist or it is not a file.', $certFile));
            }

            return $isFile;
        }

        /**
         * @param  string $certDir
         * @return bool
         */
        private static function isDir($certDir, $logger = null)
        {
            $isDir = @is_dir($certDir);
            if (!$isDir && $logger) {
                $logger->debug(sprintf('Checked directory %s does not exist or it is not a directory.', $certDir));
            }

            return $isDir;
        }

        /**
         * @param  string $certFileOrDir
         * @return bool
         */
        private static function isReadable($certFileOrDir, $logger = null)
        {
            $isReadable = @is_readable($certFileOrDir);
            if (!$isReadable && $logger) {
                $logger->debug(sprintf('Checked file or directory %s is not readable.', $certFileOrDir));
            }

            return $isReadable;
        }

        /**
         * @param  string $pattern
         * @return bool
         */
        private static function glob($pattern, $logger = null)
        {
            $certs = glob($pattern);
            if ($certs === false) {
                if ($logger) {
                    $logger->debug(sprintf("An error occurred while trying to find certificates for pattern: %s", $pattern));
                }
                return false;
            }

            if (count($certs) === 0) {
                if ($logger) {
                    $logger->debug(sprintf("No CA files found for pattern: %s", $pattern));
                }
                return false;
            }

            return true;
        }
    }
}

// -----------------------------
// class CurlHttpClientJustapWechatPay
// -----------------------------
if  (!class_exists('CurlHttpClientJustapWechatPay')) {
    class CurlHttpClientJustapWechatPay {
        public function send($uri, $headerOptions, $method, $body, array $options): array
        {
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
//            $options['ssl_cafile'] = CaBundleJustapWechatPay::getBundledCaBundleJustapWechatPayPath();
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
}

// ------------------------------
// class JustapBaseJustapWechatPay
// ------------------------------
if (!class_exists('JustapBaseJustapWechatPay')) {
    class JustapBaseJustapWechatPay {
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
            $server = JustapConfigurationJustapWechatPay::getDefaultConfiguration();
            $server->setApiKey($this->config['justap_secret_key']);
            $server->setHost('https://trade.justap.cn');
            $server->setPrivateKey($this->config['justap_merchant_private_key']);
            $server->setUserAgent('justap-php-sdk/shopxo');
            $sdk = new JustapSdkJustapWechatPay();
            $sdk->setConfig($server);
            $sdk->setClient(new CurlHttpClientJustapWechatPay());
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
                'version'       => 'v1.3.0',  // 插件版本
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

                $decrypted = DecryptRsaJustapWechatPay($this->config['justap_public_key'], $data['data']);
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
            throw new \Exception('支付失败');
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
}

if (!function_exists('EncryptRsaJustapWechatPay')) {
    function EncryptRsaJustapWechatPay($plainData, $privatePEMKey)
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
}

if (!function_exists('DecryptRsaJustapWechatPay')) {
    function DecryptRsaJustapWechatPay($publicPEMKey, $data)
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
}

if  (!class_exists('JustapConfigurationJustapWechatPay')) {

    class JustapConfigurationJustapWechatPay {
        private static $defaultConfiguration;
        private $privateKey;
        protected $apiKeys = '';
        protected $accessToken = '';
        protected $username = '';
        protected $password = '';
        protected $host = 'https://trade.justap.cn';
        protected $userAgent = 'Swagger-Codegen/1.0.0/php';

        /**
         * Debug switch (default set to false)
         *
         * @var bool
         */
        protected $debug = false;

        /**
         * Debug file location (log to STDOUT by default)
         *
         * @var string
         */
        protected $debugFile = 'php://output';

        /**
         * Debug file location (log to STDOUT by default)
         *
         * @var string
         */
        protected $tempFolderPath;

        /**
         * Constructor
         */
        public function __construct()
        {
            $this->tempFolderPath = sys_get_temp_dir();
        }

        public function setPrivateKey($content)
        {
            $this->privateKey = $this->formatRsaPrivateKey($content);
            return $this;
        }

        function formatRsaPrivateKey($rsaPrivateKey)
        {
            $rsaPrivateKey = str_replace('-----BEGIN RSA PRIVATE KEY-----', '', $rsaPrivateKey);
            $rsaPrivateKey = trim(str_replace('-----END RSA PRIVATE KEY-----', '', $rsaPrivateKey));
            $rsaPrivateKey = str_replace("\n", '', $rsaPrivateKey);

            $privateKey = "-----BEGIN RSA PRIVATE KEY-----\n" . wordwrap($rsaPrivateKey, 64, "\n", true) . "\n-----END RSA PRIVATE KEY-----\n";
            return $privateKey;
        }

        public function getPrivateKey()
        {
            return isset($this->privateKey) ? $this->privateKey : null;
        }

        public function setApiKey($key)
        {
            $this->apiKeys = $key;
            return $this;
        }

        public function getApiKey()
        {
            return $this->apiKeys;
        }

        public function setAccessToken($accessToken)
        {
            $this->accessToken = $accessToken;
            return $this;
        }

        public function getAccessToken()
        {
            return $this->accessToken;
        }

        public function setUsername($username)
        {
            $this->username = $username;
            return $this;
        }

        public function getUsername()
        {
            return $this->username;
        }

        public function setPassword($password)
        {
            $this->password = $password;
            return $this;
        }

        public function getPassword()
        {
            return $this->password;
        }

        public function setHost($host)
        {
            $this->host = $host;
            return $this;
        }

        public function getHost()
        {
            return rtrim($this->host, "/");
        }

        public function setUserAgent($userAgent)
        {
            $this->userAgent = $userAgent;
            return $this;
        }

        public function getUserAgent()
        {
            return $this->userAgent;
        }

        public function setDebug($debug)
        {
            $this->debug = $debug;
            return $this;
        }

        public function getDebug()
        {
            return $this->debug;
        }

        public function setDebugFile($debugFile)
        {
            $this->debugFile = $debugFile;
            return $this;
        }

        public function getDebugFile()
        {
            return $this->debugFile;
        }

        public function setTempFolderPath($tempFolderPath)
        {
            $this->tempFolderPath = $tempFolderPath;
            return $this;
        }

        public function getTempFolderPath()
        {
            return $this->tempFolderPath;
        }

        public static function getDefaultConfiguration(): JustapConfigurationJustapWechatPay
        {
            if (self::$defaultConfiguration === null) {
                self::$defaultConfiguration = new JustapConfigurationJustapWechatPay();
            }

            return self::$defaultConfiguration;
        }

        public static function setDefaultConfiguration(JustapConfigurationJustapWechatPay $config)
        {
            self::$defaultConfiguration = $config;
        }

        /**
         * Gets the essential information for debugging
         *
         * @return string The report for debugging
         */
        public static function toDebugReport()
        {
            $report  = 'PHP SDK (Justapnet\Justap) Debug Report:' . PHP_EOL;
            $report .= '    OS: ' . php_uname() . PHP_EOL;
            $report .= '    PHP Version: ' . PHP_VERSION . PHP_EOL;
            $report .= '    OpenAPI Spec Version: 1.0' . PHP_EOL;
            $report .= '    Temp Folder Path: ' . self::getDefaultConfiguration()->getTempFolderPath() . PHP_EOL;

            return $report;
        }
    }
}

if (!class_exists('JustapSdkJustapWechatPay')) {
    class JustapSdkJustapWechatPay {
        private $conf;
        private $httpClient;

        public function setConfig(JustapConfigurationJustapWechatPay $conf) {
            $this->conf = $conf;
        }

        public function setClient(CurlHttpClientJustapWechatPay $client) {
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
}
// --------------------------------------------------------------------------------
// end
// --------------------------------------------------------------------------------



class JustapWechatPay extends JustapBaseJustapWechatPay {
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

        dd(APPLICATION_CLIENT_TYPE, IsWeixinEnv(), $params['user']);

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

        dd(APPLICATION_CLIENT_TYPE, IsWeixinEnv());
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
