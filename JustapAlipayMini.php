<?php

namespace payment;


// -----------------------------------------------------------------
// 以下代码所有开源聚合支付插件相同
// -----------------------------------------------------------------

// -----------------------------
// class CaBundleJustapAlipayMini
// -----------------------------
if  (!class_exists('CaBundleJustapAlipayMini')) {

    /**
     * @author Chris Smith <chris@cs278.org>
     * @author Jordi Boggiano <j.boggiano@seld.be>
     */
    class CaBundleJustapAlipayMini
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
            $CaBundleJustapAlipayMiniPaths = array();

            // If SSL_CERT_FILE env variable points to a valid certificate/bundle, use that.
            // This mimics how OpenSSL uses the SSL_CERT_FILE env variable.
            $CaBundleJustapAlipayMiniPaths[] = self::getEnvVariable('SSL_CERT_FILE');

            // If SSL_CERT_DIR env variable points to a valid certificate/bundle, use that.
            // This mimics how OpenSSL uses the SSL_CERT_FILE env variable.
            $CaBundleJustapAlipayMiniPaths[] = self::getEnvVariable('SSL_CERT_DIR');

            $CaBundleJustapAlipayMiniPaths[] = ini_get('openssl.cafile');
            $CaBundleJustapAlipayMiniPaths[] = ini_get('openssl.capath');

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

            $CaBundleJustapAlipayMiniPaths = array_merge($CaBundleJustapAlipayMiniPaths, $otherLocations);

            foreach ($CaBundleJustapAlipayMiniPaths as $CaBundleJustapAlipayMini) {
                if ($CaBundleJustapAlipayMini && self::caFileUsable($CaBundleJustapAlipayMini, $logger)) {
                    return self::$caPath = $CaBundleJustapAlipayMini;
                }

                if ($CaBundleJustapAlipayMini && self::caDirUsable($CaBundleJustapAlipayMini, $logger)) {
                    return self::$caPath = $CaBundleJustapAlipayMini;
                }
            }

            return self::$caPath = static::getBundledCaBundleJustapAlipayMiniPath(); // Bundled CA file, last resort
        }

        /**
         * Returns the path to the bundled CA file
         *
         * In case you don't want to trust the user or the system, you can use this directly
         *
         * @return string path to a CA bundle file
         */
        public static function getBundledCaBundleJustapAlipayMiniPath()
        {
            $CaBundleJustapAlipayMiniFile = __DIR__.'/../res/cacert.pem';

            // cURL does not understand 'phar://' paths
            // see https://github.com/composer/ca-bundle/issues/10
            if (0 === strpos($CaBundleJustapAlipayMiniFile, 'phar://')) {
                $tempCaBundleJustapAlipayMiniFile = tempnam(sys_get_temp_dir(), 'openssl-ca-bundle-');
                if (false === $tempCaBundleJustapAlipayMiniFile) {
                    throw new \RuntimeException('Could not create a temporary file to store the bundled CA file');
                }

                file_put_contents(
                    $tempCaBundleJustapAlipayMiniFile,
                    file_get_contents($CaBundleJustapAlipayMiniFile)
                );

                register_shutdown_function(function() use ($tempCaBundleJustapAlipayMiniFile) {
                    @unlink($tempCaBundleJustapAlipayMiniFile);
                });

                $CaBundleJustapAlipayMiniFile = $tempCaBundleJustapAlipayMiniFile;
            }

            return $CaBundleJustapAlipayMiniFile;
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
// class CurlHttpClientJustapAlipayMini
// -----------------------------
if  (!class_exists('CurlHttpClientJustapAlipayMini')) {
    class CurlHttpClientJustapAlipayMini {
        public function send($uri, $headerOptions, $method, $body, array $options): array
        {
            $ch = curl_init();
            $options = $this->buildOptions($uri, $headerOptions, $method, $body, $options);
            curl_setopt_array($ch, $options);
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

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

        public function get($uri, $headers) {
            $headerOptions = [];
            foreach ($headers as $key => $values) {
                if (is_array($values)) {
                    $headerOptions[] = $key . ': ' . implode(', ', $values);
                } else {
                    $headerOptions[] = $key . ': ' . $values;
                }
            }

            $ch = curl_init();
            curl_setopt_array($ch, array(
                CURLOPT_URL => $uri,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_HEADER => true,
                CURLOPT_ENCODING => '',
                CURLOPT_MAXREDIRS => 10,
                CURLOPT_TIMEOUT => 0,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_CUSTOMREQUEST => 'GET',
                CURLOPT_HTTPHEADER => $headerOptions,
            ));
            curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);

            $body = curl_exec($ch);
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

            $response = $this->createResponse($ch, $body);
            curl_close($ch);

            return $response;
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

            $out[CURLOPT_SSL_VERIFYHOST] = false;
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
// class JustapBaseJustapAlipayMini
// ------------------------------
if (!class_exists('JustapBaseJustapAlipayMini')) {
    class JustapBaseJustapAlipayMini {
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
            $server = JustapConfigurationJustapAlipayMini::getDefaultConfiguration();
            $server->setApiKey($this->config['justap_secret_key']);
            $server->setHost('https://trade.justap.cn');
            $server->setPrivateKey($this->config['justap_merchant_private_key']);
            $server->setUserAgent('justap-php-sdk/shopxo');
            $sdk = new JustapSdkJustapAlipayMini();
            $sdk->setConfig($server);
            $sdk->setClient(new CurlHttpClientJustapAlipayMini());
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
                    $resp = $this->client->createCharge($creatChargeParams);
                    break;
                case self::CHANNEL_WECHATPAY_APP:
                    $creatChargeParams['extra'] = [
                        'wechatpay_app' => new \stdClass()
                    ];
                    $resp = $this->client->createCharge($creatChargeParams);
                    break;
                case self::CHANNEL_WECHATPAY_H5:
                    $creatChargeParams['extra'] = [
                        'wechatpay_h5' => new \stdClass()
                    ];
                    $resp = $this->client->createCharge($creatChargeParams);
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
                    $resp = $this->client->createCharge($creatChargeParams);
                    break;
                case self::CHANNEL_WECHATPAY_JSAPI:
                    $creatChargeParams['extra'] = [
                        'wechatpay_jsapi' => [
                            'payer' => [
                                'openid' => $params['openid'],
                            ]
                        ]
                    ];
                    $resp = $this->client->createCharge($creatChargeParams);
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
                'version'       => 'v1.4.0',  // 插件版本
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

                $decrypted = DecryptRsaJustapAlipayMini($this->config['justap_public_key'], $data['data']);
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

            return DataReturn('未知的状态', -1);
        }

        public function Refund($params = []) {
            // 参数
            $p = [
                [
                    'checked_type'      => 'empty',
                    'key_name'          => 'order_no',
                    'error_msg'         => '订单号不能为空',
                ],
                [
                    'checked_type'      => 'empty',
                    'key_name'          => 'trade_no',
                    'error_msg'         => '交易平台订单号不能为空',
                ],
                [
                    'checked_type'      => 'empty',
                    'key_name'          => 'refund_price',
                    'error_msg'         => '退款金额不能为空',
                ],
            ];
            $ret = ParamsChecked($params, $p);
            if($ret !== true)
            {
                return DataReturn($ret, -1);
            }

            // 退款原因
            $refund_reason = empty($params['refund_reason']) ? $params['order_no'].'订单退款'.$params['refund_price'].'元' : $params['refund_reason'];

            $chargeId = $params['trade_no'];
            $this->initSdk();
            $createRefundParams = [
                'charge_id' => $chargeId,
                'app_id' => $this->config['justap_app_id'],
                'description' => $refund_reason,
                'merchant_refund_id' => $params['order_no'],
                'amount' => $params['refund_price']
            ];

            $resp = $this->client->createRefund($createRefundParams);

            if (empty($resp) || !isset($resp['headers']) || count($resp['headers']) < 0) {
                return DataReturn('支付平台下单失败', -1);
            }

            if (strpos($resp['headers'][0], '200') < 0) {
                return DataReturn('支付接口下单失败', -1);
            }

            $body = json_decode($resp['body'], true);
            if (isset($body['code']) && $body['code'] != 0) {
                throw new \Exception($body['message']);
            }

            if ($body['data']['refund_id']) {
                return DataReturn('退款成功', 0, [
                    'out_trade_no' => $body['data']['charge_merchant_trade_id'],
                    'trade_no' => $chargeId,
                    'buyer_user' => '',
                    'refund_price' => $body['data']['amount'],
                    'return_params' => [],
                ]);
            }

            if (strtolower($body['data']['status']) == 'refunding') {
                // todo 临时的做法
                return DataReturn('退款成功，可前往支付平台进一步确认结果', 0, [
                    'out_trade_no' => $body['data']['charge_merchant_trade_id'],
                    'trade_no' => $chargeId,
                    'buyer_user' => '',
                    'refund_price' => $body['data']['amount'],
                    'return_params' => [],
                ]);


                if (!$body['data']['is_success']) {
                    // 请求退款成功，
                    // 需要查询退款结果 4 次
                    for ($i = 0; $i <= 3; $i++) {
                        $queryResp = $this->client->queryRefund([
                            'charge_id' => $chargeId,
                            'refund_id' => $body['data']['refund_id'],
                            'app_id' => $this->config['justap_app_id']
                        ]);

                        if (empty($queryResp) || !isset($queryResp['headers']) || count($queryResp['headers']) < 0) {
                            return DataReturn('请求退款成功但查询结果失败，建议前往支付平台确认', -1);
                        }

                        if (strpos($queryResp['headers'][0], '200') < 0) {
                            return DataReturn('请求退款成功但查询结果失败，建议前往支付平台确认', -1);
                        }

                        $refundQueryBody = json_decode($queryResp['body'], true);

                        if (isset($refundQueryBody['code']) && $refundQueryBody['code'] != 0) {
                            return DataReturn('请求退款成功但查询结果失败，建议前往支付平台确认', -1);
                        }

                        if ($refundQueryBody['data']['is_success'] && strtolower($refundQueryBody['data']['status']) == 'refunded') {
                            return DataReturn('退款成功', 0, [
                                'out_trade_no' => $refundQueryBody['data']['charge_merchant_trade_id'],
                                'trade_no' => $chargeId,
                                'buyer_user' => '',
                                'refund_price' => $refundQueryBody['data']['amount'],
                                'return_params' => [],
                            ]);
                        }

                        sleep(2);
                    }
                }

                return DataReturn('退款请求正在处理中，结果请稍后进入支付平台查询', -1);
            }

            return DataReturn('请求退求失败，请进入支付平台查询', -1);
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
            $data['trade_no']       = $data['charge_id'];        // 支付平台 - 订单号
            $data['buyer_user']     = "";       // 支付平台 - 用户
            $data['out_trade_no']   = $data['merchant_trade_id'];    // 本系统发起支付的 - 订单号
            $data['subject']        = ''; // 本系统发起支付的 - 商品名称
            $data['pay_price']      = $data['amount_total'];    // 本系统发起支付的 - 总价

            return $data;
        }
    }
}

if (!function_exists('EncryptRsaJustapAlipayMini')) {
    function EncryptRsaJustapAlipayMini($plainData, $privatePEMKey)
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

if (!function_exists('DecryptRsaJustapAlipayMini')) {
    function DecryptRsaJustapAlipayMini($publicPEMKey, $data)
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

if  (!class_exists('JustapConfigurationJustapAlipayMini')) {

    class JustapConfigurationJustapAlipayMini {
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

        public static function getDefaultConfiguration(): JustapConfigurationJustapAlipayMini
        {
            if (self::$defaultConfiguration === null) {
                self::$defaultConfiguration = new JustapConfigurationJustapAlipayMini();
            }

            return self::$defaultConfiguration;
        }

        public static function setDefaultConfiguration(JustapConfigurationJustapAlipayMini $config)
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

if (!class_exists('JustapSdkJustapAlipayMini')) {
    class JustapSdkJustapAlipayMini {
        private $conf;
        private $httpClient;

        public function setConfig(JustapConfigurationJustapAlipayMini $conf) {
            $this->conf = $conf;
        }

        public function setClient(CurlHttpClientJustapAlipayMini $client) {
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

        function createRefund($params) {
            $headers = ['Content-Type' => 'application/json'];
            $this->genSign($params, $headers);
            $uri = $this->conf->getHost().'/transaction/v1/refunds';

            $httpBody = json_encode($params);
            return $this->httpClient->send($uri, $headers, 'post', $httpBody, []);
        }

        function queryRefund($params) {
            $headers = ['Content-Type' => 'application/json', 'Accept' => 'application/json'];
            $this->genSign($params, $headers, 'get');
            $uri = $this->conf->getHost().'/transaction/v1/charges/'. $params['charge_id'] .'/refunds/'. $params['refund_id'].'?app_id='.$params['app_id'];
            
            return $this->httpClient->get($uri, $headers);
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


class JustapAlipayMini extends JustapBaseJustapAlipayMini {
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
