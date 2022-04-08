<?php

namespace payment;

class JustapConfiguration {
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

    public static function getDefaultConfiguration(): JustapConfiguration
    {
        if (self::$defaultConfiguration === null) {
            self::$defaultConfiguration = new JustapConfiguration();
        }

        return self::$defaultConfiguration;
    }

    public static function setDefaultConfiguration(JustapConfiguration $config)
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
