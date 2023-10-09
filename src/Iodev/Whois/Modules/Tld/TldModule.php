<?php

declare(strict_types=1);

namespace Iodev\Whois\Modules\Tld;

use Iodev\Whois\Exceptions\ConnectionException;
use Iodev\Whois\Exceptions\ServerMismatchException;
use Iodev\Whois\Exceptions\WhoisException;
use Iodev\Whois\Helpers\DomainHelper;
use Iodev\Whois\Loaders\ILoader;
use Iodev\Whois\Modules\Module;
use Iodev\Whois\Modules\ModuleType;

class TldModule extends Module
{
    /**
     * @param ILoader $loader
     */
    public function __construct(ILoader $loader)
    {
        parent::__construct(ModuleType::TLD, $loader);
    }

    /** @var TldServer[] */
    protected $servers = [];

    /** @var TldServer[] */
    protected $lastUsedServers = [];

    /**
     * @return TldServer[]
     */
    public function getServers()
    {
        return $this->servers;
    }

    /**
     * @return TldServer[]
     */
    public function getLastUsedServers()
    {
        return $this->lastUsedServers;
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function addServers($servers)
    {
        return $this->setServers(array_merge($this->servers, $servers));
    }

    /**
     * @param TldServer[] $servers
     * @return $this
     */
    public function setServers($servers)
    {
        $weightMap = [];
        foreach ($servers as $index => $server) {
            $parts = explode('.', $server->getZone());
            $rootZone = array_pop($parts);
            $subZone1 = $parts ? array_pop($parts) : '';
            $subZone2 = $parts ? array_pop($parts) : '';
            $weightMap[$server->getId()] = sprintf('%16s.%16s.%32s.%13s', $subZone2, $subZone1, $rootZone, 1000000 - $index);
        };
        usort($servers, function(TldServer $a, TldServer $b) use ($weightMap) {
            return strcmp($weightMap[$b->getId()], $weightMap[$a->getId()]);
        });
        $this->servers = $servers;
        return $this;
    }

    /**
     * @param string $domain
     * @param bool $quiet
     * @return TldServer[]
     * @throws ServerMismatchException
     */
    public function matchServers($domain, $quiet = false)
    {
        $domainAscii = DomainHelper::toAscii($domain);
        $servers = [];
        foreach ($this->servers as $server) {
            $matchedCount = $server->matchDomainZone($domainAscii);
            if ($matchedCount) {
                $servers[] = $server;
            }
        }
        if (!$quiet && empty($servers)) {
            throw new ServerMismatchException("No servers matched for domain '$domain'");
        }
        return $servers;
    }

    /**
     * @param string $domain
     * @return bool
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function isDomainAvailable($domain)
    {
        return !$this->loadDomainInfo($domain);
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldResponse
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function lookupDomain($domain, TldServer $server = null)
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list ($response) = $this->loadDomainData($domain, $servers);
        return $response;
    }

    /**
     * @param string $domain
     * @param TldServer $server
     * @return TldInfo
     * @throws ServerMismatchException
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainInfo($domain, TldServer $server = null)
    {
        $servers = $server ? [$server] : $this->matchServers($domain);
        list (, $info) = $this->loadDomainData($domain, $servers);
        return $info;
    }

    /**
     * @param TldServer $server
     * @param string $domain
     * @param bool $strict
     * @param string $host
     * @return TldResponse
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadResponse(TldServer $server, $domain, $strict = false, $host = null)
    {
        $host = $host ?: $server->getHost();
        $query = $server->buildDomainQuery($domain, $strict);
        return new TldResponse([
            'domain' => $domain,
            'host' => $host,
            'query' => $query,
            'text' => $this->getLoader()->loadText($host, $query),
        ]);
    }

    /**
     * @param string $domain
     * @param TldServer[] $servers
     * @return array
     * @throws ConnectionException
     * @throws WhoisException
     */
    public function loadDomainData(string $domain, array $servers): array
    {
        $this->lastUsedServers = [];
        $domain = DomainHelper::toAscii($domain);
        $response = null;
        $info = null;
        $lastError = null;
        foreach ($servers as $server) {
            $this->lastUsedServers[] = $server;
            $this->loadParsedTo($response, $info, $server, $domain, false, null, $lastError);
            if ($info) {
                break;
            }
        }
        if (!$response && !$info) {
            throw $lastError ? $lastError : new WhoisException("No response");
        }
        return [$response, $info];
    }

    /**
     * @param $outResponse
     * @param TldInfo $outInfo
     * @param TldServer $server
     * @param $domain
     * @param $strict
     * @param $host
     * @param $lastError
     * @throws ConnectionException
     * @throws WhoisException
     */
    protected function loadParsedTo(&$outResponse, &$outInfo, $server, $domain, $strict = false, $host = null, &$lastError = null)
    {
        $tld = explode('.',$domain);
        $tld = $tld && count($tld)>1 ? $tld[count($tld)-1] : "n\a";
        try {
            $outResponse = $this->loadResponse($server, $domain, $strict, $host);

            $this->saveReport([
                date('d.m.Y H:i:s'),
                $tld,
                $domain,
                "Ok",
                $outResponse->text
            ]);

            $reserved_substr = "This name is reserved by the Registry in accordance with ICANN Policy.";
            $substr_in = strpos($outResponse->text, $reserved_substr) !== false;
            if ($substr_in){
                $outResponse = null;
                $outInfo = null;
                return;
            }
            
            $outInfo = $server->getParser()->parseResponse($outResponse);
        } catch (ConnectionException $e) {
            $this->saveReport([
                date('d.m.Y H:i:s'),
                $tld,
                $domain,
                "Fail",
                $e->getMessage()
            ]);
            $lastError = $lastError ?: $e;
        }
        if (!$outInfo && $lastError && $host == $server->getHost() && $strict) {
            throw $lastError;
        }
        if (!$strict && !$outInfo) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, true, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
        if (!$outInfo || $host == $outInfo->whoisServer) {
            return;
        }
        $host = $outInfo->whoisServer;
        if ($host && $host != $server->getHost() && !$server->isCentralized()) {
            $this->loadParsedTo($tmpResponse, $tmpInfo, $server, $domain, false, $host, $lastError);
            $outResponse = $tmpInfo ? $tmpResponse : $outResponse;
            $outInfo = $tmpInfo ?: $outInfo;
        }
    }

    protected function saveReport($data)
    {
        try {
            if (!defined('WP_CONTENT_DIR') || !is_dir(WP_CONTENT_DIR)) {
                throw new \Exception('WP_CONTENT_DIR не определена или не является директорией');
            }
            $maxFileSizeMB = 64;
            $filename = WP_CONTENT_DIR."/domainplugin/reports/report.csv";
            if (file_exists($filename)) {
                // Получаем размер файла в байтах
                $fileSize = filesize($filename);
                // Если размер файла превышает максимальный размер
                if ($fileSize >= $maxFileSizeMB * 1024 * 1024) {
                    // Прочитаем старые данные из файла
                    $oldData = file($filename, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    // Удаляем старые данные, оставив только последние N строк
                    $newData = array_slice($oldData, -$maxFileSizeMB * 1024);
                    // Открываем файл для записи и перезаписываем его
                    $file = fopen($filename, 'w');
                    fwrite($file, implode("\n", $newData));
                    fclose($file);
                }
            }

            $file = fopen($filename, 'a');
            fputcsv($file, $data);
            fclose($file);
        }catch (\Exception $e){

        }
    }
}
