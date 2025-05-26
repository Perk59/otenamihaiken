<?php
// エラーレポーティングの設定
error_reporting(E_ALL);
ini_set('display_errors', 1);

// セッション開始
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

class AdvancedProxyHandler {
    private $targetUrl;
    private $originalUrl;
    private $requestMethod;
    private $startTime;
    private $responseHeaders;
    private $sessionId;
    private $cookieJar;
    private $targetHost;
    private $targetScheme;
    private $proxyBaseUrl;
    
    public function __construct($url) {
        $this->startTime = microtime(true);
        $this->targetUrl = $url;
        $this->originalUrl = $this->getCurrentUrl();
        $this->requestMethod = $_SERVER['REQUEST_METHOD'];
        $this->sessionId = session_id();
        $this->cookieJar = $this->getCookieJarPath();
        
        // URLの解析
        $parsed = parse_url($url);
        $this->targetHost = $parsed['host'] ?? '';
        $this->targetScheme = $parsed['scheme'] ?? 'https';
        
        // プロキシベースURLの構築
        $currentUrl = $this->getCurrentUrl();
        $currentParsed = parse_url($currentUrl);
        $this->proxyBaseUrl = $currentParsed['scheme'] . '://' . $currentParsed['host'] . 
                             dirname($currentParsed['path']) . '/proxy.php?url=';
    }
    
    public function execute() {
        try {
            // セキュリティチェック
            if (!$this->securityCheck()) {
                throw new Exception('Security check failed');
            }
            
            // URLの検証
            if (!$this->validateUrl()) {
                throw new Exception('Invalid URL provided');
            }
            
            // APIリクエストの特別処理
            if ($this->isApiRequest()) {
                return $this->handleApiRequest();
            }
            
            // 通常のコンテンツ取得
            $content = $this->fetchContent();
            
            // レスポンスの送信
            return $this->sendResponse($content);
            
        } catch (Exception $e) {
            $this->handleError($e);
        }
    }
    
    private function getCurrentUrl() {
        $protocol = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        return $protocol . "://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    }
    
    private function getCookieJarPath() {
        $cookieDir = sys_get_temp_dir() . '/proxy_cookies';
        if (!is_dir($cookieDir)) {
            mkdir($cookieDir, 0755, true);
        }
        return $cookieDir . '/cookies_' . $this->sessionId . '.txt';
    }
    
    private function securityCheck() {
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $suspiciousPatterns = [
            '/bot/i', '/crawler/i', '/spider/i', '/scraper/i'
        ];
        
        foreach ($suspiciousPatterns as $pattern) {
            if (preg_match($pattern, $userAgent)) {
                return false;
            }
        }
        
        return true;
    }
    
    private function validateUrl() {
        if (empty($this->targetUrl)) {
            return false;
        }
        
        $url = filter_var($this->targetUrl, FILTER_VALIDATE_URL);
        if ($url === false) {
            return false;
        }
        
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['http', 'https'])) {
            return false;
        }
        
        return true;
    }
    
    private function isApiRequest() {
        $acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $ajaxHeader = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
        
        return (
            strpos($acceptHeader, 'application/json') !== false ||
            strpos($contentType, 'application/json') !== false ||
            $ajaxHeader === 'XMLHttpRequest' ||
            strpos($this->targetUrl, '/api/') !== false ||
            strpos($this->targetUrl, '/ajax/') !== false ||
            strpos($this->targetUrl, '/graphql') !== false ||
            strpos($this->targetUrl, '.json') !== false
        );
    }
    
    private function handleApiRequest() {
        $content = $this->fetchContentWithCurl();
        
        // JSONレスポンスの処理
        $decodedContent = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decodedContent)) {
            $content = $this->rewriteJsonUrls($content);
        }
        
        // APIレスポンスヘッダーの設定
        if (isset($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                if (!preg_match('/^Transfer-Encoding:|^Connection:|^Content-Length:/i', $header)) {
                    header($header);
                }
            }
        }
        
        echo $content;
        return true;
    }
    
    private function fetchContent() {
        return $this->fetchContentWithCurl();
    }
    
    private function fetchContentWithCurl() {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $this->targetUrl,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 10,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_COOKIEJAR => $this->cookieJar,
            CURLOPT_COOKIEFILE => $this->cookieJar,
            CURLOPT_HEADERFUNCTION => [$this, 'handleResponseHeader'],
            CURLOPT_ENCODING => '',
        ]);
        
        if (defined('CURL_HTTP_VERSION_2_0')) {
            curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        }
        
        $headers = $this->buildAdvancedHeaders();
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        switch ($this->requestMethod) {
            case 'POST':
                curl_setopt($ch, CURLOPT_POST, true);
                $postData = file_get_contents('php://input');
                if (!empty($postData)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $postData);
                }
                break;
            case 'PUT':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
                $putData = file_get_contents('php://input');
                if (!empty($putData)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $putData);
                }
                break;
            case 'DELETE':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'DELETE');
                break;
            case 'PATCH':
                curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PATCH');
                $patchData = file_get_contents('php://input');
                if (!empty($patchData)) {
                    curl_setopt($ch, CURLOPT_POSTFIELDS, $patchData);
                }
                break;
        }
        
        $content = curl_exec($ch);
        
        if ($content === false) {
            $error = curl_error($ch);
            curl_close($ch);
            throw new Exception('cURL error: ' . $error);
        }
        
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        http_response_code($httpCode);
        
        return $content;
    }
    
    private function buildAdvancedHeaders() {
        $headers = [];
        
        $headers[] = 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
        $headers[] = 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
        $headers[] = 'Accept-Language: ja,en-US;q=0.9,en;q=0.8';
        $headers[] = 'Accept-Encoding: gzip, deflate, br';
        $headers[] = 'Connection: keep-alive';
        $headers[] = 'Upgrade-Insecure-Requests: 1';
        $headers[] = 'Sec-Fetch-Site: same-origin';
        $headers[] = 'Sec-Fetch-Mode: navigate';
        $headers[] = 'Sec-Fetch-User: ?1';
        $headers[] = 'Sec-Fetch-Dest: document';
        
        $forwardHeaders = [
            'HTTP_REFERER' => 'Referer',
            'HTTP_AUTHORIZATION' => 'Authorization',
            'HTTP_X_REQUESTED_WITH' => 'X-Requested-With',
            'HTTP_X_CSRF_TOKEN' => 'X-CSRF-Token',
            'HTTP_X_XSRF_TOKEN' => 'X-XSRF-Token',
            'CONTENT_TYPE' => 'Content-Type',
        ];
        
        foreach ($forwardHeaders as $serverKey => $headerName) {
            if (isset($_SERVER[$serverKey]) && !empty($_SERVER[$serverKey])) {
                $headers[] = $headerName . ': ' . $_SERVER[$serverKey];
            }
        }
        
        if (isset($_SERVER['HTTP_COOKIE'])) {
            $headers[] = 'Cookie: ' . $_SERVER['HTTP_COOKIE'];
        }
        
        $headers[] = 'X-Forwarded-For: ' . $this->getRealIpAddr();
        $headers[] = 'X-Forwarded-Proto: ' . (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http');
        $headers[] = 'X-Real-IP: ' . $this->getRealIpAddr();
        
        return $headers;
    }
    
    private function getRealIpAddr() {
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }
    
    public function handleResponseHeader($ch, $header) {
        $this->responseHeaders[] = trim($header);
        
        if (stripos($header, 'Set-Cookie:') === 0) {
            $cookieValue = trim(substr($header, 11));
            $cookieValue = preg_replace('/Domain=[^;]+;?\s*/i', '', $cookieValue);
            $cookieValue = preg_replace('/Path=[^;]+;?\s*/i', '', $cookieValue);
            header('Set-Cookie: ' . $cookieValue);
        }
        
        return strlen($header);
    }
    
    private function sendResponse($content) {
        if (isset($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                $headerLower = strtolower($header);
                
                if (strpos($headerLower, 'transfer-encoding:') === 0 ||
                    strpos($headerLower, 'connection:') === 0 ||
                    strpos($headerLower, 'content-length:') === 0 ||
                    strpos($headerLower, 'set-cookie:') === 0) {
                    continue;
                }
                
                if (strpos($headerLower, 'x-frame-options:') === 0) {
                    header('X-Frame-Options: SAMEORIGIN');
                    continue;
                }
                
                if (strpos($headerLower, 'content-security-policy:') === 0) {
                    continue;
                }
                
                header($header);
            }
        }
        
        $contentType = $this->detectContentType($content);
        
        if (strpos($contentType, 'text/html') !== false) {
            $content = $this->processHtmlContent($content);
        } elseif (strpos($contentType, 'text/css') !== false) {
            $content = $this->processCssContent($content);
        } elseif (strpos($contentType, 'application/javascript') !== false || 
                  strpos($contentType, 'text/javascript') !== false) {
            $content = $this->processJsContent($content);
        }
        
        echo $content;
    }
    
    private function detectContentType($content) {
        if (isset($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                if (stripos($header, 'Content-Type:') === 0) {
                    return strtolower(trim(substr($header, 13)));
                }
            }
        }
        
        if (strpos($content, '<!DOCTYPE html') !== false || strpos($content, '<html') !== false) {
            return 'text/html';
        }
        
        return 'text/plain';
    }
    
    private function processHtmlContent($content) {
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        $basePath = isset($baseUrl['path']) ? dirname($baseUrl['path']) : '';
        
        if (strpos($content, '<base') === false) {
            $content = preg_replace('/(<head[^>]*>)/i', '$1<base href="' . $baseHost . $basePath . '/">', $content);
        }
        
        $content = preg_replace('/<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*>/i', '', $content);
        $content = $this->rewriteHtmlUrls($content);
        
        $proxyScript = $this->generateProxyScript();
        $content = str_replace('</body>', $proxyScript . '</body>', $content);
        
        return $content;
    }
    
    private function rewriteHtmlUrls($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        $patterns = [
            '/(href)=["\'](?!#|javascript:|mailto:|tel:)([^"\']+)["\']/i',
            '/(src)=["\'](?!data:)([^"\']+)["\']/i',
            '/(action)=["\']([^"\']+)["\']/i',
        ];
        
        foreach ($patterns as $pattern) {
            $content = preg_replace_callback($pattern, function($matches) use ($baseHost) {
                $attr = $matches[1];
                $url = $matches[2];
                
                if (preg_match('/^https?:\/\//', $url)) {
                    return $attr . '="' . $this->proxyBaseUrl . urlencode($url) . '"';
                }
                
                if (strpos($url, '//') === 0) {
                    return $attr . '="' . $this->proxyBaseUrl . urlencode('https:' . $url) . '"';
                }
                
                if (strpos($url, '/') === 0) {
                    return $attr . '="' . $this->proxyBaseUrl . urlencode($baseHost . $url) . '"';
                }
                
                $fullUrl = $baseHost . '/' . ltrim($url, '/');
                return $attr . '="' . $this->proxyBaseUrl . urlencode($fullUrl) . '"';
                
            }, $content);
        }
        
        return $content;
    }
    
    private function processCssContent($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        $content = preg_replace_callback(
            '/url\(["\']?([^"\']+)["\']?\)/i',
            function($matches) use ($baseHost) {
                $url = $matches[1];
                if (strpos($url, 'http') === 0) {
                    return 'url("' . $this->proxyBaseUrl . urlencode($url) . '")';
                } else {
                    $fullUrl = $baseHost . '/' . ltrim($url, '/');
                    return 'url("' . $this->proxyBaseUrl . urlencode($fullUrl) . '")';
                }
            },
            $content
        );
        
        return $content;
    }
    
    private function processJsContent($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        // JavaScript内のURL書き換え（重要な部分のみ）
        $patterns = [
            // 基本的な文字列内のURL
            '/"(https?:\/\/[^"]+)"/i',
            "/'(https?:\/\/[^']+)'/i",
            // 関数呼び出し内のURL  
            '/(fetch|ajax|get|post)\s*\(\s*["\']([^"\']+)["\']/i',
            // 変数代入
            '/(\burl\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
        ];
        
        foreach ($patterns as $pattern) {
            $content = preg_replace_callback($pattern, function($matches) {
                if (count($matches) === 2) {
                    // URLのみのマッチ
                    return '"' . $this->proxyBaseUrl . urlencode($matches[1]) . '"';
                } else {
                    // より複雑なマッチ
                    return $matches[1] . $this->proxyBaseUrl . urlencode($matches[2]) . $matches[3];
                }
            }, $content);
        }
        
        return $content;
    }
    
    private function rewriteJsonUrls($content) {
        $content = preg_replace_callback(
            '/"(https?:\/\/[^"]+)"/i',
            function($matches) {
                return '"' . $this->proxyBaseUrl . urlencode($matches[1]) . '"';
            },
            $content
        );
        
        return $content;
    }
    
    private function generateProxyScript() {
        return '
        <script>
        (function() {
            const PROXY_BASE = "' . $this->proxyBaseUrl . '";
            const TARGET_HOST = "' . $this->targetHost . '";
            const TARGET_SCHEME = "' . $this->targetScheme . '";
            
            function proxyUrl(url) {
                if (!url || url.startsWith(PROXY_BASE) || url.startsWith("#") || 
                    url.startsWith("javascript:") || url.startsWith("mailto:") || url.startsWith("tel:")) {
                    return url;
                }
                
                if (url.match(/^https?:\/\//)) {
                    return PROXY_BASE + encodeURIComponent(url);
                }
                
                if (url.startsWith("//")) {
                    return PROXY_BASE + encodeURIComponent(TARGET_SCHEME + ":" + url);
                }
                
                if (url.startsWith("/")) {
                    return PROXY_BASE + encodeURIComponent(TARGET_SCHEME + "://" + TARGET_HOST + url);
                }
                
                const currentPath = window.location.pathname;
                const basePath = currentPath.substring(0, currentPath.lastIndexOf("/") + 1);
                return PROXY_BASE + encodeURIComponent(TARGET_SCHEME + "://" + TARGET_HOST + basePath + url);
            }
            
            // XMLHttpRequestの書き換え
            const originalXHR = window.XMLHttpRequest;
            window.XMLHttpRequest = function() {
                const xhr = new originalXHR();
                const originalOpen = xhr.open;
                
                xhr.open = function(method, url, async, user, password) {
                    url = proxyUrl(url);
                    return originalOpen.call(this, method, url, async, user, password);
                };
                
                return xhr;
            };
            
            // fetchの書き換え
            if (window.fetch) {
                const originalFetch = window.fetch;
                window.fetch = function(input, init) {
                    let url;
                    if (typeof input === "string") {
                        url = proxyUrl(input);
                    } else if (input instanceof Request) {
                        url = proxyUrl(input.url);
                        init = init || {};
                        init.method = input.method;
                        init.headers = input.headers;
                        init.body = input.body;
                    } else {
                        url = input;
                    }
                    return originalFetch(url, init);
                };
            }
            
            // jQueryの書き換え
            if (window.jQuery) {
                const $ = window.jQuery;
                if ($.ajaxPrefilter) {
                    $.ajaxPrefilter(function(options) {
                        if (options.url) {
                            options.url = proxyUrl(options.url);
                        }
                    });
                }
            }
            
            // Axiosの書き換え
            if (window.axios && window.axios.interceptors) {
                window.axios.interceptors.request.use(function(config) {
                    if (config.url) {
                        config.url = proxyUrl(config.url);
                    }
                    return config;
                });
            }
            
        })();
        </script>';
    }
    
    private function handleError($e) {
        error_log('Proxy Error: ' . $e->getMessage() . ' | URL: ' . $this->targetUrl);
        
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => true,
            'message' => 'Proxy request failed',
            'details' => $e->getMessage()
        ]);
    }
    
    public function __destruct() {
        $this->cleanupOldCookies();
    }
    
    private function cleanupOldCookies() {
        $cookieDir = sys_get_temp_dir() . '/proxy_cookies';
        if (is_dir($cookieDir)) {
            $files = glob($cookieDir . '/cookies_*.txt');
            foreach ($files as $file) {
                if (filemtime($file) < time() - 3600) {
                    unlink($file);
                }
            }
        }
    }
}

// CORS対応
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: *');
    exit;
}

// メイン処理
$targetUrl = $_GET['url'] ?? '';

if (empty($targetUrl)) {
    http_response_code(400);
    header('Content-Type: application/json');
    echo json_encode([
        'error' => true,
        'message' => 'URL parameter is required',
        'usage' => 'proxy.php?url=https://example.com'
    ]);
    exit;
}

$proxy = new AdvancedProxyHandler($targetUrl);
$proxy->execute();
?>
