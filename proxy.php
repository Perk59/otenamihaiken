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
    private $responseHeaders = [];
    private $sessionId;
    private $cookieJar;
    private $targetHost;
    private $targetScheme;
    private $proxyBaseUrl;
    private $debug = false;

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

            // リクエストタイプの判定とハンドリング
            if ($this->isApiRequest()) {
                return $this->handleApiRequest();
            }

            // 通常のコンテンツ取得
            $content = $this->fetchContent();
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
        $blockedPatterns = ['/bot/i', '/crawler/i', '/spider/i', '/scraper/i'];
        
        foreach ($blockedPatterns as $pattern) {
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
        return in_array($scheme, ['http', 'https']);
    }

    private function isApiRequest() {
        $acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $ajaxHeader = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';

        // Instagram特有のAPIエンドポイントパターン
        $instagramApiPatterns = [
            '/\/api\/v1\//',
            '/\/graphql\/query/',
            '/\/ajax/',
            '/\/logging_client_events/',
            '/\/web\/search\/topsearch/',
            '/\/web\/likes/',
            '/\/web\/comments/',
            '/\/web\/friendships/'
        ];

        foreach ($instagramApiPatterns as $pattern) {
            if (preg_match($pattern, $this->targetUrl)) {
                return true;
            }
        }

        return (
            strpos($acceptHeader, 'application/json') !== false ||
            strpos($contentType, 'application/json') !== false ||
            $ajaxHeader === 'XMLHttpRequest' ||
            strpos($this->targetUrl, '/api/') !== false ||
            strpos($this->targetUrl, '/graphql') !== false ||
            strpos($this->targetUrl, '.json') !== false
        );
    }

    private function handleApiRequest() {
        $content = $this->fetchContentWithCurl();

        // HTMLレスポンスのチェック（JSONを期待している場合）
        if (strpos($content, '<!DOCTYPE html') !== false || strpos($content, '<html') !== false) {
            header('Content-Type: application/json');
            echo json_encode([
                'status' => 'error',
                'message' => 'Authentication required or session expired',
                'redirect_required' => true
            ]);
            return true;
        }

        // JSONレスポンスの処理
        $decodedContent = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE) {
            $content = $this->rewriteJsonUrls($content);
            
            // レスポンスヘッダーの設定
            $this->setApiResponseHeaders();
            echo $content;
            return true;
        }

        // エラー処理
        header('Content-Type: application/json');
        echo json_encode([
            'status' => 'error',
            'message' => 'Invalid response format',
            'details' => json_last_error_msg()
        ]);
        return true;
    }

    private function setApiResponseHeaders() {
        header('Content-Type: application/json');
        header('Cache-Control: no-store, no-cache, must-revalidate');
        header('Pragma: no-cache');
    }

    private function fetchContent() {
        return $this->fetchContentWithCurl();
    }

    private function fetchContentWithCurl() {
        $ch = curl_init();
        
        $curlOptions = [
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
            // エンコーディングの明示的な指定
            CURLOPT_ENCODING => 'gzip, deflate, br',
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ];

        if (defined('CURL_HTTP_VERSION_2_0')) {
            $curlOptions[CURLOPT_HTTP_VERSION] = CURL_HTTP_VERSION_2_0;
        }

        $headers = $this->buildAdvancedHeaders();
        curl_setopt_array($ch, $curlOptions);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        // リクエストメソッドとデータの設定
        if ($this->requestMethod !== 'GET') {
            $this->setRequestData($curlOptions);
        }

        $content = curl_exec($ch);

        if ($content === false) {
            $error = curl_error($ch);
            $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            curl_close($ch);
            throw new Exception(sprintf('cURL error (%d): %s', $httpCode, $error));
        }

        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        http_response_code($httpCode);

        return $content;
    }

    private function setRequestData(&$curlOptions) {
        $inputData = file_get_contents('php://input');
        if (!empty($inputData)) {
            $curlOptions[CURLOPT_POSTFIELDS] = $inputData;
        }
    }

    private function buildAdvancedHeaders() {
        $headers = [
            // 日本語を優先した Accept-Language の設定
            'Accept-Language: ja,ja_JP;q=0.9,en-US;q=0.8,en;q=0.7',
            'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding: gzip, deflate, br',
            'Connection: keep-alive',
            'Upgrade-Insecure-Requests: 1',
            'Sec-Fetch-Site: same-origin',
            'Sec-Fetch-Mode: cors',
            'Sec-Fetch-Dest: empty',
            // 文字エンコーディングを明示的に指定
            'Accept-Charset: utf-8,shift_jis,euc-jp,iso-2022-jp'
        ];

        // Instagram特有のヘッダー
        if (strpos($this->targetHost, 'instagram.com') !== false) {
            $headers[] = 'X-Instagram-AJAX: 1';
            $headers[] = 'X-IG-App-ID: 936619743392459';
            $headers[] = 'X-Requested-With: XMLHttpRequest';
            $headers[] = 'Origin: https://www.instagram.com';
        }

        return $headers;
    }

    private function handleResponseHeader($ch, $header) {
        $trimmedHeader = trim($header);
        if (empty($trimmedHeader)) {
            return strlen($header);
        }

        try {
            // ヘッダーの検証
            if (!preg_match('/^[\x20-\x7E]*$/', $trimmedHeader)) {
                // 無効な文字が含まれている場合はスキップ
                return strlen($header);
            }

            // Set-Cookieヘッダーの特別処理
            if (stripos($trimmedHeader, 'Set-Cookie:') === 0) {
                $cookieValue = trim(substr($trimmedHeader, 11));
                // Cookieの値をサニタイズ
                $cookieValue = preg_replace('/[\x00-\x1F\x7F]/', '', $cookieValue);
                $cookieValue = preg_replace('/Domain=[^;]+;?\s*/i', '', $cookieValue);
                $cookieValue = preg_replace('/Path=[^;]+;?\s*/i', '', $cookieValue);
                
                if (!empty($cookieValue)) {
                    // バッファリングが開始されていない場合のチェック
                    if (!headers_sent()) {
                        header('Set-Cookie: ' . $cookieValue, false);
                    }
                }
            } else {
                // 通常のヘッダーの処理
                $this->responseHeaders[] = $trimmedHeader;
            }
        } catch (Exception $e) {
            error_log('Header processing error: ' . $e->getMessage());
        }

        return strlen($header);
    }

    private function sendResponse($content) {
        // コンテンツタイプと文字セットの検出
        $contentInfo = $this->detectContentType($content);
        $contentType = $contentInfo['contentType'];
        $charset = $contentInfo['charset'];

        // 文字エンコーディングの変換が必要な場合
        if ($charset !== 'utf-8' && function_exists('mb_convert_encoding')) {
            $content = mb_convert_encoding($content, 'UTF-8', $charset);
            $charset = 'utf-8';
        }

        // Content-Typeヘッダーの設定
        if (!headers_sent()) {
            header("Content-Type: {$contentType}; charset=utf-8");
        }

        // その他のヘッダーの設定
        if (!empty($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                $headerLower = strtolower($header);
                
                // 特定のヘッダーをスキップ
                if (strpos($headerLower, 'content-type:') === 0 ||
                    strpos($headerLower, 'transfer-encoding:') === 0 ||
                    strpos($headerLower, 'content-length:') === 0 ||
                    strpos($headerLower, 'content-encoding:') === 0) {
                    continue;
                }

                header($header);
            }
        }

        // コンテンツの処理
        switch ($contentType) {
            case 'text/html':
                $content = $this->processHtmlContent($content);
                break;
            case 'text/css':
                $content = $this->processCssContent($content);
                break;
            case 'application/javascript':
            case 'text/javascript':
                $content = $this->processJsContent($content);
                break;
            case 'application/json':
                $content = $this->ensureJsonEncoding($content);
                break;
        }

        echo $content;
        return true;
    }

    private function ensureJsonEncoding($content) {
        // JSONデータのエンコーディング処理
        if (function_exists('mb_convert_encoding')) {
            $content = mb_convert_encoding($content, 'UTF-8', 'ASCII,JIS,UTF-8,EUC-JP,SJIS');
        }
        
        // JSONの妥当性チェック
        $decoded = json_decode($content);
        if (json_last_error() !== JSON_ERROR_NONE) {
            // エラーの場合、UTF-8でエンコードし直す
            $content = utf8_encode($content);
        }
        
        return $content;
    }

    private function detectContentType($content) {
        $contentType = 'text/plain';
        $charset = 'utf-8';

        // レスポンスヘッダーからContent-Typeを検索
        if (!empty($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                if (stripos($header, 'Content-Type:') === 0) {
                    $parts = explode(';', $header);
                    $contentType = strtolower(trim(substr($parts[0], 13)));
                    
                    // 文字セットの検出
                    foreach ($parts as $part) {
                        if (stripos($part, 'charset=') !== false) {
                            $charset = trim(substr($part, strpos($part, '=') + 1));
                            break;
                        }
                    }
                    break;
                }
            }
        }

        // HTMLの場合はmetaタグから文字セットを検出
        if (strpos($contentType, 'text/html') !== false) {
            if (preg_match('/<meta[^>]+charset=[\'"]*([a-zA-Z0-9_-]+)/i', $content, $matches)) {
                $charset = $matches[1];
            }
        }

        return compact('contentType', 'charset');
    }

    private function processHtmlContent($content) {
        // 文字エンコーディングメタタグの追加/更新
        if (!preg_match('/<meta[^>]+charset/i', $content)) {
            $content = preg_replace(
                '/(<head[^>]*>)/i',
                '$1<meta charset="utf-8">',
                $content
            );
        } else {
            $content = preg_replace(
                '/(<meta[^>]+charset=[\'"]?)([a-zA-Z0-9_-]+)([\'"]?[^>]*>)/i',
                '$1utf-8$3',
                $content
            );
        }

        // その他のHTML処理
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        $basePath = isset($baseUrl['path']) ? dirname($baseUrl['path']) : '';

        if (strpos($content, '<base') === false) {
            $content = preg_replace(
                '/(<head[^>]*>)/i',
                '$1<base href="' . $baseHost . $basePath . '/">',
                $content
            );
        }

        // URLの書き換え
        $content = $this->rewriteHtmlUrls($content);

        // プロキシスクリプトの追加
        $proxyScript = $this->generateProxyScript();
        $content = str_replace('</body>', $proxyScript . '</body>', $content);

        return $content;
    }

    private function rewriteHtmlUrls($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        $patterns = [
            '/(href)=["\'](?!#|javascript:|mailto:|tel:)([^"\']+)["\']/i',
            '/(src)=["\'](?!data:)([^"\']+)["\']/i',
            '/(action)=["\']([^"\']+)["\']/i'
        ];

        foreach ($patterns as $pattern) {
            $content = preg_replace_callback(
                $pattern,
                function($matches) use ($baseHost) {
                    $attr = $matches[1];
                    $url = $matches[2];

                    // 完全なURLの場合
                    if (preg_match('/^https?:\/\//', $url)) {
                        return $attr . '="' . $this->proxyBaseUrl . urlencode($url) . '"';
                    }

                    // プロトコル相対URLの場合
                    if (strpos($url, '//') === 0) {
                        return $attr . '="' . $this->proxyBaseUrl . urlencode('https:' . $url) . '"';
                    }

                    // ルート相対URLの場合
                    if (strpos($url, '/') === 0) {
                        return $attr . '="' . $this->proxyBaseUrl . urlencode($baseHost . $url) . '"';
                    }

                    // 相対URLの場合
                    $fullUrl = $baseHost . '/' . ltrim($url, '/');
                    return $attr . '="' . $this->proxyBaseUrl . urlencode($fullUrl) . '"';
                },
                $content
            );
        }

        return $content;
    }

    private function processCssContent($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        return preg_replace_callback(
            '/url\(["\']?([^"\']+)["\']?\)/i',
            function($matches) use ($baseHost) {
                $url = $matches[1];
                if (strpos($url, 'data:') === 0) {
                    return 'url("' . $url . '")';
                }
                
                if (strpos($url, 'http') === 0) {
                    return 'url("' . $this->proxyBaseUrl . urlencode($url) . '")';
                }
                
                $fullUrl = $baseHost . '/' . ltrim($url, '/');
                return 'url("' . $this->proxyBaseUrl . urlencode($fullUrl) . '")';
            },
            $content
        );
    }

    private function processJsContent($content) {
        $baseHost = $this->targetScheme . '://' . $this->targetHost;
        
        $patterns = [
            '/"(https?:\/\/[^"]+)"/i',
            "/'(https?:\/\/[^']+)'/i",
            '/(fetch|ajax|get|post)\s*\(\s*["\']([^"\']+)["\']/i',
            '/(\burl\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i'
        ];

        foreach ($patterns as $pattern) {
            $content = preg_replace_callback(
                $pattern,
                function($matches) use ($baseHost) {
                    if (count($matches) === 2) {
                        return '"' . $this->proxyBaseUrl . urlencode($matches[1]) . '"';
                    }
                    return $matches[1] . $this->proxyBaseUrl . urlencode($matches[2]) . (isset($matches[3]) ? $matches[3] : '');
                },
                $content
            );
        }

        return $content;
    }

    private function rewriteJsonUrls($content) {
        return preg_replace_callback(
            '/"(https?:\/\/[^"]+)"/i',
            function($matches) {
                return '"' . $this->proxyBaseUrl . urlencode($matches[1]) . '"';
            },
            $content
        );
    }

    private function generateProxyScript() {
        return <<<EOT
        <script>
        (function() {
            const PROXY_BASE = "{$this->proxyBaseUrl}";
            const TARGET_HOST = "{$this->targetHost}";
            const TARGET_SCHEME = "{$this->targetScheme}";
            
            function proxyUrl(url) {
                if (!url || url.startsWith(PROXY_BASE) || url.startsWith("#") || 
                    url.startsWith("javascript:") || url.startsWith("mailto:") || url.startsWith("tel:") ||
                    url.startsWith("data:")) {
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
                    if (typeof input === "string") {
                        input = proxyUrl(input);
                    } else if (input instanceof Request) {
                        input = new Request(proxyUrl(input.url), {
                            method: input.method,
                            headers: input.headers,
                            body: input.body,
                            mode: input.mode,
                            credentials: input.credentials,
                            cache: input.cache,
                            redirect: input.redirect,
                            referrer: input.referrer,
                            integrity: input.integrity
                        });
                    }
                    return originalFetch(input, init);
                };
            }
            
            // jQueryの書き換え
            if (window.jQuery) {
                jQuery.ajaxPrefilter(function(options) {
                    if (options.url) {
                        options.url = proxyUrl(options.url);
                    }
                });
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
            
            // フォーム送信の処理
            document.addEventListener('submit', function(e) {
                const form = e.target;
                if (form.tagName === 'FORM' && form.action) {
                    form.action = proxyUrl(form.action);
                }
            });
            
        })();
        </script>
EOT;
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
                    @unlink($file);
                }
            }
        }
    }
}

// CORSヘッダーの設定
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    header('Access-Control-Allow-Origin: ' . ($_SERVER['HTTP_ORIGIN'] ?? '*'));
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, X-CSRF-Token');
    header('Access-Control-Allow-Credentials: true');
    exit;
}

// メイン処理の実行
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
