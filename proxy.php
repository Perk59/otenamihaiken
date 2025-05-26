<?php
// エラーレポーティングの設定
error_reporting(E_ALL);
ini_set('display_errors', 1);

// セッション開始（セッション管理の改善）
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
    
    public function __construct($url) {
        $this->startTime = microtime(true);
        $this->targetUrl = $url;
        $this->originalUrl = $this->getCurrentUrl();
        $this->requestMethod = $_SERVER['REQUEST_METHOD'];
        $this->sessionId = session_id();
        $this->cookieJar = $this->getCookieJarPath();
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
        // セッション毎にCookieファイルを作成（セッション管理の向上）
        $cookieDir = sys_get_temp_dir() . '/proxy_cookies';
        if (!is_dir($cookieDir)) {
            mkdir($cookieDir, 0755, true);
        }
        return $cookieDir . '/cookies_' . $this->sessionId . '.txt';
    }
    
    private function securityCheck() {
        // 基本的なセキュリティチェック
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
        
        // ボット検出の簡易版
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
        
        // 危険なプロトコルをブロック
        $scheme = parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['http', 'https'])) {
            return false;
        }
        
        return true;
    }
    
    private function isApiRequest() {
        // APIリクエストの判定（JSONレスポンスやAJAX通信の検出）
        $acceptHeader = $_SERVER['HTTP_ACCEPT'] ?? '';
        $contentType = $_SERVER['CONTENT_TYPE'] ?? '';
        $ajaxHeader = $_SERVER['HTTP_X_REQUESTED_WITH'] ?? '';
        
        return (
            strpos($acceptHeader, 'application/json') !== false ||
            strpos($contentType, 'application/json') !== false ||
            $ajaxHeader === 'XMLHttpRequest' ||
            strpos($this->targetUrl, '/api/') !== false ||
            strpos($this->targetUrl, '.json') !== false
        );
    }
    
    private function handleApiRequest() {
        // API専用の処理（AJAX通信やJSON APIの中継）
        $content = $this->fetchContentWithCurl();
        
        // JSONレスポンスの場合は特別処理
        $decodedContent = json_decode($content, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decodedContent)) {
            // JSON内のURLも書き換え（必要に応じて）
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
        // より高度なHTTPクライアント処理
        return $this->fetchContentWithCurl();
    }
    
    private function fetchContentWithCurl() {
        $ch = curl_init();
        
        // 基本設定
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
            CURLOPT_ENCODING => '', // 自動的にgzip/deflateを処理
        ]);
        
        // HTTP/2サポート
        if (defined('CURL_HTTP_VERSION_2_0')) {
            curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
        }
        
        // ヘッダーの設定
        $headers = $this->buildAdvancedHeaders();
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        
        // リクエストメソッドに応じた処理
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
        
        // HTTPステータスコードの設定
        http_response_code($httpCode);
        
        return $content;
    }
    
    private function buildAdvancedHeaders() {
        $headers = [];
        
        // より現実的なブラウザヘッダー
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
        $headers[] = 'sec-ch-ua: "Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"';
        $headers[] = 'sec-ch-ua-mobile: ?0';
        $headers[] = 'sec-ch-ua-platform: "Windows"';
        
        // オリジナルのリクエストヘッダーを転送
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
        
        // Cookieの転送（改善されたCookie管理）
        if (isset($_SERVER['HTTP_COOKIE'])) {
            $headers[] = 'Cookie: ' . $_SERVER['HTTP_COOKIE'];
        }
        
        // プロキシ情報
        $headers[] = 'X-Forwarded-For: ' . $this->getRealIpAddr();
        $headers[] = 'X-Forwarded-Proto: ' . (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http');
        $headers[] = 'X-Real-IP: ' . $this->getRealIpAddr();
        
        return $headers;
    }
    
    private function getRealIpAddr() {
        // より正確なIP取得
        if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
            return $_SERVER['HTTP_CLIENT_IP'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_X_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['HTTP_X_FORWARDED'])) {
            return $_SERVER['HTTP_X_FORWARDED'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED_FOR'])) {
            return $_SERVER['HTTP_FORWARDED_FOR'];
        } elseif (!empty($_SERVER['HTTP_FORWARDED'])) {
            return $_SERVER['HTTP_FORWARDED'];
        } else {
            return $_SERVER['REMOTE_ADDR'];
        }
    }
    
    public function handleResponseHeader($ch, $header) {
        // レスポンスヘッダーの処理（コールバック関数）
        $this->responseHeaders[] = trim($header);
        
        // Set-Cookieヘッダーの特別処理
        if (stripos($header, 'Set-Cookie:') === 0) {
            $cookieValue = trim(substr($header, 11));
            // ドメインとパスの調整
            $cookieValue = preg_replace('/Domain=[^;]+;?\s*/i', '', $cookieValue);
            $cookieValue = preg_replace('/Path=[^;]+;?\s*/i', '', $cookieValue);
            header('Set-Cookie: ' . $cookieValue);
        }
        
        return strlen($header);
    }
    
    private function sendResponse($content) {
        // レスポンスヘッダーの送信
        if (isset($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                $headerLower = strtolower($header);
                
                // 除外するヘッダー
                if (strpos($headerLower, 'transfer-encoding:') === 0 ||
                    strpos($headerLower, 'connection:') === 0 ||
                    strpos($headerLower, 'content-length:') === 0 ||
                    strpos($headerLower, 'set-cookie:') === 0) {
                    continue;
                }
                
                // セキュリティヘッダーの調整
                if (strpos($headerLower, 'x-frame-options:') === 0) {
                    header('X-Frame-Options: SAMEORIGIN');
                    continue;
                }
                
                if (strpos($headerLower, 'content-security-policy:') === 0) {
                    // CSPを緩和（プロキシ経由でのアクセスを許可）
                    continue;
                }
                
                header($header);
            }
        }
        
        // コンテンツタイプの検出と処理
        $contentType = $this->detectContentType($content);
        
        if (strpos($contentType, 'text/html') !== false) {
            // HTMLコンテンツの処理
            $content = $this->processHtmlContent($content);
        } elseif (strpos($contentType, 'text/css') !== false) {
            // CSSコンテンツの処理
            $content = $this->processCssContent($content);
        } elseif (strpos($contentType, 'application/javascript') !== false || 
                  strpos($contentType, 'text/javascript') !== false) {
            // JavaScriptコンテンツの処理
            $content = $this->processJsContent($content);
        }
        
        echo $content;
    }
    
    private function detectContentType($content) {
        // レスポンスヘッダーからContent-Typeを取得
        if (isset($this->responseHeaders)) {
            foreach ($this->responseHeaders as $header) {
                if (stripos($header, 'Content-Type:') === 0) {
                    return strtolower(trim(substr($header, 13)));
                }
            }
        }
        
        // コンテンツから推測
        if (strpos($content, '<!DOCTYPE html') !== false || strpos($content, '<html') !== false) {
            return 'text/html';
        }
        
        return 'text/plain';
    }
    
    private function processHtmlContent($content) {
        // HTMLコンテンツの高度な処理
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        $basePath = isset($baseUrl['path']) ? dirname($baseUrl['path']) : '';
        
        // Base URLの設定
        if (strpos($content, '<base') === false) {
            $content = preg_replace('/(<head[^>]*>)/i', '$1<base href="' . $baseHost . $basePath . '/">', $content);
        }
        
        // メタタグの調整
        $content = preg_replace('/<meta[^>]+http-equiv=["\']?refresh["\']?[^>]*>/i', '', $content);
        
        // URLの書き換え（より詳細な処理）
        $content = $this->rewriteHtmlUrls($content);
        
        // プロキシ用のJavaScriptを注入
        $proxyScript = $this->generateProxyScript();
        $content = str_replace('</body>', $proxyScript . '</body>', $content);
        
        return $content;
    }
    
    private function rewriteHtmlUrls($content) {
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        
        // プロキシのベースURL
        $proxyUrl = parse_url($this->originalUrl);
        $proxyBase = $proxyUrl['scheme'] . '://' . $proxyUrl['host'] . 
                    (isset($proxyUrl['port']) ? ':' . $proxyUrl['port'] : '') .
                    dirname($proxyUrl['path']) . '/proxy.php?url=';
        
        // 属性別の書き換えパターン
        $patterns = [
            // href属性（リンク）
            '/(href)=["\'](?!#|javascript:|mailto:|tel:)([^"\']+)["\']/i',
            // src属性（画像、スクリプト等）
            '/(src)=["\'](?!data:)([^"\']+)["\']/i',
            // action属性（フォーム）
            '/(action)=["\']([^"\']+)["\']/i',
            // その他のURL属性
            '/(poster|background)=["\']([^"\']+)["\']/i',
        ];
        
        foreach ($patterns as $pattern) {
            $content = preg_replace_callback($pattern, function($matches) use ($baseHost, $proxyBase) {
                $attr = $matches[1];
                $url = $matches[2];
                
                // 絶対URLの場合
                if (preg_match('/^https?:\/\//', $url)) {
                    return $attr . '="' . $proxyBase . urlencode($url) . '"';
                }
                
                // プロトコル相対URLの場合
                if (strpos($url, '//') === 0) {
                    return $attr . '="' . $proxyBase . urlencode('https:' . $url) . '"';
                }
                
                // 絶対パスの場合
                if (strpos($url, '/') === 0) {
                    return $attr . '="' . $proxyBase . urlencode($baseHost . $url) . '"';
                }
                
                // 相対パスの場合
                $fullUrl = $baseHost . '/' . ltrim($url, '/');
                return $attr . '="' . $proxyBase . urlencode($fullUrl) . '"';
                
            }, $content);
        }
        
        return $content;
    }
    
    private function processCssContent($content) {
        // CSS内のURLを書き換え
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        
        $proxyUrl = parse_url($this->originalUrl);
        $proxyBase = $proxyUrl['scheme'] . '://' . $proxyUrl['host'] . 
                    dirname($proxyUrl['path']) . '/proxy.php?url=';
        
        $content = preg_replace_callback(
            '/url\(["\']?([^"\']+)["\']?\)/i',
            function($matches) use ($baseHost, $proxyBase) {
                $url = $matches[1];
                if (strpos($url, 'http') === 0) {
                    return 'url("' . $proxyBase . urlencode($url) . '")';
                } else {
                    $fullUrl = $baseHost . '/' . ltrim($url, '/');
                    return 'url("' . $proxyBase . urlencode($fullUrl) . '")';
                }
            },
            $content
        );
        
        return $content;
    }
    
    private function processJsContent($content) {
        // JavaScript内のURL書き換え（包括的な処理）
        $baseUrl = parse_url($this->targetUrl);
        $baseHost = $baseUrl['scheme'] . '://' . $baseUrl['host'];
        
        $proxyUrl = parse_url($this->originalUrl);
        $proxyBase = $proxyUrl['scheme'] . '://' . $proxyUrl['host'] . 
                    dirname($proxyUrl['path']) . '/proxy.php?url=';
        
        // 1. 文字列リテラル内のHTTP(S) URLを書き換え
        // シングルクォート文字列
        $content = preg_replace_callback(
            "/'(https?:\/\/[^']*?)'/",
            function($matches) use ($proxyBase) {
                return "'" . $proxyBase . urlencode($matches[1]) . "'";
            },
            $content
        );
        
        // ダブルクォート文字列
        $content = preg_replace_callback(
            '/"(https?:\/\/[^"]*?)"/',
            function($matches) use ($proxyBase) {
                return '"' . $proxyBase . urlencode($matches[1]) . '"';
            },
            $content
        );
        
        // 2. テンプレートリテラル内のURL（ES6バッククォート）
        $content = preg_replace_callback(
            '/`([^`]*https?:\/\/[^`]*?)`/s',
            function($matches) use ($proxyBase) {
                $template = $matches[1];
                // テンプレート内のHTTPSURLを置換
                $template = preg_replace_callback(
                    '/(https?:\/\/[^\s\`\$\{\}]+)/',
                    function($urlMatches) use ($proxyBase) {
                        return $proxyBase . urlencode($urlMatches[1]);
                    },
                    $template
                );
                return '`' . $template . '`';
            },
            $content
        );
        
        // 3. 変数代入パターンの書き換え
        $urlPatterns = [
            // var url = "http://...";
            '/(\burl\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // var apiUrl = "http://...";  
            '/(\bapiUrl\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // var endpoint = "http://...";
            '/(\bendpoint\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // var baseURL = "http://...";
            '/(\bbaseURL\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // var API_BASE = "http://...";
            '/(\bAPI_BASE\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
        ];
        
        foreach ($urlPatterns as $pattern) {
            $content = preg_replace_callback($pattern, function($matches) use ($proxyBase) {
                return $matches[1] . $proxyBase . urlencode($matches[2]) . $matches[3];
            }, $content);
        }
        
        // 4. オブジェクトプロパティ内のURL
        $content = preg_replace_callback(
            '/(\b(?:url|src|href|endpoint|api|base|host)\s*:\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            function($matches) use ($proxyBase) {
                return $matches[1] . $proxyBase . urlencode($matches[2]) . $matches[3];
            },
            $content
        );
        
        // 5. 関数呼び出し内のURL
        $functionPatterns = [
            // fetch("http://...")
            '/(\bfetch\s*\(\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // $.get("http://...")  
            '/(\$\.(?:get|post|ajax|load)\s*\(\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // axios.get("http://...")
            '/(\baxios\.(?:get|post|put|delete|patch)\s*\(\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // XMLHttpRequest.open("GET", "http://...")
            '/(\.open\s*\(\s*["\'][^"\']*["\']\s*,\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // window.open("http://...")
            '/(\bwindow\.open\s*\(\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // location.href = "http://..."
            '/(\blocation\.href\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            // window.location = "http://..."
            '/(\bwindow\.location\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
        ];
        
        foreach ($functionPatterns as $pattern) {
            $content = preg_replace_callback($pattern, function($matches) use ($proxyBase) {
                return $matches[1] . $proxyBase . urlencode($matches[2]) . $matches[3];
            }, $content);
        }
        
        // 6. 配列内のURL
        $content = preg_replace_callback(
            '/(\[\s*["\'])(https?:\/\/[^"\']+)(["\'](?:\s*,\s*["\'][^"\']*["\'])*\s*\])/i',
            function($matches) use ($proxyBase) {
                $urls = $matches[0];
                return preg_replace_callback(
                    '/(["\'])(https?:\/\/[^"\']+)(["\'])/',
                    function($urlMatches) use ($proxyBase) {
                        return $urlMatches[1] . $proxyBase . urlencode($urlMatches[2]) . $urlMatches[3];
                    },
                    $urls
                );
            },
            $content
        );
        
        // 7. 正規表現パターン内のURL（注意深く処理）
        $content = preg_replace_callback(
            '/(new\s+RegExp\s*\(\s*["\'].*?)(https?:\/\/[^"\']+)(.*?["\'])/i',
            function($matches) use ($proxyBase) {
                // 正規表現内のURLは複雑なので、基本的な置換のみ実行
                return $matches[1] . str_replace('/', '\/', $proxyBase . urlencode($matches[2])) . $matches[3];
            },
            $content
        );
        
        // 8. 動的URL構築パターン
        // protocol + '://' + host + path の形式
        $content = preg_replace_callback(
            '/(["\']https?["\'])\s*\+\s*["\']:\/\/["\']\s*\+\s*([^+]+?)(\s*\+\s*[^;,\)\}]+)?/i',
            function($matches) use ($proxyBase) {
                // 動的構築の場合は、実行時の書き換えが必要
                return '"' . $proxyBase . '" + encodeURIComponent(' . $matches[1] . ' + "://" + ' . $matches[2] . 
                       (isset($matches[3]) ? $matches[3] : '') . ')';
            },
            $content
        );
        
        // 9. 相対URLから絶対URLへの変換（同一ドメイン内のAPIコールなど）
        $content = preg_replace_callback(
            '/(\b(?:fetch|get|post|ajax)\s*\(\s*["\'])\/([^"\']+)(["\'])/i',
            function($matches) use ($proxyBase, $baseHost) {
                $fullUrl = $baseHost . '/' . $matches[2];
                return $matches[1] . $proxyBase . urlencode($fullUrl) . $matches[3];
            },
            $content
        );
        
        // 10. WebSocket URLの書き換え
        $content = preg_replace_callback(
            '/(["\'])ws(s)?:\/\/([^"\']+)(["\'])/i',
            function($matches) use ($proxyBase) {
                $wsUrl = 'ws' . $matches[2] . '://' . $matches[3];
                // WebSocketプロキシの実装が必要（ここでは基本的な置換のみ）
                return $matches[1] . $proxyBase . urlencode($wsUrl) . $matches[4];
            },
            $content
        );
        
        // 11. 設定オブジェクト内のURL
        $content = preg_replace_callback(
            '/(\{[^}]*(?:baseURL|url|endpoint|host)[^}]*:\s*["\'])(https?:\/\/[^"\']+)(["\'][^}]*\})/i',
            function($matches) use ($proxyBase) {
                return $matches[1] . $proxyBase . urlencode($matches[2]) . $matches[3];
            },
            $content
        );
        
        // 12. 圧縮されたコード内のパターン（minified JavaScript対応）
        // 圧縮されたコードでは空白が除去されているため、より厳密なパターンが必要
        $content = preg_replace_callback(
            '/([=:,\(])(["\'])(https?:\/\/[^"\']+)(["\'])([,\)\;\}])/i',
            function($matches) use ($proxyBase) {
                return $matches[1] . $matches[2] . $proxyBase . urlencode($matches[3]) . $matches[4] . $matches[5];
            },
            $content
        );
        
        // 13. コメント行の除外（書き換え対象から外す）
        // コメント内のURLは書き換えない
        $content = preg_replace_callback(
            '/\/\*[\s\S]*?\*\/|\/\/.*$/m',
            function($matches) {
                // コメント内容はそのまま返す
                return $matches[0];  
            },
            $content
        );
        
        // 14. 高度なパターン：動的プロパティアクセス
        // obj["url"] = "http://..." のようなパターン
        $content = preg_replace_callback(
            '/(\[["\'](?:url|src|href|endpoint|api)["\']]\s*=\s*["\'])(https?:\/\/[^"\']+)(["\'])/i',
            function($matches) use ($proxyBase) {
                return $matches[1] . $proxyBase . urlencode($matches[2]) . $matches[3];
            },
            $content
        );
        
        // 15. エラーハンドリング：不正な置換を防ぐための最終チェック
        // 既にプロキシURLになっているものは再処理しない
        $content = preg_replace_callback(
            '/(["\'])(' . preg_quote($proxyBase, '/') . ')(' . preg_quote($proxyBase, '/') . '[^"\']+)(["\'])/i',
            function($matches) use ($proxyBase) {
                // 二重プロキシを防ぐ
                return $matches[1] . $proxyBase . urldecode(str_replace($proxyBase, '', $matches[3])) . $matches[4];
            },
            $content
        );
        
        return $content;
    }
    
    private function rewriteJsonUrls($content) {
        // JSON内のURLを書き換え（API レスポンス用）
        $proxyUrl = parse_url($this->originalUrl);
        $proxyBase = $proxyUrl['scheme'] . '://' . $proxyUrl['host'] . 
                    dirname($proxyUrl['path']) . '/proxy.php?url=';
        
        $content = preg_replace_callback(
            '/"(https?:\/\/[^"]+)"/i',
            function($matches) use ($proxyBase) {
                return '"' . $proxyBase . urlencode($matches[1]) . '"';
            },
            $content
        );
        
        return $content;
    }
    
    private function generateProxyScript() {
        // 高度なプロキシ用JavaScriptコードを生成
        $proxyUrl = parse_url($this->originalUrl);
        $proxyBase = $proxyUrl['scheme'] . '://' . $proxyUrl['host'] . 
                    dirname($proxyUrl['path']) . '/proxy.php?url=';
        
        $targetHost = parse_url($this->targetUrl, PHP_URL_HOST);
        $targetScheme = parse_url($this->targetUrl, PHP_URL_SCHEME);
        
        return '
        <script>
        (function() {
            // グローバル設定
            const PROXY_BASE = "' . $proxyBase . '";
            const TARGET_HOST = "' . $targetHost . '";
            const TARGET_SCHEME = "' . $targetScheme . '";
            
            // 詳細なログ出力（デバッグ用）
            const DEBUG = false;
            function log(...args) {
                if (DEBUG) console.log("[PROXY]", ...args);
            }
            
            // プロキシURL生成関数（高度版）
            function proxyUrl(url) {
                if (!url) return url;
                
                // 既にプロキシURLの場合はそのまま返す
                if (url.startsWith(PROXY_BASE)) {
                    return url;
                }
                
                // 絶対URLの場合
                if (url.match(/^https?:\/\//)) {
                    log("Proxying absolute URL:", url);
                    return PROXY_BASE + encodeURIComponent(url);
                }
                
                // プロトコル相対URL（//example.com/path）
                if (url.startsWith("//")) {
                    const fullUrl = TARGET_SCHEME + ":" + url;
                    log("Proxying protocol-relative URL:", fullUrl);
                    return PROXY_BASE + encodeURIComponent(fullUrl);
                }
                
                // 絶対パス（/path）
                if (url.startsWith("/")) {
                    const fullUrl = TARGET_SCHEME + "://" + TARGET_HOST + url;
                    log("Proxying absolute path:", fullUrl);
                    return PROXY_BASE + encodeURIComponent(fullUrl);
                }
                
                // 相対パス（path）
                if (!url.startsWith("#") && !url.startsWith("javascript:") && !url.startsWith("mailto:") && !url.startsWith("tel:")) {
                    const currentPath = window.location.pathname;
                    const basePath = currentPath.substring(0, currentPath.lastIndexOf("/") + 1);
                    const fullUrl = TARGET_SCHEME + "://" + TARGET_HOST + basePath + url;
                    log("Proxying relative path:", fullUrl);
                    return PROXY_BASE + encodeURIComponent(fullUrl);
                }
                
                return url;
            }
            
            // オリジナル関数の保存
            const originalXHR = window.XMLHttpRequest;
            const originalFetch = window.fetch;
            const originalOpen = window.open;
            const originalAssign = window.location.assign;
            const originalReplace = window.location.replace;
            const originalPushState = history.pushState;
            const originalReplaceState = history.replaceState;
            
            // XMLHttpRequestの包括的な書き換え
            window.XMLHttpRequest = function() {
                const xhr = new originalXHR();
                const originalOpen = xhr.open;
                const originalSend = xhr.send;
                const originalSetRequestHeader = xhr.setRequestHeader;
                
                // プロキシ固有のヘッダー管理
                let proxyHeaders = {};
                
                xhr.open = function(method, url, async, user, password) {
                    log("XHR open:", method, url);
                    url = proxyUrl(url);
                    return originalOpen.call(this, method, url, async, user, password);
                };
                
                xhr.setRequestHeader = function(name, value) {
                    // 特定のヘッダーはプロキシで処理
                    if (name.toLowerCase() === "referer") {
                        proxyHeaders[name] = value;
                        return;
                    }
                    return originalSetRequestHeader.call(this, name, value);
                };
                
                xhr.send = function(data) {
                    // プロキシヘッダーを適用
                    for (const [name, value] of Object.entries(proxyHeaders)) {
                        originalSetRequestHeader.call(this, name, value);
                    }
                    return originalSend.call(this, data);
                };
                
                return xhr;
            };
            
            // fetchの完全な書き換え
            if (originalFetch) {
                window.fetch = function(input, init) {
                    let url, options = init || {};
                    
                    if (typeof input === "string") {
                        url = proxyUrl(input);
                    } else if (input instanceof Request) {
                        url = proxyUrl(input.url);
                        // Request オブジェクトから設定を複製
                        options = {
                            method: input.method,
                            headers: input.headers,
                            body: input.body,
                            mode: input.mode,
                            credentials: input.credentials,
                            cache: input.cache,
                            redirect: input.redirect,
                            referrer: input.referrer,
                            ...options
                        };
                    } else {
                        url = input;
                    }
                    
                    log("Fetch request:", url, options);
                    
                    // ヘッダーの調整
                    if (options.headers) {
                        const headers = new Headers(options.headers);
                        // CORSヘッダーの調整
                        if (headers.has("origin")) {
                            headers.set("origin", TARGET_SCHEME + "://" + TARGET_HOST);
                        }
                        options.headers = headers;
                    }
                    
                    return originalFetch(url, options);
                };
            }
            
            // jQuery AJAX の書き換え（jQueryが存在する場合）
            if (window.jQuery || window.$) {
                const $ = window.jQuery || window.$;
                if ($.ajaxPrefilter) {
                    $.ajaxPrefilter(function(options, originalOptions, jqXHR) {
                        if (options.url) {
                            log("jQuery AJAX:", options.url);
                            options.url = proxyUrl(options.url);
                        }
                    });
                }
            }
            
            // Axios の書き換え（Axiosが存在する場合）
            if (window.axios) {
                // リクエストインターセプターを追加
                window.axios.interceptors.request.use(function(config) {
                    if (config.url) {
                        log("Axios request:", config.url);
                        config.url = proxyUrl(config.url);
                    }
                    return config;
                });
            }
            
            // 位置情報とページ遷移の書き換え
            Object.defineProperty(window.location, "assign", {
                value: function(url) {
                    log("Location assign:", url);
                    return originalAssign.call(this, proxyUrl(url));
                }
            });
            
            Object.defineProperty(window.location, "replace", {
                value: function(url) {
                    log("Location replace:", url);
                    return originalReplace.call(this, proxyUrl(url));
                }
            });
            
            // window.open の書き換え
            window.open = function(url, name, features) {
                if (url) {
                    log("Window open:", url);
                    url = proxyUrl(url);
                }
                return originalOpen.call(this, url, name, features);
            };
            
            // History API の書き換え
            history.pushState = function(state, title, url) {
                if (url && !url.startsWith(PROXY_BASE) && !url.startsWith("#")) {
                    log("History pushState:", url);
                    url = proxyUrl(url);
                }
                return originalPushState.call(this, state, title, url);
            };
            
            history.replaceState = function(state, title, url) {
                if (url && !url.startsWith(PROXY_BASE) && !url.startsWith("#")) {
                    log("History replaceState:", url);
                    url = proxyUrl(url);
                }
                return originalReplaceState.call(this, state, title, url);
            };
            
            // DOM要素の動的書き換え
            const observer = new MutationObserver(function(mutations) {
                mutations.forEach(function(mutation) {
                    if (mutation.type === "childList") {
                        mutation.addedNodes.forEach(function(node) {
                            if (node.nodeType === Node.ELEMENT_NODE) {
                                rewriteElementUrls(node);
                            }
                        });
                    } else if (mutation.type === "attributes") {
                        if (["src", "href", "action"].includes(mutation.attributeName)) {
                            rewriteElementUrls(mutation.target);
                        }
                    }
                });
            });
            
            function rewriteElementUrls(element) {
                // 新しく追加された要素のURLを書き換え
                const urlAttributes = ["src", "href", "action"];
                
                urlAttributes.forEach(function(attr) {
                    if (element.hasAttribute && element.hasAttribute(attr)) {
                        const url = element.getAttribute(attr);
                        const newUrl = proxyUrl(url);
                        if (url !== newUrl) {
                            log("Rewriting element URL:", url, "->", newUrl);
                            element.setAttribute(attr, newUrl);
                        }
                    }
                });
                
                // 子要素も処理
                if (element.querySelectorAll) {
                    const children = element.querySelectorAll("[src], [href], [action]");
                    children.forEach(rewriteElementUrls);
                }
            }
            
            // DOM監視を開始
            observer.observe(document.body, {
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: ["src", "href", "action"]
            });
            
            // PostMessage の書き換え（iframe通信用）
            const originalPostMessage = window.postMessage;
            if (originalPostMessage) {
                window.postMessage = function(message, targetOrigin, transfer) {
                    if (targetOrigin && targetOrigin !== "*" && !targetOrigin.startsWith(PROXY_BASE)) {
                        log("PostMessage target origin:", targetOrigin);
                        targetOrigin = proxyUrl(targetOrigin);
                    }
                    return originalPostMessage.call(this, message, targetOrigin, transfer);
                };
            }
            
            // WebSocket の書き換え
            const originalWebSocket = window.WebSocket;
            if (originalWebSocket) {
                window.WebSocket = function(url, protocols) {
                    if (url && (url.startsWith("ws://") || url.startsWith("wss://"))) {
                        log("WebSocket URL:", url);
                        // WebSocketプロキシの実装が必要
                        // ここでは基本的な置換のみ
                        url = proxyUrl(url);
                    }
                    return new originalWebSocket(url, protocols);
                };
            }
            
            // イベントリスナーの後処理
            document.addEventListener("DOMContentLoaded", function() {
                log("DOM loaded, performing final URL rewrite");
                rewriteElementUrls(document.body);
            });
            
            // エラーハンドリング
            window.addEventListener("error", function(e) {
                if (e.filename && e.filename.includes("proxy.php")) {
                    log("Proxy error:", e.message, e.filename, e.lineno);
                }
            });
            
            log("Proxy script initialized");
        })();
        </script>';
    }
    
    private function handleError($e) {
        // エラーログの記録
        error_log('Proxy Error: ' . $e->getMessage() . ' | URL: ' . $this->targetUrl);
        
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'error' => true,
            'message' => 'Proxy request failed',
            'details' => $e->getMessage(),
            'timestamp' => date('c'),
            'request_id' => uniqid()
        ]);
    }
    
    public function __destruct() {
        // クリーンアップ処理（古いCookieファイルの削除等）
        $this->cleanupOldCookies();
    }
    
    private function cleanupOldCookies() {
        $cookieDir = sys_get_temp_dir() . '/proxy_cookies';
        if (is_dir($cookieDir)) {
            $files = glob($cookieDir . '/cookies_*.txt');
            foreach ($files as $file) {
                if (filemtime($file) < time() - 3600) { // 1時間以上古いファイルを削除
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
