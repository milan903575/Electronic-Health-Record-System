<?php
// Enhanced session security - MUST be set BEFORE session_start()
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.cookie_samesite', 'Strict');

// Start session AFTER setting session configuration
session_start();

// Security Headers Manager Class
class SecurityHeadersManager {
    private $config = [
        'hsts' => [
            'enabled' => true,
            'max_age' => 31536000,
            'include_subdomains' => true,
            'preload' => false
        ],
        'csp' => [
            'enabled' => true,
            'report_only' => false,
            'directives' => []
        ],
        'frame_options' => 'DENY',
        'content_type_options' => true,
        'xss_protection' => true,
        'referrer_policy' => 'strict-origin-when-cross-origin',
        'permissions_policy' => []
    ];

    public function __construct(array $config = []) {
        $this->config = array_merge($this->config, $config);
    }

    public function sendAllHeaders() {
        $this->sendHSTS();
        $this->sendCSP();
        $this->sendFrameOptions();
        $this->sendContentTypeOptions();
        $this->sendXSSProtection();
        $this->sendReferrerPolicy();
        $this->sendPermissionsPolicy();
        $this->sendAdditionalHeaders();
    }

    private function sendHSTS() {
        if (!$this->config['hsts']['enabled'] || !$this->isHTTPS()) {
            return;
        }
        
        $header = 'Strict-Transport-Security: max-age=' . $this->config['hsts']['max_age'];
        if ($this->config['hsts']['include_subdomains']) {
            $header .= '; includeSubDomains';
        }
        if ($this->config['hsts']['preload']) {
            $header .= '; preload';
        }
        header($header);
    }

    private function sendCSP() {
        if (!$this->config['csp']['enabled']) {
            return;
        }
        
        $directives = $this->config['csp']['directives'];
        if (empty($directives)) {
            $directives = [
                'default-src' => ["'self'", 'data:'],
                'script-src' => ["'self'", "'unsafe-inline'", 'https://code.jquery.com', 'https://cdn.jsdelivr.net'],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
                'font-src' => ["'self'", 'https://cdnjs.cloudflare.com'],
                'media-src' => ["'self'", 'data:', 'blob:'],
                'img-src' => ["'self'", 'data:'],
                'connect-src' => ["'self'"],
                'object-src' => ["'none'"],
                'frame-ancestors' => ["'none'"]
            ];
        }
        
        $policy = [];
        foreach ($directives as $directive => $sources) {
            $policy[] = $directive . ' ' . implode(' ', $sources);
        }
        
        $headerName = ($this->config['csp']['report_only'] ?? false) ? 
            'Content-Security-Policy-Report-Only' : 
            'Content-Security-Policy';
        header($headerName . ': ' . implode('; ', $policy));
    }

    private function sendFrameOptions() {
        if ($this->config['frame_options']) {
            header('X-Frame-Options: ' . $this->config['frame_options']);
        }
    }

    private function sendContentTypeOptions() {
        if ($this->config['content_type_options']) {
            header('X-Content-Type-Options: nosniff');
        }
    }

    private function sendXSSProtection() {
        if ($this->config['xss_protection']) {
            header('X-XSS-Protection: 1; mode=block');
        }
    }

    private function sendReferrerPolicy() {
        if ($this->config['referrer_policy']) {
            header('Referrer-Policy: ' . $this->config['referrer_policy']);
        }
    }

    private function sendPermissionsPolicy() {
        if (!empty($this->config['permissions_policy'])) {
            $directives = [];
            foreach ($this->config['permissions_policy'] as $feature => $allowlist) {
                if (empty($allowlist)) {
                    $directives[] = "{$feature}=()";
                } else {
                    $allowlistStr = implode(' ', $allowlist);
                    $directives[] = "{$feature}=({$allowlistStr})";
                }
            }
            header('Permissions-Policy: ' . implode(', ', $directives));
        }
    }

    private function sendAdditionalHeaders() {
        header('X-Permitted-Cross-Domain-Policies: none');
        header('Cross-Origin-Embedder-Policy: require-corp');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
        header('Pragma: no-cache');
    }

    private function isHTTPS() {
        return isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ||
               isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https';
    }
}

// Initialize and send security headers
$securityHeaders = new SecurityHeadersManager([
    'csp' => [
        'enabled' => true,
        'directives' => [
            'default-src' => ["'self'", 'data:'],
            'script-src' => ["'self'", "'unsafe-inline'", 'https://code.jquery.com', 'https://cdn.jsdelivr.net'],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
            'font-src' => ["'self'", 'https://cdnjs.cloudflare.com'],
            'media-src' => ["'self'", 'data:', 'blob:'],
            'img-src' => ["'self'", 'data:'],
            'connect-src' => ["'self'"],
            'form-action' => ["'self'"],
            'frame-ancestors' => ["'none'"],
            'object-src' => ["'none'"],
            'base-uri' => ["'self'"]
        ]
    ],
    'permissions_policy' => [
        'camera' => [],
        'microphone' => [],
        'geolocation' => [],
        'payment' => []
    ]
]);
$securityHeaders->sendAllHeaders();

include '../../connection.php';

// CSRF Token Management
function generateCSRFToken() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Generate CSRF token for the session
$csrf_token = generateCSRFToken();

// Enhanced Encryption/Decryption class with proper key management
class EncryptionHandler {
    private $encryption_key;
    private $cipher_method = 'aes-256-gcm';
    
    public function __construct() {
        // Use the same key path as your encryption code
        $key_path = '../../../encryption_key.key';
        
        if (!file_exists($key_path)) {
            throw new Exception('Encryption key file not found: ' . $key_path);
        }
        
        $secret_key = trim(file_get_contents($key_path));
        
        if (empty($secret_key)) {
            throw new Exception('Encryption key is empty or invalid');
        }
        
        // Use the key directly as it comes from the file (same as encryption)
        $this->encryption_key = $secret_key;
    }
    
    /**
     * Decrypt data using AES-256-GCM with enhanced error handling
     */
    public function decrypt($encrypted_data, $iv, $auth_tag) {
        // Validate inputs
        if (empty($encrypted_data) || empty($iv) || empty($auth_tag)) {
            error_log("Decryption Error: Missing required data");
            return false;
        }
        
        try {
            // Attempt decryption with the same parameters as encryption
            $decrypted = openssl_decrypt(
                $encrypted_data,
                $this->cipher_method,
                $this->encryption_key,
                0, // Use 0 flag (same as encryption)
                $iv,
                $auth_tag
            );
            
            if ($decrypted === false) {
                $error = openssl_error_string();
                error_log("OpenSSL Decryption Error: " . $error);
                return false;
            }
            
            return $decrypted;
            
        } catch (Exception $e) {
            error_log("Decryption Exception: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Decrypt video and return as base64 for display
     */
    public function decryptVideoToBase64($encrypted_video, $iv, $auth_tag) {
        $decrypted_video = $this->decrypt($encrypted_video, $iv, $auth_tag);
        if ($decrypted_video === false) {
            return false;
        }
        
        return base64_encode($decrypted_video);
    }
    
    /**
     * Decrypt text data with fallback methods
     */
    public function decryptText($encrypted_data, $iv, $auth_tag) {
        // Primary decryption attempt
        $result = $this->decrypt($encrypted_data, $iv, $auth_tag);
        
        if ($result !== false) {
            return $result;
        }
        
        // Log the failure for debugging
        error_log("Text decryption failed for data length: " . strlen($encrypted_data));
        error_log("IV length: " . strlen($iv) . ", Auth tag length: " . strlen($auth_tag));
        
        return false;
    }
}

// Security logging class - integrated
class SecurityLogger {
    private $conn;
    
    public function __construct($connection) {
        $this->conn = $connection;
    }
    
    public function logEvent($email, $eventType, $additionalInfo = null) {
        $ipAddress = $this->getClientIp();
        $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        $userAgent = htmlspecialchars($userAgent, ENT_QUOTES, 'UTF-8');
        
        // Check if security_logs table exists, if not create it
        $this->createSecurityLogsTable();
        
        $stmt = $this->conn->prepare("INSERT INTO security_logs (email, event_type, ip_address, user_agent, additional_info, timestamp) VALUES (?, ?, ?, ?, ?, NOW())");
        if ($stmt) {
            $stmt->bind_param("sssss", $email, $eventType, $ipAddress, $userAgent, $additionalInfo);
            $stmt->execute();
            $stmt->close();
        }
    }
    
    private function createSecurityLogsTable() {
        $sql = "CREATE TABLE IF NOT EXISTS security_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email VARCHAR(255) NOT NULL,
            event_type VARCHAR(100) NOT NULL,
            ip_address VARCHAR(45) NOT NULL,
            user_agent TEXT,
            additional_info TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )";
        $this->conn->query($sql);
    }
    
    private function getClientIp() {
        $ipKeys = ['HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
        
        foreach ($ipKeys as $key) {
            if (array_key_exists($key, $_SERVER) === true) {
                foreach (explode(',', $_SERVER[$key]) as $ip) {
                    $ip = trim($ip);
                    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                        return $ip;
                    }
                }
            }
        }
        return $_SERVER['REMOTE_ADDR'] ?? 'Unknown';
    }
}

// Handle AJAX requests for security logging and session extension
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    header('Content-Type: application/json');
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit;
    }
    
    $securityLogger = new SecurityLogger($conn);
    $patient_email = $_SESSION['email'] ?? 'Unknown user';
    
    switch ($_POST['action']) {
        case 'log_security_event':
            $eventType = $_POST['event_type'] ?? 'unknown';
            $message = $_POST['message'] ?? '';
            $securityLogger->logEvent($patient_email, $eventType, $message);
            echo json_encode(['success' => true]);
            break;
            
        case 'extend_session':
            $_SESSION['last_activity'] = time();
            echo json_encode(['success' => true]);
            break;
            
        default:
            http_response_code(400);
            echo json_encode(['error' => 'Invalid action']);
    }
    exit;
}

// Initialize classes with proper error handling
try {
    $securityLogger = new SecurityLogger($conn);
    $encryptionHandler = new EncryptionHandler();
} catch (Exception $e) {
    error_log("Initialization Error: " . $e->getMessage());
    die("System error: Unable to initialize encryption handler. Please contact support.");
}

// Session validation function
function validateSession($securityLogger) {
    if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] != 'patient') {
        $email = $_SESSION['email'] ?? 'Unauthorized user trying to access this page';
        $securityLogger->logEvent($email, 'unauthorized_access', 'Attempted access to private history page without proper authentication');
        header("Location: ../../logout.php");
        exit;
    }
    
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > 300) {
        $email = $_SESSION['email'] ?? 'Unknown user';
        $securityLogger->logEvent($email, 'session_timeout', 'Session expired after 5 minutes of inactivity');
        session_unset();
        session_destroy();
        header("Location: ../../logout.php?reason=timeout");
        exit;
    }
    
    if (isset($_SESSION['ip_address']) && $_SESSION['ip_address'] !== $_SERVER['REMOTE_ADDR']) {
        $email = $_SESSION['email'] ?? 'Unknown user';
        $securityLogger->logEvent($email, 'ip_change_detected', 'Session IP changed from ' . $_SESSION['ip_address'] . ' to ' . $_SERVER['REMOTE_ADDR']);
        session_unset();
        session_destroy();
        header("Location: ../../logout.php?reason=security");
        exit;
    }
    
    $currentUserAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (isset($_SESSION['user_agent_hash']) && $_SESSION['user_agent_hash'] !== hash('sha256', $currentUserAgent)) {
        $email = $_SESSION['email'] ?? 'Unknown user';
        $securityLogger->logEvent($email, 'user_agent_change', 'User agent changed during session');
        session_unset();
        session_destroy();
        header("Location: ../../logout.php?reason=security");
        exit;
    }
    
    $_SESSION['last_activity'] = time();
    if (!isset($_SESSION['ip_address'])) {
        $_SESSION['ip_address'] = $_SERVER['REMOTE_ADDR'];
    }
    if (!isset($_SESSION['user_agent_hash'])) {
        $_SESSION['user_agent_hash'] = hash('sha256', $currentUserAgent);
    }
}

// Validate session
validateSession($securityLogger);

$patient_id = $_SESSION['user_id'];
$patient_email = $_SESSION['email'] ?? 'Unknown user';

// Validate history_id parameter
if (!isset($_GET['history_id']) || !is_numeric($_GET['history_id'])) {
    $securityLogger->logEvent($patient_email, 'invalid_parameter', 'Invalid or missing history_id parameter');
    header("Location: ../private_problems.php?error=invalid_request");
    exit;
}

$history_id = (int)$_GET['history_id'];

// Verify ownership
$verify_stmt = $conn->prepare("SELECT pp.id, pp.patient_id FROM private_problems pp WHERE pp.id = ? AND pp.patient_id = ?");

if (!$verify_stmt) {
    $securityLogger->logEvent($patient_email, 'database_error', 'Failed to prepare verification statement');
    header("Location: ../private_problems.php?error=system_error");
    exit;
}

$verify_stmt->bind_param("ii", $history_id, $patient_id);
$verify_stmt->execute();
$verify_result = $verify_stmt->get_result();

if ($verify_result->num_rows === 0) {
    $securityLogger->logEvent($patient_email, 'unauthorized_access', 'Attempted to access history_id: ' . $history_id . ' not belonging to patient');
    header("Location: ../private_problems.php?error=access_denied");
    exit;
}

$verify_stmt->close();

// Log legitimate access
$securityLogger->logEvent($patient_email, 'history_access', 'Accessed private history ID: ' . $history_id);

// Fetch detailed history information
$history_stmt = $conn->prepare("
    SELECT 
        pp.id,
        pp.problem_description,
        pp.iv,
        pp.auth_tag,
        pp.video_file,
        pp.video_iv,
        pp.video_auth_tag,
        pp.created_at as submission_date,
        pp.updated_at,
        pp.status,
        pp.doctor_solution,
        pp.solution_iv,
        pp.solution_auth_tag,
        CONCAT(d.first_name, ' ', d.last_name) AS doctor_name,
        d.specialization,
        h.hospital_name,
        h.city
    FROM private_problems pp
    LEFT JOIN doctors d ON pp.doctor_id = d.id
    LEFT JOIN hospitals h ON pp.hospital_id = h.id
    WHERE pp.id = ? AND pp.patient_id = ?
");

if (!$history_stmt) {
    $securityLogger->logEvent($patient_email, 'database_error', 'Failed to prepare history statement');
    header("Location: ../private_problems.php?error=system_error");
    exit;
}

$history_stmt->bind_param("ii", $history_id, $patient_id);
$history_stmt->execute();
$history_result = $history_stmt->get_result();

if ($history_result->num_rows === 0) {
    $securityLogger->logEvent($patient_email, 'data_not_found', 'History not found for ID: ' . $history_id);
    header("Location: ../private_problems.php?error=not_found");
    exit;
}

$history_data = $history_result->fetch_assoc();
$history_stmt->close();

// Decrypt the problem description with enhanced error handling
$decrypted_description = '';
if ($history_data['problem_description'] && $history_data['iv'] && $history_data['auth_tag']) {
    $decrypted_description = $encryptionHandler->decryptText(
        $history_data['problem_description'],
        $history_data['iv'],
        $history_data['auth_tag']
    );
    
    if ($decrypted_description === false) {
        $securityLogger->logEvent($patient_email, 'decryption_error', 'Failed to decrypt problem description for ID: ' . $history_id);
        $decrypted_description = '[Error: Unable to decrypt problem description - Please contact support]';
    }
} else {
    $decrypted_description = '[Error: Missing encryption data for problem description]';
}

// Decrypt the doctor solution if available
$decrypted_solution = '';
if ($history_data['doctor_solution'] && $history_data['solution_iv'] && $history_data['solution_auth_tag']) {
    $decrypted_solution = $encryptionHandler->decryptText(
        $history_data['doctor_solution'],
        $history_data['solution_iv'],
        $history_data['solution_auth_tag']
    );
    
    if ($decrypted_solution === false) {
        $securityLogger->logEvent($patient_email, 'decryption_error', 'Failed to decrypt doctor solution for ID: ' . $history_id);
        $decrypted_solution = '[Error: Unable to decrypt doctor solution - Please contact support]';
    }
}

// Prepare video data for display
$video_data_url = '';
$has_video = false;
if ($history_data['video_file'] && $history_data['video_iv'] && $history_data['video_auth_tag']) {
    $video_base64 = $encryptionHandler->decryptVideoToBase64(
        $history_data['video_file'],
        $history_data['video_iv'],
        $history_data['video_auth_tag']
    );
    
    if ($video_base64 !== false) {
        $video_data_url = 'data:video/mp4;base64,' . $video_base64;
        $has_video = true;
    } else {
        $securityLogger->logEvent($patient_email, 'decryption_error', 'Failed to decrypt video for ID: ' . $history_id);
    }
}

// Generate CSRF token
$csrfToken = generateCSRFToken();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrfToken) ?>">
    <title>Medical History Details - Secure Portal</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2c3e50;
            --secondary-color: #3498db;
            --accent-color: #e74c3c;
            --light-color: #ecf0f1;
            --dark-color: #34495e;
            --success-color: #2ecc71;
            --warning-color: #f39c12;
            --danger-color: #e74c3c;
            --info-color: #17a2b8;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: var(--dark-color);
            line-height: 1.6;
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
            -webkit-touch-callout: none;
            -webkit-tap-highlight-color: transparent;
        }
        
        .security-banner {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            padding: 15px;
            text-align: center;
            font-weight: 600;
            box-shadow: 0 2px 10px rgba(231, 76, 60, 0.3);
        }
        
        .session-timer {
            position: fixed;
            top: 20px;
            right: 20px;
            background: rgba(231, 76, 60, 0.9);
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: 600;
            z-index: 1050;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        }
        
        .session-warning {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            z-index: 1060;
            text-align: center;
            border: 3px solid var(--danger-color);
            display: none;
        }
        
        .main-container {
            max-width: 1400px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            overflow: hidden;
            margin-bottom: 25px;
        }
        
        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 20px 25px;
            border-bottom: none;
        }
        
        .card-body {
            padding: 30px;
        }
        
        .status-badge {
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
        }
        
        .status-pending {
            background-color: rgba(243, 156, 18, 0.1);
            color: var(--warning-color);
            border: 1px solid var(--warning-color);
        }
        
        .status-completed {
            background-color: rgba(46, 204, 113, 0.1);
            color: var(--success-color);
            border: 1px solid var(--success-color);
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 0;
            border-bottom: 1px solid #eee;
        }
        
        .info-row:last-child {
            border-bottom: none;
        }
        
        .info-label {
            font-weight: 600;
            color: var(--dark-color);
            min-width: 150px;
        }
        
        .info-value {
            flex: 1;
            text-align: right;
        }
        
        .problem-description {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 10px;
            border-left: 4px solid var(--info-color);
            margin: 20px 0;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        
        .response-section {
            background-color: rgba(46, 204, 113, 0.05);
            padding: 25px;
            border-radius: 10px;
            border-left: 4px solid var(--success-color);
            margin: 20px 0;
        }
        
        .video-container {
            text-align: center;
            margin: 30px 0;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 15px;
            position: relative;
        }
        
        .video-player {
            width: 100%;
            max-width: 900px;
            height: auto;
            min-height: 500px;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
            background-color: #000;
            position: relative;
        }
        
        .video-protection-notice {
            background: linear-gradient(135deg, #e74c3c, #c0392b);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 15px 0;
            text-align: center;
            font-weight: 600;
        }
        
        .btn-back {
            background-color: var(--secondary-color);
            border: none;
            color: white;
            padding: 12px 25px;
            font-weight: 600;
            border-radius: 8px;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            transition: all 0.3s;
        }
        
        .btn-back:hover {
            background-color: #2980b9;
            color: white;
            transform: translateY(-2px);
        }
        
        .no-response {
            text-align: center;
            padding: 40px;
            color: #7f8c8d;
        }
        
        .timeline-item {
            position: relative;
            padding-left: 30px;
            margin-bottom: 20px;
        }
        
        .timeline-item::before {
            content: '';
            position: absolute;
            left: 8px;
            top: 8px;
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background-color: var(--secondary-color);
        }
        
        .timeline-item::after {
            content: '';
            position: absolute;
            left: 13px;
            top: 20px;
            width: 2px;
            height: calc(100% - 12px);
            background-color: #ddd;
        }
        
        .timeline-item:last-child::after {
            display: none;
        }
        
        .error-message {
            background-color: rgba(231, 76, 60, 0.1);
            border: 1px solid var(--danger-color);
            color: var(--danger-color);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        
        .security-warning-popup {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            z-index: 2000;
            text-align: center;
            border: 3px solid var(--danger-color);
            display: none;
            min-width: 400px;
        }
        
        .security-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.7);
            z-index: 1999;
            display: none;
        }
        
        /* Disable text selection */
        * {
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }
        
        /* Allow video controls to be clickable */
        video, video::-webkit-media-controls-panel, video::-webkit-media-controls-play-button, 
        video::-webkit-media-controls-volume-slider, video::-webkit-media-controls-timeline,
        video::-webkit-media-controls-current-time-display, video::-webkit-media-controls-time-remaining-display,
        video::-webkit-media-controls-mute-button, video::-webkit-media-controls-volume-control-container {
            pointer-events: auto !important;
        }
        
        /* Hide specific video controls but keep play button */
        video::-webkit-media-controls-download-button {
            display: none !important;
        }
        
        video::-webkit-media-controls-fullscreen-button {
            display: none !important;
        }
        
        video::-webkit-media-controls-picture-in-picture-button {
            display: none !important;
        }
        
        @media (max-width: 768px) {
            .main-container {
                margin: 20px auto;
                max-width: 100%;
            }
            
            .card-body {
                padding: 20px;
            }
            
            .info-row {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .info-value {
                text-align: left;
                margin-top: 5px;
            }
            
            .session-timer {
                position: relative;
                top: auto;
                right: auto;
                margin-bottom: 20px;
                text-align: center;
            }
            
            .video-player {
                min-height: 300px;
            }
        }
    </style>
</head>
<body>
    <!-- Hidden CSRF token for JavaScript -->
    <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($csrfToken) ?>">

    <div class="security-overlay" id="securityOverlay"></div>
    <div class="security-warning-popup" id="securityWarning">
        <div class="mb-3">
            <i class="fas fa-shield-alt" style="font-size: 3rem; color: var(--danger-color);"></i>
        </div>
        <h4 class="text-danger">Security Alert</h4>
        <p id="securityMessage">This action is not allowed for security reasons.</p>
        <button class="btn btn-danger" onclick="closeSecurityWarning()">I Understand</button>
    </div>

    <div class="security-banner">
        <i class="fas fa-shield-alt me-2"></i>
        <strong>SECURE</strong> - This page contains sensitive medical information. Unauthorized copying, downloading, or sharing is strictly prohibited. For your safety, you will be automatically logged out after 5 minutes of inactivity.
    </div>

    <div class="session-timer" id="sessionTimer">
        <i class="fas fa-clock me-2"></i>
        Session expires in: <span id="countdown">5:00</span>
    </div>

    <div class="session-warning" id="sessionWarning">
        <div class="mb-3">
            <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: var(--danger-color);"></i>
        </div>
        <h4 class="text-danger">Security Warning</h4>
        <p>Your session will expire in <span id="warningCountdown">60</span> seconds due to inactivity.</p>
        <p><strong>This is for your safety as this page contains very sensitive information.</strong></p>
        <button class="btn btn-primary" onclick="extendSession()">Stay Logged In</button>
        <button class="btn btn-secondary ms-2" onclick="logoutNow()">Logout Now</button>
    </div>

    <div class="main-container">
        <!-- Back Button -->
        <div class="mb-4">
            <a href="../patient_history.php" class="btn-back">
                <i class="fas fa-arrow-left me-2"></i>Back to Problems List
            </a>
        </div>

        <!-- Main History Card -->
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h2 class="mb-0"><i class="fas fa-file-medical me-2"></i>Medical History Details</h2>
                    <span class="status-badge status-<?php echo strtolower($history_data['status']); ?>">
                        <?php echo htmlspecialchars($history_data['status'], ENT_QUOTES, 'UTF-8'); ?>
                    </span>
                </div>
            </div>
            <div class="card-body">
                <!-- Basic Information -->
                
                <div class="info-row">
                    <span class="info-label"><i class="fas fa-calendar me-2"></i>Submission Date:</span>
                    <span class="info-value"><?php echo date('F j, Y \a\t g:i A', strtotime($history_data['submission_date'])); ?></span>
                </div>
                
                <?php if ($history_data['updated_at']): ?>
                <div class="info-row">
                    <span class="info-label"><i class="fas fa-clock me-2"></i>Last Updated:</span>
                    <span class="info-value"><?php echo date('F j, Y \a\t g:i A', strtotime($history_data['updated_at'])); ?></span>
                </div>
                <?php endif; ?>
                
                <?php if ($history_data['doctor_name']): ?>
                <div class="info-row">
                    <span class="info-label"><i class="fas fa-user-md me-2"></i>Doctor:</span>
                    <span class="info-value">Dr. <?php echo htmlspecialchars($history_data['doctor_name'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label"><i class="fas fa-stethoscope me-2"></i>Specialization:</span>
                    <span class="info-value"><?php echo htmlspecialchars($history_data['specialization'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                
                <div class="info-row">
                    <span class="info-label"><i class="fas fa-hospital me-2"></i>Hospital:</span>
                    <span class="info-value"><?php echo htmlspecialchars($history_data['hospital_name'], ENT_QUOTES, 'UTF-8'); ?>, <?php echo htmlspecialchars($history_data['city'], ENT_QUOTES, 'UTF-8'); ?></span>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Problem Description -->
        <div class="card">
            <div class="card-header">
                <h3 class="mb-0"><i class="fas fa-notes-medical me-2"></i>Problem Description</h3>
            </div>
            <div class="card-body">
                <div class="problem-description">
                    <?php 
                    if (strpos($decrypted_description, '[Error:') === 0) {
                        echo '<div class="error-message">' . htmlspecialchars($decrypted_description, ENT_QUOTES, 'UTF-8') . '</div>';
                    } else {
                        echo htmlspecialchars($decrypted_description, ENT_QUOTES, 'UTF-8');
                    }
                    ?>
                </div>
                
                <?php if ($has_video): ?>
                <div class="video-container">
                    <div class="video-protection-notice">
                        <i class="fas fa-shield-alt me-2"></i>
                        <strong>PROTECTED MEDICAL VIDEO</strong> - This video is encrypted and protected. Right-click, downloading, and copying are disabled for your privacy and security.
                    </div>
                    <h5><i class="fas fa-video me-2"></i>Attached Medical Video</h5>
                    <div style="position: relative; display: inline-block;">
                        <video 
                            class="video-player" 
                            controls 
                            controlsList="nodownload nofullscreen noremoteplayback" 
                            disablePictureInPicture
                            oncontextmenu="showSecurityWarning('Video downloading and right-click are disabled to protect medical content.'); return false;"
                            ondragstart="return false;"
                            onselectstart="return false;"
                            style="pointer-events: auto;"
                        >
                            <source src="<?php echo $video_data_url; ?>" type="video/mp4">
                            Your browser does not support the video tag.
                        </video>
                    </div>
                    <div class="mt-3">
                        <small class="text-muted">
                            <i class="fas fa-info-circle me-1"></i>
                            This video is securely encrypted and can only be viewed in this portal. Download and sharing features are disabled for patient privacy protection.
                        </small>
                    </div>
                </div>
                <?php elseif ($history_data['video_file']): ?>
                <div class="video-container">
                    <h5><i class="fas fa-video me-2"></i>Attached Video</h5>
                    <div class="error-message">
                        <i class="fas fa-exclamation-triangle me-2"></i>
                        Error: Unable to decrypt and display video file. Please contact support.
                    </div>
                </div>
                <?php endif; ?>
            </div>
        </div>

        <!-- Doctor's Response -->
        <?php if ($decrypted_solution && strpos($decrypted_solution, '[Error:') !== 0): ?>
        <div class="card">
            <div class="card-header">
                <div class="d-flex justify-content-between align-items-center">
                    <h3 class="mb-0"><i class="fas fa-reply me-2"></i>Doctor's Response</h3>
                    <?php if ($history_data['updated_at']): ?>
                    <small class="text-light">
                        <i class="fas fa-clock me-1"></i>
                        <?php echo date('F j, Y \a\t g:i A', strtotime($history_data['updated_at'])); ?>
                    </small>
                    <?php endif; ?>
                </div>
            </div>
            <div class="card-body">
                <!-- Timeline of Response -->
                <div class="timeline-item">
                    <div class="timeline-content">
                        <h6><i class="fas fa-calendar-plus me-2"></i>Consultation Submitted</h6>
                        <p class="text-muted mb-0"><?php echo date('F j, Y \a\t g:i A', strtotime($history_data['submission_date'])); ?></p>
                    </div>
                </div>
                
                <?php if ($history_data['updated_at']): ?>
                <div class="timeline-item">
                    <div class="timeline-content">
                        <h6><i class="fas fa-reply me-2"></i>Doctor Responded</h6>
                        <p class="text-muted mb-0"><?php echo date('F j, Y \a\t g:i A', strtotime($history_data['updated_at'])); ?></p>
                    </div>
                </div>
                <?php endif; ?>
                
                <div class="response-section">
                    <h5><i class="fas fa-comment-medical me-2"></i>Medical Solution</h5>
                    <p class="mb-0"><?php echo nl2br(htmlspecialchars($decrypted_solution, ENT_QUOTES, 'UTF-8')); ?></p>
                </div>
            </div>
        </div>
        <?php elseif ($decrypted_solution && strpos($decrypted_solution, '[Error:') === 0): ?>
        <div class="card">
            <div class="card-header">
                <h3 class="mb-0"><i class="fas fa-reply me-2"></i>Doctor's Response</h3>
            </div>
            <div class="card-body">
                <div class="error-message">
                    <?php echo htmlspecialchars($decrypted_solution, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            </div>
        </div>
        <?php else: ?>
        <div class="card">
            <div class="card-header">
                <h3 class="mb-0"><i class="fas fa-hourglass-half me-2"></i>Awaiting Response</h3>
            </div>
            <div class="card-body">
                <div class="no-response">
                    <i class="fas fa-clock" style="font-size: 3rem; color: var(--warning-color); margin-bottom: 20px;"></i>
                    <h5>Doctor's Response Pending</h5>
                    <p class="text-muted">Your consultation has been submitted and is being reviewed by the doctor. You will be notified once a response is available.</p>
                </div>
            </div>
        </div>
        <?php endif; ?>

        <!-- Security Notice -->
        <div class="card">
            <div class="card-body">
                <div class="alert alert-danger">
                    <i class="fas fa-shield-alt me-2"></i>
                    <strong>Security Notice:</strong> 
                    This page contains sensitive medical information protected by encryption. 
                    Right-clicking, copying, downloading, and sharing are disabled for your privacy and security.
                    Any unauthorized attempts to access or copy this content will be logged and may result in account suspension.
                </div>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function () {
            // Session management variables
            let sessionTimeLeft = 300; // 5 minutes in seconds
            let warningShown = false;
            let sessionTimer;
            let warningTimer;
            
            // CSRF token for AJAX requests
            const csrfToken = '<?php echo $csrfToken; ?>';
            
            // Security warning function
            function showSecurityWarning(message) {
                $('#securityMessage').text(message);
                $('#securityOverlay').show();
                $('#securityWarning').show();
                
                // Log security violation
                logSecurityEvent('security_violation', message);
            }
            
            // Make showSecurityWarning globally available
            window.showSecurityWarning = showSecurityWarning;
            
            // Close security warning
            window.closeSecurityWarning = function() {
                $('#securityOverlay').hide();
                $('#securityWarning').hide();
            };
            
            // Log security events
            function logSecurityEvent(eventType, message) {
                $.ajax({
                    url: window.location.href,
                    type: 'POST',
                    data: { 
                        action: 'log_security_event',
                        csrf_token: csrfToken,
                        event_type: eventType,
                        message: message
                    }
                });
            }
            
            // Comprehensive security measures
            
            // 1. Disable right-click context menu (except for video controls)
            $(document).on('contextmenu', function(e) {
                // Allow right-click on video controls
                if ($(e.target).is('video') || $(e.target).closest('video').length > 0) {
                    showSecurityWarning('Video downloading and right-click are disabled to protect medical content.');
                    e.preventDefault();
                    return false;
                }
                
                // Block right-click on everything else
                if (!$(e.target).is('video')) {
                    e.preventDefault();
                    showSecurityWarning('Right-click is disabled to protect sensitive medical content.');
                    return false;
                }
            });
            
            // 2. Disable text selection (except video controls)
            $(document).on('selectstart', function(e) {
                if (!$(e.target).is('video') && !$(e.target).closest('video').length) {
                    e.preventDefault();
                    showSecurityWarning('Text selection is disabled to protect patient privacy.');
                    return false;
                }
            });
            
            // 3. Disable drag and drop (except video controls)
            $(document).on('dragstart', function(e) {
                if (!$(e.target).is('video') && !$(e.target).closest('video').length) {
                    e.preventDefault();
                    showSecurityWarning('Dragging content is not allowed for security reasons.');
                    return false;
                }
            });
            
            // 4. Disable keyboard shortcuts
            $(document).keydown(function(e) {
                // Disable F12 (Developer Tools)
                if (e.keyCode == 123) {
                    e.preventDefault();
                    showSecurityWarning('Developer tools are disabled to protect sensitive medical information.');
                    return false;
                }
                
                // Disable Ctrl+Shift+I (Developer Tools)
                if (e.ctrlKey && e.shiftKey && e.keyCode == 73) {
                    e.preventDefault();
                    showSecurityWarning('Developer tools are disabled to protect sensitive medical information.');
                    return false;
                }
                
                // Disable Ctrl+Shift+J (Console)
                if (e.ctrlKey && e.shiftKey && e.keyCode == 74) {
                    e.preventDefault();
                    showSecurityWarning('Console access is disabled to protect sensitive medical information.');
                    return false;
                }
                
                // Disable Ctrl+U (View Source)
                if (e.ctrlKey && e.keyCode == 85) {
                    e.preventDefault();
                    showSecurityWarning('Viewing page source is disabled to protect sensitive medical information.');
                    return false;
                }
                
                // Disable Ctrl+S (Save Page)
                if (e.ctrlKey && e.keyCode == 83) {
                    e.preventDefault();
                    showSecurityWarning('Saving this page is not allowed to protect patient privacy.');
                    return false;
                }
                
                // Disable Ctrl+A (Select All)
                if (e.ctrlKey && e.keyCode == 65) {
                    e.preventDefault();
                    showSecurityWarning('Selecting all content is disabled to protect patient privacy.');
                    return false;
                }
                
                // Disable Ctrl+C (Copy)
                if (e.ctrlKey && e.keyCode == 67) {
                    e.preventDefault();
                    showSecurityWarning('Copying content is disabled to protect patient privacy.');
                    return false;
                }
                
                // Disable Ctrl+V (Paste)
                if (e.ctrlKey && e.keyCode == 86) {
                    e.preventDefault();
                    showSecurityWarning('Pasting is disabled in this secure medical portal.');
                    return false;
                }
                
                // Disable Ctrl+X (Cut)
                if (e.ctrlKey && e.keyCode == 88) {
                    e.preventDefault();
                    showSecurityWarning('Cutting content is disabled to protect patient privacy.');
                    return false;
                }
                
                // Disable Ctrl+P (Print)
                if (e.ctrlKey && e.keyCode == 80) {
                    e.preventDefault();
                    showSecurityWarning('Printing is disabled to protect sensitive medical information.');
                    return false;
                }
                
                // Disable Print Screen
                if (e.keyCode == 44) {
                    e.preventDefault();
                    showSecurityWarning('Screenshots are disabled to protect patient privacy.');
                    return false;
                }
            });
            
            // 5. Monitor for developer tools
            let devtools = {
                open: false,
                orientation: null
            };
            
            const threshold = 160;
            
            setInterval(function() {
                if (window.outerHeight - window.innerHeight > threshold || 
                    window.outerWidth - window.innerWidth > threshold) {
                    if (!devtools.open) {
                        devtools.open = true;
                        showSecurityWarning('Developer tools detected. This action has been logged for security purposes.');
                    }
                } else {
                    devtools.open = false;
                }
            }, 500);
            
            // Session management
            function startSessionTimer() {
                sessionTimer = setInterval(function() {
                    sessionTimeLeft--;
                    updateTimerDisplay();
                    
                    // Show warning at 60 seconds
                    if (sessionTimeLeft <= 60 && !warningShown) {
                        showSessionWarning();
                    }
                    
                    // Auto logout at 0
                    if (sessionTimeLeft <= 0) {
                        clearInterval(sessionTimer);
                        window.location.href = '../../logout.php?reason=timeout';
                    }
                }, 1000);
            }
            
            function updateTimerDisplay() {
                const minutes = Math.floor(sessionTimeLeft / 60);
                const seconds = sessionTimeLeft % 60;
                const display = minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
                $('#countdown').text(display);
                
                // Change color when time is running low
                if (sessionTimeLeft <= 60) {
                    $('#sessionTimer').css('background', 'rgba(231, 76, 60, 0.9)');
                } else if (sessionTimeLeft <= 120) {
                    $('#sessionTimer').css('background', 'rgba(243, 156, 18, 0.9)');
                }
            }
            
            function showSessionWarning() {
                warningShown = true;
                $('#sessionWarning').show();
                
                let warningTimeLeft = 60;
                warningTimer = setInterval(function() {
                    warningTimeLeft--;
                    $('#warningCountdown').text(warningTimeLeft);
                    
                    if (warningTimeLeft <= 0) {
                        clearInterval(warningTimer);
                        window.location.href = '../../logout.php?reason=timeout';
                    }
                }, 1000);
            }
            
            // Extend session function
            window.extendSession = function() {
                $.ajax({
                    url: window.location.href,
                    type: 'POST',
                    data: { 
                        action: 'extend_session',
                        csrf_token: csrfToken 
                    },
                    success: function(response) {
                        sessionTimeLeft = 300; // Reset to 5 minutes
                        warningShown = false;
                        $('#sessionWarning').hide();
                        clearInterval(warningTimer);
                        $('#sessionTimer').css('background', 'rgba(231, 76, 60, 0.9)');
                    },
                    error: function() {
                        window.location.href = '../../logout.php?reason=security';
                    }
                });
            };
            
            // Logout now function
            window.logoutNow = function() {
                window.location.href = '../../logout.php';
            };
            
            // Reset timer on user activity
            function resetSessionTimer() {
                if (!warningShown) {
                    sessionTimeLeft = 300;
                }
            }
            
            // Activity detection
            $(document).on('mousemove keypress click scroll', resetSessionTimer);
            
            // Start the timer
            startSessionTimer();
            
            // Disable zoom
            $(document).on('wheel', function(e) {
                if (e.ctrlKey) {
                    e.preventDefault();
                    showSecurityWarning('Zooming is disabled to maintain content security.');
                    return false;
                }
            });
            
            // Monitor for window blur (potential screenshot tools)
            $(window).on('blur', function() {
                logSecurityEvent('window_blur', 'Window lost focus - potential screenshot attempt');
            });
        });

        // Additional video protection
        document.addEventListener('DOMContentLoaded', function() {
            // Override video controls
            const videos = document.querySelectorAll('video');
            videos.forEach(function(video) {
                // Remove download button but keep play controls
                video.controlsList = 'nodownload nofullscreen noremoteplaybook';
                video.disablePictureInPicture = true;
                
                // Enable pointer events for video controls
                video.style.pointerEvents = 'auto';
                
                // Allow video interaction but prevent context menu
                video.addEventListener('contextmenu', function(e) {
                    e.preventDefault();
                    showSecurityWarning('Video downloading and right-click are disabled to protect medical content.');
                    return false;
                });
                
                // Prevent video dragging
                video.addEventListener('dragstart', function(e) {
                    e.preventDefault();
                    return false;
                });
            });
        });
    </script>
</body>
</html>
