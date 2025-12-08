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
                'default-src' => ["'self'"],
                'script-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://code.jquery.com', 'https://cdnjs.cloudflare.com'],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
                'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
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
            'default-src' => ["'self'"],
            'script-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://code.jquery.com', 'https://cdnjs.cloudflare.com'],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
            'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
            'img-src' => ["'self'", 'data:'],
            'connect-src' => ["'self'"],
            'form-action' => ["'self'"],
            'frame-ancestors' => ["'none'"],
            'object-src' => ["'none'"],
            'base-uri' => ["'self'"]
        ]
    ],
    'permissions_policy' => [
        'camera' => ["'self'"],
        'microphone' => [],
        'geolocation' => [],
        'payment' => []
    ]
]);
$securityHeaders->sendAllHeaders();

include '../connection.php';

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

// Optimized security logging function - Only log important events
function logSecurityEvent($conn, $email, $event_type, $ip_address, $user_agent, $additional_info = '') {
    // Only log critical security events to prevent database bloat
    $critical_events = [
        'UNAUTHORIZED_DASHBOARD_ACCESS',
        'SESSION_TIMEOUT',
        'SESSION_HIJACK_ATTEMPT',
        'CSRF_TOKEN_MISMATCH',
        'RATE_LIMIT_EXCEEDED',
        'MALICIOUS_CHATBOT_INPUT',
        'DEV_TOOLS_DETECTED',
        'LOGIN_SUCCESS',
        'LOGIN_FAILURE',
        'LOGOUT'
    ];
    
    if (in_array($event_type, $critical_events)) {
        $stmt = $conn->prepare("INSERT INTO security_logs (email, event_type, ip_address, user_agent, additional_info, timestamp) VALUES (?, ?, ?, ?, ?, NOW())");
        if ($stmt) {
            $stmt->bind_param("sssss", $email, $event_type, $ip_address, $user_agent, $additional_info);
            $stmt->execute();
            $stmt->close();
        }
    }
}

// Get client IP address
function getClientIP() {
    $ip_keys = ['HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

$ip_address = getClientIP();
$user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';

// Enhanced authentication check with security logging
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'patient') {
    // Log unauthorized access attempt
    logSecurityEvent($conn, 'Unauthorized user detected - your information will be noticed', 'UNAUTHORIZED_DASHBOARD_ACCESS', $ip_address, $user_agent, 'Attempted to access patient dashboard without proper authentication');
    
    // Clear any existing session data
    session_destroy();
    
    // Redirect with security message
    header("Location: ../logout.php?error=unauthorized");
    exit;
}

// Session timeout check (30 minutes)
$session_timeout = 1800;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $session_timeout) {
    $user_email = $_SESSION['user_email'] ?? 'Session timeout detected - your information will be noticed';
    logSecurityEvent($conn, $user_email, 'SESSION_TIMEOUT', $ip_address, $user_agent, 'Session expired after 30 minutes');
    session_destroy();
    header("Location: ../logout.php?timeout=1");
    exit;
}
$_SESSION['last_activity'] = time();

// Session hijacking protection
if (!isset($_SESSION['user_agent'])) {
    $_SESSION['user_agent'] = $user_agent;
} elseif ($_SESSION['user_agent'] !== $user_agent) {
    $user_email = $_SESSION['user_email'] ?? 'Session hijack attempt detected - your information will be noticed';
    logSecurityEvent($conn, $user_email, 'SESSION_HIJACK_ATTEMPT', $ip_address, $user_agent, 'User agent mismatch detected');
    session_destroy();
    header("Location: ../logout.php?error=session_invalid");
    exit;
}

// IP validation for suspicious activity
if (!isset($_SESSION['user_ip'])) {
    $_SESSION['user_ip'] = $ip_address;
} elseif ($_SESSION['user_ip'] !== $ip_address) {
    $user_email = $_SESSION['user_email'] ?? 'IP change detected - your information will be noticed';
    // Only log if IP change is significant (different subnet)
    $old_ip_parts = explode('.', $_SESSION['user_ip']);
    $new_ip_parts = explode('.', $ip_address);
    if (count($old_ip_parts) >= 3 && count($new_ip_parts) >= 3) {
        if ($old_ip_parts[0] !== $new_ip_parts[0] || $old_ip_parts[1] !== $new_ip_parts[1]) {
            logSecurityEvent($conn, $user_email, 'IP_CHANGE_DETECTED', $ip_address, $user_agent, 'Significant IP change from ' . $_SESSION['user_ip'] . ' to ' . $ip_address);
        }
    }
    $_SESSION['user_ip'] = $ip_address;
}

// Rate limiting for requests using security_logs table
$max_requests = 500;
$time_window = 3600; // 1 hour

function checkRateLimit($conn, $ip, $max_requests, $window) {
    $stmt = $conn->prepare("SELECT COUNT(*) as request_count FROM security_logs WHERE ip_address = ? AND timestamp > DATE_SUB(NOW(), INTERVAL ? SECOND)");
    if ($stmt) {
        $stmt->bind_param("si", $ip, $window);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc();
        $stmt->close();
        return $row['request_count'] < $max_requests;
    }
    return true;
}

// Check rate limit
if (!checkRateLimit($conn, $ip_address, $max_requests, $time_window)) {
    $user_email = $_SESSION['user_email'] ?? 'Rate limit exceeded - your information will be noticed';
    logSecurityEvent($conn, $user_email, 'RATE_LIMIT_EXCEEDED', $ip_address, $user_agent, 'Exceeded maximum requests per hour');
    http_response_code(429);
    die(json_encode(["success" => false, "message" => "Too many requests. Please try again later.", "type" => "error"]));
}

// Function to sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Function to validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

$patient_id = (int)$_SESSION['user_id'];
$first_name = "Unknown";
$last_name = "Patient";
$dob = "N/A";
$age = "N/A";

// Count doctors with prepared statement
$sql_doctors = "SELECT COUNT(id) as doctor_count FROM doctors WHERE registration_status = 'approved'";
$result_doctors = $conn->query($sql_doctors);
$doctor_count = ($result_doctors && $result_doctors->num_rows > 0) ? $result_doctors->fetch_assoc()['doctor_count'] : 0;

// Count all hospitals without filtering by status
$sql_hospitals = "SELECT COUNT(id) as hospital_count FROM hospitals";
$result_hospitals = $conn->query($sql_hospitals);
$hospital_count = ($result_hospitals && $result_hospitals->num_rows > 0) ? $result_hospitals->fetch_assoc()['hospital_count'] : 0;

// Count unique patients with completed history
$sql_patients = "SELECT COUNT(DISTINCT patient_id) as patient_count FROM patient_history WHERE status = 'completed'";
$result_patients = $conn->query($sql_patients);
$patient_count = ($result_patients && $result_patients->num_rows > 0) ? $result_patients->fetch_assoc()['patient_count'] : 0;

// Fetch patient information with prepared statement (including authorized column)
$sql_patient = "SELECT first_name, last_name, date_of_birth, profile_picture, email, authorized FROM patients WHERE id = ? LIMIT 1";
$stmt_patient = $conn->prepare($sql_patient);
if (!$stmt_patient) {
    logSecurityEvent($conn, 'Database error detected - your information will be noticed', 'DATABASE_ERROR', $ip_address, $user_agent, 'Failed to prepare patient query');
    die(json_encode(["success" => false, "message" => "System error. Please try again later.", "type" => "error"]));
}
$stmt_patient->bind_param("i", $patient_id);
$stmt_patient->execute();
$result_patient = $stmt_patient->get_result();

if ($result_patient->num_rows > 0) {
    $row = $result_patient->fetch_assoc();
    
    // **AUTHORIZATION CHECK - NEW LOGIC ADDED HERE**
    $authorized = (int)($row['authorized'] ?? 1); // Default to 1 if column doesn't exist
    
    if ($authorized === 0) {
        // User is not authorized - display blocking message
        $stmt_patient->close();
        $conn->close();
        ?>
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Access Blocked - Healthcare Portal</title>
            <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
            <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
            <style>
                * {
                    margin: 0;
                    padding: 0;
                    box-sizing: border-box;
                    font-family: 'Plus Jakarta Sans', sans-serif;
                }
                
                body {
                    background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    padding: 2rem;
                }
                
                .blocked-container {
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(12px);
                    border-radius: 1.5rem;
                    padding: 3rem;
                    max-width: 600px;
                    width: 100%;
                    text-align: center;
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
                }
                
                .blocked-icon {
                    font-size: 4rem;
                    color: #fca5a5;
                    margin-bottom: 2rem;
                    animation: pulse 2s infinite;
                }
                
                @keyframes pulse {
                    0%, 100% { opacity: 1; }
                    50% { opacity: 0.7; }
                }
                
                .blocked-title {
                    font-size: 2rem;
                    font-weight: 700;
                    margin-bottom: 1.5rem;
                    color: #fef2f2;
                }
                
                .blocked-message {
                    font-size: 1.1rem;
                    line-height: 1.6;
                    margin-bottom: 2.5rem;
                    color: rgba(255, 255, 255, 0.9);
                }
                
                .blocked-actions {
                    display: flex;
                    gap: 1rem;
                    justify-content: center;
                    flex-wrap: wrap;
                }
                
                .blocked-btn {
                    display: inline-flex;
                    align-items: center;
                    gap: 0.5rem;
                    padding: 0.875rem 1.5rem;
                    background: rgba(255, 255, 255, 0.2);
                    color: white;
                    text-decoration: none;
                    border-radius: 0.75rem;
                    font-weight: 600;
                    transition: all 0.3s ease;
                    border: 1px solid rgba(255, 255, 255, 0.3);
                }
                
                .blocked-btn:hover {
                    background: rgba(255, 255, 255, 0.3);
                    transform: translateY(-2px);
                    box-shadow: 0 8px 20px rgba(0, 0, 0, 0.2);
                }
                
                .blocked-btn.primary {
                    background: rgba(59, 130, 246, 0.8);
                    border-color: rgba(59, 130, 246, 0.9);
                }
                
                .blocked-btn.primary:hover {
                    background: rgba(59, 130, 246, 0.9);
                }
                
                @media (max-width: 768px) {
                    .blocked-container {
                        padding: 2rem;
                        margin: 1rem;
                    }
                    
                    .blocked-title {
                        font-size: 1.5rem;
                    }
                    
                    .blocked-message {
                        font-size: 1rem;
                    }
                    
                    .blocked-actions {
                        flex-direction: column;
                    }
                }
            </style>
        </head>
        <body>
            <div class="blocked-container">
                <div class="blocked-icon">
                    <i class="fas fa-ban"></i>
                </div>
                <h1 class="blocked-title">Access Blocked</h1>
                <p class="blocked-message">
                    You have been blocked by the admin for some reason. If you want to access your dashboard, please request access from the admin, or try to log in with a different email. If you're unable to log in with a different email, your device may also be blocked — in that case, please submit a valid reason using the same request form.
                </p>
                <div class="blocked-actions">
                    <a href="../send_report" class="blocked-btn primary">
                        <i class="fas fa-paper-plane"></i>
                        Request Access from Admin
                    </a>
                    <a href="../logout.php" class="blocked-btn">
                        <i class="fas fa-sign-out-alt"></i>
                        Try Different Email
                    </a>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
    // **END OF AUTHORIZATION CHECK**
    
    $first_name = sanitizeInput($row['first_name'] ?? "Unknown");
    $last_name = sanitizeInput($row['last_name'] ?? "Patient");
    $dob = $row['date_of_birth'] ?? "N/A";
    $age = ($dob !== "N/A") ? (new DateTime())->diff(new DateTime($dob))->y : "N/A";
    
    // Create a default SVG avatar as base64
    $default_avatar = 'data:image/svg+xml;base64,' . base64_encode('
    <svg width="52" height="52" viewBox="0 0 52 52" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="26" cy="26" r="26" fill="#6366F1"/>
        <path d="M26 26c3.314 0 6-2.686 6-6s-2.686-6-6-6-6 2.686-6 6 2.686 6 6 6zm0 3c-4.008 0-12 2.016-12 6v3h24v-3c0-3.984-7.992-6-12-6z" fill="white"/>
    </svg>');

    // Handle profile picture with proper path checking
    $profile_picture_db = $row['profile_picture'] ?? '';
    if (!empty($profile_picture_db)) {
        // Check if file actually exists on server
        if (file_exists($profile_picture_db) && is_file($profile_picture_db)) {
            $profile_picture = $profile_picture_db;
        } else {
            $profile_picture = $default_avatar;
        }
    } else {
        $profile_picture = $default_avatar;
    }

    $user_email = $row['email'] ?? 'unknown';
    $_SESSION['user_email'] = $user_email;
    
} else {
    logSecurityEvent($conn, 'User not found - your information will be noticed', 'USER_NOT_FOUND', $ip_address, $user_agent, 'User ID not found: ' . $patient_id);
    session_destroy();
    header("Location: ../logout.php");
    exit;
}
$stmt_patient->close();

// Check if this is the first visit to dashboard (for welcome message)
$show_welcome = false;
if (!isset($_SESSION['dashboard_visited'])) {
    $_SESSION['dashboard_visited'] = true;
    $show_welcome = true;
}

// Handle POST request for enhanced security
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle session refresh
    if (isset($_POST['action']) && $_POST['action'] === 'heartbeat') {
        // CSRF token validation
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in heartbeat request');
            http_response_code(403);
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Security token mismatch", "type" => "error"]);
            exit;
        }
        
        $_SESSION['last_activity'] = time();
        header("Content-Type: application/json");
        echo json_encode(["success" => true, "message" => "Session refreshed", "type" => "success"]);
        exit;
    }

    // Handle security event logging from JavaScript (only for critical events)
    if (isset($_POST['action']) && $_POST['action'] === 'log_security_event') {
        // CSRF token validation
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in security logging request');
            http_response_code(403);
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Security token mismatch", "type" => "error"]);
            exit;
        }

        $event_type = sanitizeInput($_POST['event_type'] ?? '');
        $details = sanitizeInput($_POST['details'] ?? '');
        
        if (!empty($event_type)) {
            logSecurityEvent($conn, $user_email, $event_type, $ip_address, $user_agent, $details);
            header("Content-Type: application/json");
            echo json_encode(["success" => true, "message" => "Event logged", "type" => "success"]);
        } else {
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Invalid event type", "type" => "error"]);
        }
        exit;
    }

    // Handle events/news data fetching
    if (isset($_POST['action']) && $_POST['action'] === 'fetch_events') {
        // CSRF token validation
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in events fetch request');
            http_response_code(403);
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Security token mismatch", "type" => "error"]);
            exit;
        }

        $filter = sanitizeInput($_POST['filter'] ?? 'all');
        $custom_date = sanitizeInput($_POST['custom_date'] ?? '');

        $sql = "SELECT * FROM events_news WHERE 1=1";
        $params = [];
        $types = "";

        if ($filter === 'today') {
            $sql .= " AND DATE(created_at) = CURDATE()";
        } elseif ($filter === 'custom' && !empty($custom_date)) {
            $sql .= " AND DATE(created_at) = ?";
            $params[] = $custom_date;
            $types .= "s";
        }

        $sql .= " ORDER BY created_at DESC LIMIT 20";

        $stmt = $conn->prepare($sql);
        if ($stmt) {
            if (!empty($params)) {
                $stmt->bind_param($types, ...$params);
            }
            $stmt->execute();
            $result = $stmt->get_result();
            
            $events = [];
            while ($row = $result->fetch_assoc()) {
                $events[] = [
                    'id' => $row['id'],
                    'title' => $row['title'],
                    'description' => $row['description'],
                    'image_path' => $row['image_path'],
                    'video_path' => $row['video_path'],
                    'posted_by' => $row['posted_by'],
                    'hospital_name' => $row['hospital_name'],
                    'created_at' => $row['created_at']
                ];
            }
            $stmt->close();
            
            header("Content-Type: application/json");
            echo json_encode(["success" => true, "events" => $events]);
        } else {
            header("Content-Type: application/json");
            echo json_encode(["success" => false, "message" => "Database error", "type" => "error"]);
        }
        exit;
    }

// Handle chatbot interaction with enhanced reliability
if (!isset($_POST['action'])) {
    // CSRF token validation for chatbot
    $input = json_decode(file_get_contents('php://input'), true);
    if (!isset($input['csrf_token']) || !validateCSRFToken($input['csrf_token'])) {
        logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in chatbot request');
        http_response_code(403);
        header("Content-Type: application/json");
        echo json_encode(["status" => "error", "message" => "Security token mismatch", "type" => "error"]);
        exit;
    }

    header("Content-Type: application/json");

    if (!isset($input['message']) || trim($input['message']) === "") {
        echo json_encode(["status" => "error", "message" => "Invalid input", "type" => "error"]);
        exit;
    }

    $userMessage = sanitizeInput(trim($input['message']));
    $user_id = $_SESSION['user_id'];

    // Input validation
    if (strlen($userMessage) > 500) {
        echo json_encode(["status" => "error", "message" => "Message too long", "type" => "error"]);
        exit;
    }

    // Security check for malicious content
    $dangerous_patterns = [
        '/<script/i',
        '/javascript:/i',
        '/on\w+\s*=/i',
        '/<iframe/i',
        '/<object/i',
        '/<embed/i',
        '/eval\s*\(/i',
        '/document\./i'
    ];

    foreach ($dangerous_patterns as $pattern) {
        if (preg_match($pattern, $userMessage)) {
            logSecurityEvent($conn, $user_email, 'MALICIOUS_CHATBOT_INPUT', $ip_address, $user_agent, 'Dangerous pattern detected: ' . $userMessage);
            echo json_encode(["status" => "error", "message" => "Invalid message content", "type" => "error"]);
            exit;
        }
    }

    // Enhanced API call with retry mechanism
    function callChatbotAPI($userMessage, $maxRetries = 3) {
        $api_url = "https://username-spacename.hf.space/space";
        $user_id = $_SESSION['user_id'];
        $payload = json_encode(["question" => $userMessage]);
        
        for ($attempt = 1; $attempt <= $maxRetries; $attempt++) {
            $ch = curl_init($api_url);
            
            // Enhanced cURL options for better reliability
            curl_setopt_array($ch, [
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_POST => true,
                CURLOPT_HTTPHEADER => [
                    "Content-Type: application/json",
                    "User-Agent: HealthcarePortal/1.0",
                    "Accept: application/json",
                    "Connection: keep-alive"
                ],
                CURLOPT_POSTFIELDS => $payload,
                CURLOPT_CONNECTTIMEOUT => 15,
                CURLOPT_TIMEOUT => 90,
                CURLOPT_FOLLOWLOCATION => true,
                CURLOPT_MAXREDIRS => 3,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_ENCODING => 'gzip, deflate',
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_TCP_KEEPALIVE => 1,
                CURLOPT_TCP_KEEPIDLE => 120,
                CURLOPT_TCP_KEEPINTVL => 60,
                CURLOPT_FRESH_CONNECT => false,
                CURLOPT_FORBID_REUSE => false
            ]);

            $response = curl_exec($ch);
            $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $curl_error = curl_error($ch);
            $curl_errno = curl_errno($ch);
            
            curl_close($ch);

            // Check for successful response
            if ($curl_errno === 0 && $http_status === 200 && $response !== false) {
                $api_result = json_decode($response, true);
                
                // Validate JSON response
                if (json_last_error() === JSON_ERROR_NONE && isset($api_result)) {
                    return [
                        'success' => true,
                        'data' => $api_result,
                        'attempt' => $attempt
                    ];
                }
            }

            // Log the error for debugging
            error_log("Chatbot API Attempt $attempt failed - HTTP: $http_status, cURL Error: $curl_error (Code: $curl_errno)");
            
            // If not the last attempt, wait before retrying
            if ($attempt < $maxRetries) {
                // Exponential backoff: 1s, 2s, 4s
                sleep(pow(2, $attempt - 1));
            }
        }

        // All attempts failed
        return [
            'success' => false,
            'error' => $curl_error ?: "API request failed after $maxRetries attempts",
            'http_status' => $http_status ?? 0
        ];
    }

    // Call the API with retry mechanism
    $apiResponse = callChatbotAPI($userMessage);

    if ($apiResponse['success']) {
        $api_result = $apiResponse['data'];
        
        if (isset($api_result['status']) && $api_result['status'] === 'success') {
            echo json_encode([
                "status" => "success",
                "message" => $api_result['answer'],
                "type" => "success",
                "attempt" => $apiResponse['attempt'] // For debugging
            ]);
        } else {
            echo json_encode([
                "status" => "error",
                "message" => $api_result['answer'] ?? "Sorry, I couldn't process your request.",
                "type" => "error"
            ]);
        }
    } else {
        // Enhanced error handling
        $errorMessage = "I'm temporarily unable to connect to the AI service. ";
        
        if (strpos($apiResponse['error'], 'timeout') !== false) {
            $errorMessage .= "The service is taking longer than usual to respond. Please try again.";
        } elseif (strpos($apiResponse['error'], 'Connection refused') !== false) {
            $errorMessage .= "The AI service is currently unavailable. Please try again in a few moments.";
        } elseif ($apiResponse['http_status'] >= 500) {
            $errorMessage .= "The AI service is experiencing technical difficulties. Please try again later.";
        } else {
            $errorMessage .= "Please check your connection and try again.";
        }

        echo json_encode([
            "status" => "error",
            "message" => $errorMessage,
            "type" => "error",
            "retry_suggested" => true
        ]);
    }
    exit;
}


}

// Ensure DB connection closes properly
$conn->close();
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="robots" content="noindex, nofollow">
    <meta name="referrer" content="strict-origin-when-cross-origin">
    <title>Healthcare Portal - Patient Dashboard</title>
    
    <!-- Preload critical resources -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="preload" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" as="style">
    
    <!-- Google Fonts -->
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    
    <!-- FontAwesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous">
    
    <!-- Custom CSS -->
    <style>
        :root {
            /* 2025 Modern Healthcare Color Palette */
            --primary: #2563eb;
            --primary-light: #60a5fa;
            --primary-dark: #1e40af;
            --secondary: #10b981;
            --secondary-light: #34d399;
            --secondary-dark: #059669;
            --accent: #8b5cf6;
            --accent-light: #a78bfa;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #3b82f6;
            
            /* UI Colors */
            --dark: #0f172a;
            --dark-light: #1e293b;
            --light: #f8fafc;
            --gray: #94a3b8;
            --gray-light: #e2e8f0;
            --gray-dark: #475569;
            
            /* Shadows & Effects */
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.05), 0 2px 4px rgba(0,0,0,0.05);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.05), 0 4px 6px rgba(0,0,0,0.05);
            --shadow-xl: 0 20px 25px rgba(0,0,0,0.05), 0 10px 10px rgba(0,0,0,0.05);
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            
            /* Radius */
            --radius-sm: 0.375rem;
            --radius-md: 0.75rem;
            --radius-lg: 1.5rem;
            --radius-full: 9999px;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }

        body {
            color: var(--dark);
            min-height: 100vh;
            display: flex;
            overflow-x: hidden;
            position: relative;
            background: #1e3a8a;
        }

        /* Enhanced security - disable text selection on sensitive areas */
        .no-select {
            -webkit-user-select: none;
            -moz-user-select: none;
            -ms-user-select: none;
            user-select: none;
        }


        /* Custom Scrollbar */
        ::-webkit-scrollbar {
            width: 6px;
            height: 6px;
        }

        ::-webkit-scrollbar-track {
            background: var(--gray-light);
            border-radius: var(--radius-full);
        }

        ::-webkit-scrollbar-thumb {
            background: var(--primary);
            border-radius: var(--radius-full);
        }

        ::-webkit-scrollbar-thumb:hover {
            background: var(--primary-dark);
        }

        /* Layout */
        .app-container {
            display: flex;
            width: 100%;
            min-height: 100vh;
            position: relative;
            z-index: 2;
        }

        /* Sidebar Styles - Enhanced Security */
        .sidebar {
            width: 280px;
            background: rgba(15, 23, 42, 0.92);
            backdrop-filter: blur(12px);
            color: var(--light);
            height: 100vh;
            position: fixed;
            left: 0;
            top: 0;
            z-index: 100;
            transition: var(--transition);
            display: flex;
            flex-direction: column;
            border-right: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 5px 0 30px rgba(0, 0, 0, 0.2);
        }

        .sidebar-collapsed {
            width: 80px;
        }

        .sidebar-header {
            padding: 1.75rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 0.75rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }

        .sidebar-logo {
            font-size: 1.5rem;
            font-weight: 800;
            color: var(--light);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .sidebar-logo i {
            font-size: 1.75rem;
            color: var(--primary-light);
            filter: drop-shadow(0 0 8px rgba(96, 165, 250, 0.5));
        }

        .sidebar-toggle {
            margin-left: auto;
            background: rgba(255, 255, 255, 0.05);
            border: none;
            color: var(--gray);
            cursor: pointer;
            width: 32px;
            height: 32px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: var(--transition);
        }

        .sidebar-toggle:hover {
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
        }

        .sidebar-user {
            padding: 1.75rem 1.5rem;
            display: flex;
            align-items: center;
            gap: 1rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            background: linear-gradient(to right, rgba(37, 99, 235, 0.1), transparent);
        }

        .sidebar-user-avatar {
            width: 52px;
            height: 52px;
            border-radius: var(--radius-full);
            object-fit: cover;
            border: 2px solid var(--primary-light);
            box-shadow: 0 0 15px rgba(96, 165, 250, 0.5);
            background: var(--primary-light);
            flex-shrink: 0;
        }

        .sidebar-user-info {
            display: flex;
            flex-direction: column;
        }

        .sidebar-user-name {
            font-weight: 600;
            font-size: 1.05rem;
            color: var(--light);
        }

        .sidebar-user-role {
            font-size: 0.875rem;
            color: var(--primary-light);
            font-weight: 500;
        }

        .sidebar-menu {
            padding: 1.5rem 0;
            flex: 1;
            overflow-y: auto;
        }

        .sidebar-menu-title {
            padding: 0 1.5rem;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.05em;
            color: var(--gray);
            margin-bottom: 0.75rem;
            margin-top: 1.25rem;
        }

        .sidebar-menu-items {
            list-style: none;
        }

        .sidebar-menu-item {
            margin-bottom: 0.25rem;
        }

        .sidebar-menu-link {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            padding: 0.875rem 1.5rem;
            color: var(--gray);
            text-decoration: none;
            transition: var(--transition);
            border-left: 3px solid transparent;
            position: relative;
            cursor: pointer;
        }

        .sidebar-menu-link:hover {
            background: rgba(255, 255, 255, 0.05);
            color: var(--light);
        }

        .sidebar-menu-link.active {
            background: linear-gradient(to right, rgba(37, 99, 235, 0.2), transparent);
            color: var(--primary-light);
            border-left-color: var(--primary-light);
        }

        .sidebar-menu-link.active::before {
            content: '';
            position: absolute;
            right: 0;
            top: 0;
            height: 100%;
            width: 4px;
            background: var(--primary-light);
            border-radius: 4px 0 0 4px;
        }

        .sidebar-menu-icon {
            width: 20px;
            text-align: center;
            font-size: 1.25rem;
        }

        .sidebar-menu-text {
            transition: var(--transition);
        }

        .sidebar-collapsed .sidebar-menu-text,
        .sidebar-collapsed .sidebar-user-info,
        .sidebar-collapsed .sidebar-logo span,
        .sidebar-collapsed .sidebar-menu-title {
            display: none;
        }

        .sidebar-footer {
            padding: 1.25rem 1.5rem;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .logout-button {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border: none;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-weight: 600;
            transition: var(--transition);
        }

        .logout-button:hover {
            background: rgba(239, 68, 68, 0.25);
            transform: translateY(-2px);
        }

        .sidebar-collapsed .logout-button span {
            display: none;
        }

        /* Main Content Styles */
        .main-content {
            flex: 1;
            margin-left: 280px;
            transition: var(--transition);
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .sidebar-collapsed + .main-content {
            margin-left: 80px;
        }

        /* Header Styles */
        .header {
            background: rgba(15, 23, 42, 0.75);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 1.5rem 2rem;
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-content {
            display: flex;
            align-items: center;
            gap: 1rem;
            flex-wrap: wrap;
        }

        .header-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--light);
            background: linear-gradient(to right, #fff, #60a5fa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .header-subtitle {
            font-size: 1rem;
            color: rgba(255, 255, 255, 0.8);
            font-weight: 500;
        }

        /* Session Timer Styles */
        .session-timer {
            display: none;
            background: rgba(239, 68, 68, 0.9);
            color: white;
            padding: 0.75rem 1.5rem;
            border-radius: var(--radius-md);
            font-weight: 600;
            font-size: 0.9rem;
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            animation: pulse 2s infinite;
        }

        .session-timer.show {
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.8; }
        }

        /* Dashboard Content */
        .dashboard {
            padding: 1.5rem;
            flex: 1;
            background: transparent;
            height: calc(100vh - 80px);
            overflow: hidden;
        }

        /* New Dashboard Layout - 50/50 Split */
        .dashboard-layout {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            height: 100%;
        }

        .dashboard-left {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
        }

        .dashboard-right {
            display: flex;
            flex-direction: column;
        }

        /* Combined Metrics Card */
        .combined-metrics-card {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
            color: var(--light);
            position: relative;
            overflow: hidden;
        }

        .combined-metrics-card::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), transparent);
            opacity: 0;
            transition: var(--transition);
        }

        .combined-metrics-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }

        .combined-metrics-card:hover::after {
            opacity: 1;
        }

        .combined-metrics-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(to right, var(--primary), var(--secondary), var(--accent));
        }

        .metrics-header {
            margin-bottom: 1rem;
        }

        .metrics-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.25rem;
            background: linear-gradient(to right, #fff, #60a5fa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .metrics-subtitle {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.7);
        }

        .metrics-grid {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 1rem;
        }

        .metric-item {
            text-align: center;
            padding: 0.75rem;
            border-radius: var(--radius-md);
            background: rgba(255, 255, 255, 0.05);
            transition: var(--transition);
        }

        .metric-item:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-2px);
        }

        .metric-icon {
            width: 40px;
            height: 40px;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.25rem;
            margin: 0 auto 0.75rem;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
        }

        .metric-icon.doctors {
            background: rgba(37, 99, 235, 0.25);
            color: var(--primary-light);
        }

        .metric-icon.hospitals {
            background: rgba(16, 185, 129, 0.25);
            color: var(--secondary-light);
        }

        .metric-icon.patients {
            background: rgba(139, 92, 246, 0.25);
            color: var(--accent-light);
        }

        .metric-value {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
            background: linear-gradient(to right, #fff, rgba(255, 255, 255, 0.7));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .metric-label {
            font-size: 0.75rem;
            color: rgba(255, 255, 255, 0.8);
            font-weight: 500;
        }

        /* Action Cards */
        .action-cards {
            display: flex;
            flex-direction: column;
            gap: 1.25rem;
            flex: 1;
        }

        .action-card {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
            display: flex;
            flex-direction: column;
            position: relative;
            overflow: hidden;
            color: var(--light);
            flex: 1;
        }

        .action-card::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), transparent);
            opacity: 0;
            transition: var(--transition);
        }

        .action-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }

        .action-card:hover::after {
            opacity: 1;
        }

        .action-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
        }

        .action-card.public::before {
            background: linear-gradient(to right, var(--primary), var(--primary-light));
        }

        .action-card.private::before {
            background: linear-gradient(to right, var(--secondary), var(--secondary-light));
        }

        .action-card-header {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            margin-bottom: 1rem;
        }

        .action-card-icon {
            width: 48px;
            height: 48px;
            border-radius: var(--radius-md);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
        }

        .action-card-icon.public {
            background: rgba(37, 99, 235, 0.25);
            color: var(--primary-light);
        }

        .action-card-icon.private {
            background: rgba(16, 185, 129, 0.25);
            color: var(--secondary-light);
        }

        .action-card-title {
            font-size: 1.1rem;
            font-weight: 600;
        }

        .action-card-description {
            font-size: 0.85rem;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 1rem;
            flex: 1;
            line-height: 1.5;
        }

        .action-card-button {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.75rem 1rem;
            border-radius: var(--radius-md);
            font-weight: 600;
            text-decoration: none;
            transition: var(--transition);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.15);
            font-size: 0.9rem;
            cursor: pointer;
            position: relative;
            z-index: 10;
            pointer-events: auto;
        }

        .action-card-button.public {
            background: linear-gradient(to right, var(--primary), var(--primary-dark));
            color: var(--light);
        }

        .action-card-button.public:hover {
            background: linear-gradient(to right, var(--primary-dark), var(--primary));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.3);
        }

        .action-card-button.private {
            background: linear-gradient(to right, var(--secondary), var(--secondary-dark));
            color: var(--light);
        }

        .action-card-button.private:hover {
            background: linear-gradient(to right, var(--secondary-dark), var(--secondary));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.3);
        }

        /* Events/News Card - Fixed Height */
        .events-news-card {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
            color: var(--light);
            position: relative;
            overflow: hidden;
            height: 100%;
            display: flex;
            flex-direction: column;
            max-height: calc(100vh - 135px);
        }

        .events-news-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(to right, var(--info), var(--accent));
        }

        .events-header {
            padding: 1.25rem 1.5rem;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 1rem;
            flex-shrink: 0;
        }

        .events-title {
            font-size: 1.25rem;
            font-weight: 600;
            background: linear-gradient(to right, #fff, #60a5fa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .events-controls {
            display: flex;
            gap: 0.75rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .events-filter {
            display: flex;
            gap: 0.5rem;
            align-items: center;
        }

        .filter-select {
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: var(--radius-sm);
            color: var(--light);
            padding: 0.5rem 0.75rem;
            font-size: 0.8rem;
            outline: none;
            transition: var(--transition);
            min-width: 80px;
        }

        .filter-select option {
            background: var(--dark);
            color: var(--light);
        }

        .filter-select:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .filter-date {
            background: rgba(255, 255, 255, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: var(--radius-sm);
            color: var(--light);
            padding: 0.5rem 0.75rem;
            font-size: 0.8rem;
            outline: none;
            transition: var(--transition);
            display: none;
        }

        .filter-date.show {
            display: block;
        }

        .filter-date:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .scroll-control-btn {
            background: linear-gradient(135deg, var(--accent), var(--accent-light));
            color: var(--light);
            border: none;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-sm);
            font-size: 0.8rem;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            box-shadow: 0 2px 8px rgba(139, 92, 246, 0.3);
        }

        .scroll-control-btn:hover {
            background: linear-gradient(135deg, var(--accent-light), var(--accent));
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(139, 92, 246, 0.4);
        }

        .events-content {
            flex: 1;
            padding: 1rem;
            overflow: hidden;
            position: relative;
            min-height: 0;
        }

        .events-scroll-container {
            height: 100%;
            overflow: hidden;
            position: relative;
        }

        .events-scroll-container.manual-scroll {
            overflow-y: auto;
        }

        .events-list {
            display: flex;
            flex-direction: column;
            gap: 0.75rem;
            animation: scrollUp 25s linear infinite;
            animation-play-state: running;
        }

        .events-list.paused {
            animation-play-state: paused;
        }

        .events-list.manual {
            animation: none;
        }

        .events-list:hover {
            animation-play-state: paused;
        }

        @keyframes scrollUp {
            0% {
                transform: translateY(100%);
            }
            100% {
                transform: translateY(-100%);
            }
        }

        .event-item {
            background: rgba(255, 255, 255, 0.05);
            border-radius: var(--radius-md);
            padding: 1rem;
            border: 1px solid rgba(255, 255, 255, 0.1);
            transition: var(--transition);
            flex-shrink: 0;
        }

        .event-item:hover {
            background: rgba(255, 255, 255, 0.1);
            transform: translateY(-1px);
        }

        /* Dynamic Media Sizing */
        .event-media {
            width: 100%;
            border-radius: var(--radius-sm);
            margin-bottom: 0.75rem;
            object-fit: cover;
            display: block;
        }

        .event-media.has-media {
            aspect-ratio: 16/9;
            height: auto;
        }

        .event-media.no-media {
            display: none;
        }

        .event-title {
            font-size: 1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--light);
        }

        .event-description {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.8);
            margin-bottom: 0.75rem;
            line-height: 1.4;
        }

        .event-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.7rem;
            color: rgba(255, 255, 255, 0.6);
        }

        .event-author {
            display: flex;
            align-items: center;
            gap: 0.25rem;
            background: rgba(37, 99, 235, 0.2);
            padding: 0.2rem 0.5rem;
            border-radius: var(--radius-full);
            color: var(--primary-light);
            font-weight: 500;
        }

        .event-date {
            font-style: italic;
        }

        /* Enhanced Chatbot Styles */
        .chat-bot-container {
            position: fixed;
            bottom: 2rem;
            right: 2rem;
            z-index: 1000;
            transition: var(--transition);
        }

        .chat-bot-toggle {
            width: 60px;
            height: 60px;
            border-radius: var(--radius-full);
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: var(--light);
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 5px 20px rgba(37, 99, 235, 0.4);
            transition: var(--transition);
            position: relative;
            z-index: 1001;
        }

        .chat-bot-toggle i {
            font-size: 1.5rem;
            transition: var(--transition);
        }

        .chat-bot-toggle:hover {
            transform: scale(1.05) translateY(-3px);
            box-shadow: 0 8px 25px rgba(37, 99, 235, 0.5);
        }

        .chat-bot-box {
            position: absolute;
            bottom: 80px;
            right: 0;
            width: 380px;
            height: 520px;
            background: rgba(15, 23, 42, 0.9);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            box-shadow: 0 10px 40px rgba(0, 0, 0, 0.3);
            display: flex;
            flex-direction: column;
            overflow: hidden;
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
            opacity: 0;
            transform: translateY(20px) scale(0.95);
            pointer-events: none;
            visibility: hidden;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .chat-bot-container.open .chat-bot-box {
            opacity: 1;
            transform: translateY(0) scale(1);
            pointer-events: all;
            visibility: visible;
        }

        .chat-bot-container.maximized .chat-bot-box {
            width: 420px;
            height: 600px;
        }

        .chat-bot-container.open .chat-bot-toggle i {
            transform: rotate(180deg);
        }

        .chat-bot-header {
            background: linear-gradient(to right, var(--primary), var(--primary-dark));
            color: var(--light);
            padding: 1.25rem 1.5rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .chat-bot-title {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 1.1rem;
            font-weight: 600;
        }

        .chat-bot-title i {
            font-size: 1.35rem;
        }

        .chat-controls {
            display: flex;
            gap: 0.75rem;
        }

        .chat-control-btn {
            background: rgba(255, 255, 255, 0.1);
            border: none;
            color: var(--light);
            font-size: 1rem;
            cursor: pointer;
            width: 28px;
            height: 28px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
            transition: var(--transition);
        }

        .chat-control-btn:hover {
            background: rgba(255, 255, 255, 0.2);
        }

        .chat-bot-content {
            flex: 1;
            padding: 1.5rem;
            overflow-y: auto;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            background: rgba(15, 23, 42, 0.8);
            color: var(--light);
        }

        .chat-message {
            display: flex;
            flex-direction: column;
            gap: 0.25rem;
            max-width: 85%;
            animation: messageAppear 0.3s ease-out;
        }

        @keyframes messageAppear {
            from { opacity: 0; transform: translateY(10px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .user-message {
            align-self: flex-end;
        }

        .bot-message {
            align-self: flex-start;
        }

        .message-bubble {
            padding: 0.875rem 1.125rem;
            border-radius: 1.25rem;
            font-size: 0.9375rem;
            line-height: 1.5;
            word-wrap: break-word;
        }

        .user-message .message-bubble {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: var(--light);
            border-bottom-right-radius: 0.25rem;
        }

        .bot-message .message-bubble {
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
            border-bottom-left-radius: 0.25rem;
        }

        .message-meta {
            font-size: 0.75rem;
            color: var(--gray);
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        .user-message .message-meta {
            justify-content: flex-end;
        }

        .typing-indicator {
            display: flex;
            gap: 0.25rem;
            padding: 0.5rem 0;
        }

        .typing-dot {
            width: 8px;
            height: 8px;
            background-color: var(--gray);
            border-radius: var(--radius-full);
            animation: typingBounce 1.5s infinite;
        }

        .typing-dot:nth-child(2) {
            animation-delay: 0.2s;
        }

        .typing-dot:nth-child(3) {
            animation-delay: 0.4s;
        }

        @keyframes typingBounce {
            0%, 60%, 100% { transform: translateY(0); }
            30% { transform: translateY(-5px); }
        }

        .chat-bot-input {
            display: flex;
            padding: 1.25rem 1.5rem;
            background: rgba(15, 23, 42, 0.95);
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }

        .chat-input-field {
            flex: 1;
            padding: 0.875rem 1.125rem;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: var(--radius-full);
            background: rgba(255, 255, 255, 0.05);
            color: var(--light);
            font-size: 0.9375rem;
            outline: none;
            transition: var(--transition);
        }

        .chat-input-field:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .chat-input-field::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }

        .chat-send-btn {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark));
            color: var(--light);
            border: none;
            width: 42px;
            height: 42px;
            border-radius: var(--radius-full);
            margin-left: 0.75rem;
            cursor: pointer;
            display: flex;
            justify-content: center;
            align-items: center;
            transition: var(--transition);
            box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
        }

        .chat-send-btn:hover {
            background: linear-gradient(135deg, var(--primary-dark), var(--primary));
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
        }

        .suggestion-buttons {
            display: flex;
            flex-wrap: wrap;
            gap: 0.5rem;
            margin-top: 0.5rem;
        }

        .suggestion-btn {
            background: rgba(37, 99, 235, 0.2);
            border: 1px solid rgba(37, 99, 235, 0.3);
            color: var(--primary-light);
            padding: 0.5rem 0.875rem;
            border-radius: var(--radius-full);
            font-size: 0.8125rem;
            cursor: pointer;
            transition: var(--transition);
            white-space: nowrap;
        }

        .suggestion-btn:hover {
            background: rgba(37, 99, 235, 0.3);
            transform: translateY(-2px);
        }

        /* JSON Response Notification Styles */
        .notification-container {
            position: fixed;
            top: 2rem;
            right: 2rem;
            z-index: 9999;
            display: flex;
            flex-direction: column;
            gap: 1rem;
            max-width: 400px;
        }

        .notification {
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            color: white;
            font-weight: 500;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            backdrop-filter: blur(12px);
            border: 1px solid rgba(255, 255, 255, 0.1);
            animation: slideInRight 0.3s ease-out;
            position: relative;
            overflow: hidden;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .notification::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            width: 4px;
        }

        .notification.success {
            background: rgba(16, 185, 129, 0.9);
        }

        .notification.success::before {
            background: var(--secondary-light);
        }

        .notification.error {
            background: rgba(239, 68, 68, 0.9);
        }

        .notification.error::before {
            background: #ff6b6b;
        }

        .notification.info {
            background: rgba(59, 130, 246, 0.9);
        }

        .notification.info::before {
            background: var(--info);
        }

        .notification.warning {
            background: rgba(245, 158, 11, 0.9);
        }

        .notification.warning::before {
            background: var(--warning);
        }

        .notification-icon {
            font-size: 1.25rem;
            flex-shrink: 0;
        }

        .notification-content {
            flex: 1;
        }

        .notification-title {
            font-weight: 600;
            margin-bottom: 0.25rem;
        }

        .notification-message {
            font-size: 0.9rem;
            opacity: 0.9;
        }

        .notification-close {
            background: none;
            border: none;
            color: white;
            cursor: pointer;
            font-size: 1.25rem;
            opacity: 0.7;
            transition: var(--transition);
            flex-shrink: 0;
        }

        .notification-close:hover {
            opacity: 1;
        }

        @keyframes slideInRight {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }

        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(100%);
                opacity: 0;
            }
        }

        /* Security overlay for sensitive operations */
        .security-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.8);
            z-index: 9999;
            display: none;
            align-items: center;
            justify-content: center;
        }

        .security-message {
            background: white;
            padding: 2rem;
            border-radius: var(--radius-lg);
            text-align: center;
            max-width: 400px;
        }

        /* Responsive Design */
        @media (max-width: 1200px) {
            .dashboard-layout {
                grid-template-columns: 1fr;
                gap: 1.25rem;
                height: auto;
            }
            
            .metrics-grid {
                grid-template-columns: repeat(3, 1fr);
            }

            .dashboard {
                height: auto;
                overflow: visible;
            }

            .events-news-card {
                height: 500px;
                max-height: 500px;
            }
        }

        @media (max-width: 1024px) {
            .sidebar {
                width: 80px;
            }
            
            .sidebar-menu-text,
            .sidebar-user-info,
            .sidebar-logo span,
            .sidebar-menu-title {
                display: none;
            }
            
            .main-content {
                margin-left: 80px;
            }
            
            .metrics-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        @media (max-width: 768px) {
            .sidebar {
                transform: translateX(-100%);
                position: fixed;
                z-index: 1000;
            }
            
            .sidebar.mobile-open {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
            }
            
            .dashboard {
                padding: 1rem;
            }
            
            .metrics-grid {
                grid-template-columns: 1fr;
            }
            
            .action-cards {
                gap: 1rem;
            }
            
            .chat-bot-box {
                width: 320px;
                height: 480px;
            }
            
            .chat-bot-container.maximized .chat-bot-box {
                width: 100%;
                height: 70vh;
                right: 0;
                bottom: 0;
                border-radius: var(--radius-lg) var(--radius-lg) 0 0;
            }

            .notification-container {
                right: 1rem;
                left: 1rem;
                max-width: none;
            }

            .events-header {
                flex-direction: column;
                align-items: stretch;
                gap: 0.75rem;
            }

            .events-controls {
                justify-content: center;
            }

            .header-content {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }
        }

        @media (max-width: 480px) {
            .header {
                padding: 1rem;
            }
            
            .dashboard {
                padding: 0.75rem;
            }
            
            .header-title {
                font-size: 1.5rem;
            }
            
            .chat-bot-container {
                right: 1rem;
                bottom: 1rem;
            }
            
            .chat-bot-box {
                width: calc(100vw - 2rem);
                right: 0;
            }
            
            .events-header {
                padding: 1rem;
            }
            
            .events-controls {
                flex-direction: column;
                width: 100%;
            }

            .events-filter {
                width: 100%;
                justify-content: space-between;
            }

            .filter-select, .filter-date {
                flex: 1;
            }
        }


    </style>
</head>
<body>
    <!-- Security overlay for sensitive operations -->
    <div class="security-overlay" id="security-overlay">
        <div class="security-message">
            <h3>Security Check</h3>
            <p>Please wait while we verify your session...</p>
        </div>
    </div>

    <!-- Notification Container for JSON Responses -->
    <div class="notification-container" id="notification-container"></div>




    <div class="app-container">
        <!-- Sidebar -->
        <aside class="sidebar no-select" id="sidebar">
            <div class="sidebar-header">
                <div class="sidebar-logo">
                    <i class="fas fa-heartbeat"></i>
                    <span>HealthCare</span>
                </div>
                <button class="sidebar-toggle" id="sidebar-toggle">
                    <i class="fas fa-chevron-left"></i>
                </button>
            </div>
            
            <div class="sidebar-user">
                <?php if (strpos($profile_picture, 'data:image') === 0): ?>
                    <!-- Base64 encoded image -->
                    <img src="<?php echo $profile_picture; ?>" alt="User Avatar" class="sidebar-user-avatar">
                <?php else: ?>
                    <!-- Regular file path (no ../ needed since uploads is in current directory) -->
                    <img src="<?php echo htmlspecialchars($profile_picture); ?>" alt="User Avatar" class="sidebar-user-avatar" onerror="this.src='<?php echo $default_avatar; ?>';">
                <?php endif; ?>
                <div class="sidebar-user-info">
                    <div class="sidebar-user-name"><?php echo htmlspecialchars($first_name . ' ' . $last_name); ?></div>
                    <div class="sidebar-user-role">Patient</div>
                </div>
            </div>

            <div class="sidebar-menu">
                <div class="sidebar-menu-title">Main Menu</div>
                <ul class="sidebar-menu-items">
                    <li class="sidebar-menu-item">
                        <a href="#" class="sidebar-menu-link active">
                            <span class="sidebar-menu-icon"><i class="fas fa-home"></i></span>
                            <span class="sidebar-menu-text">Dashboard</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="patient_profile.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-user"></i></span>
                            <span class="sidebar-menu-text">My Profile</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="patient_history.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-history"></i></span>
                            <span class="sidebar-menu-text">Medical History</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="patient_medi_report.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-file-medical"></i></span>
                            <span class="sidebar-menu-text">Medi Reports</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="hospital_list.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-hospital"></i></span>
                            <span class="sidebar-menu-text">Hospitals</span>
                        </a>
                    </li>
                </ul>
                <div class="sidebar-menu-title">Support</div>
                <ul class="sidebar-menu-items">
                    <li class="sidebar-menu-item">
                        <a href="../faq.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-question-circle"></i></span>
                            <span class="sidebar-menu-text">FAQ</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="../contactus.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-envelope"></i></span>
                            <span class="sidebar-menu-text">Contact Hospital</span>
                        </a>
                    </li>
                    <li class="sidebar-menu-item">
                        <a href="../send_report.php" class="sidebar-menu-link">
                            <span class="sidebar-menu-icon"><i class="fas fa-envelope"></i></span>
                            <span class="sidebar-menu-text">Contact Us</span>
                        </a>
                    </li>
                </ul>
            </div>
            
            <div class="sidebar-footer">
                <button class="logout-button" onclick="secureLogout()">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Logout</span>
                </button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="main-content">
            <header class="header no-select">
                <div class="header-content">
                    <h1 class="header-title">Welcome back, <?php echo htmlspecialchars($first_name); ?>!</h1>
                    <p class="header-subtitle">Here's an overview of your healthcare journey</p>
                </div>
                <!-- Session Timer Display -->
                <div class="session-timer" id="session-timer">
                    <i class="fas fa-clock"></i>
                    <span id="timer-text">Your session will end in 30:00</span>
                </div>
            </header>

            <div class="dashboard">
                <!-- New 50/50 Dashboard Layout -->
                <div class="dashboard-layout">
                    <!-- Left Side (50%) -->
                    <div class="dashboard-left">
                        <!-- Combined Metrics Card -->
                        <div class="combined-metrics-card">
                            <div class="metrics-header">
                                <div class="metrics-title">Healthcare Metrics</div>
                                <div class="metrics-subtitle">Real-time statistics from our healthcare network</div>
                            </div>
                            <div class="metrics-grid">
                                <div class="metric-item">
                                    <div class="metric-icon doctors">
                                        <i class="fas fa-user-md"></i>
                                    </div>
                                    <div class="metric-value" id="doctors-count"><?php echo $doctor_count; ?></div>
                                    <div class="metric-label">Doctors Available</div>
                                </div>
                                <div class="metric-item">
                                    <div class="metric-icon hospitals">
                                        <i class="fas fa-hospital"></i>
                                    </div>
                                    <div class="metric-value" id="hospitals-count"><?php echo $hospital_count; ?></div>
                                    <div class="metric-label">Partner Hospitals</div>
                                </div>
                                <div class="metric-item">
                                    <div class="metric-icon patients">
                                        <i class="fas fa-users"></i>
                                    </div>
                                    <div class="metric-value" id="patients-count"><?php echo $patient_count; ?></div>
                                    <div class="metric-label">Patients Helped</div>
                                </div>
                            </div>
                        </div>

                        <!-- Action Cards -->
                        <div class="action-cards">
                            <div class="action-card public">
                                <div class="action-card-header">
                                    <div class="action-card-icon public">
                                        <i class="fas fa-globe"></i>
                                    </div>
                                    <div class="action-card-title">Public Consultation</div>
                                </div>
                                <div class="action-card-description">
                                    Submit your health concern to our network of doctors for professional advice. Your case will be visible to all doctors in our network.
                                </div>
                                <a href="detailed_problem.php" class="action-card-button public">
                                    <i class="fas fa-plus-circle"></i>
                                    <span>Submit Public Problem</span>
                                </a>
                            </div>

                            <div class="action-card private">
                                <div class="action-card-header">
                                    <div class="action-card-icon private">
                                        <i class="fas fa-lock"></i>
                                    </div>
                                    <div class="action-card-title">Private Consultation</div>
                                </div>
                                <div class="action-card-description">
                                    Submit a confidential health concern that will only be shared with selected healthcare professionals. Ideal for sensitive health issues.
                                </div>
                                <a href="PrivatePatientProblems/submit_problem.php" class="action-card-button private">
                                    <i class="fas fa-plus-circle"></i>
                                    <span>Submit Private Problem</span>
                                </a>
                            </div>
                        </div>
                    </div>

                    <!-- Right Side (50%) -->
                    <div class="dashboard-right">
                        <!-- Events/News Card -->
                        <div class="events-news-card">
                            <div class="events-header">
                                <div class="events-title">
                                    <i class="fas fa-newspaper"></i>
                                    Events & News
                                </div>
                                <div class="events-controls">
                                    <div class="events-filter">
                                        <select class="filter-select" id="events-filter">
                                            <option value="all">All</option>
                                            <option value="today">Today</option>
                                            <option value="custom">Custom Date</option>
                                        </select>
                                        <input type="date" class="filter-date" id="custom-date">
                                    </div>
                                    <button class="scroll-control-btn" id="scroll-control">
                                        <i class="fas fa-pause"></i>
                                        <span>Stop Scrolling</span>
                                    </button>
                                </div>
                            </div>
                            <div class="events-content">
                                <div class="events-scroll-container" id="events-scroll-container">
                                    <div class="events-list" id="events-list">
                                        <!-- Events will be loaded here -->
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>

        <!-- Enhanced Secure Chatbot -->
        <div class="chat-bot-container" id="chat-container">
            <div class="chat-bot-box" id="chat-box">
                <div class="chat-bot-header">
                    <div class="chat-bot-title">
                        <i class="fas fa-robot"></i>
                        <span>Healthcare Assistant</span>
                    </div>
                    <div class="chat-controls">
                        <button class="chat-control-btn" id="maximize-btn" title="Maximize">
                            <i class="fas fa-expand-alt"></i>
                        </button>
                        <button class="chat-control-btn" id="minimize-btn" title="Close">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                </div>
                <div class="chat-bot-content" id="chat-content">
                    <!-- Chat messages will appear here -->
                </div>
                <div class="chat-bot-input">
                    <input type="text" class="chat-input-field" id="chat-input" placeholder="Type your message here..." maxlength="500" />
                    <button class="chat-send-btn" id="chat-send">
                        <i class="fas fa-paper-plane"></i>
                    </button>
                </div>
            </div>
            <div class="chat-bot-toggle pulse" id="chat-toggle">
                <i class="fas fa-comment-medical"></i>
            </div>
        </div>
    </div>

    <!-- Enhanced Security JavaScript -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js" integrity="sha256-/xUj+3OJU5yExlq6GSYGSHk7tPXikynS7ogEvDej/m4=" crossorigin="anonymous"></script>
    <script>
// Enhanced security configuration
const CSRF_TOKEN = '<?php echo $_SESSION['csrf_token']; ?>';
const SESSION_TIMEOUT = 1800000; // 30 minutes in milliseconds
const HEARTBEAT_INTERVAL = 300000; // 5 minutes
const USER_EMAIL = '<?php echo $user_email; ?>';
const SHOW_WELCOME = <?php echo $show_welcome ? 'true' : 'false'; ?>;

// Security measures
let lastActivity = Date.now();
let sessionWarningShown = false;
let heartbeatInterval;
let securityEventCount = 0;
let sessionTimerInterval;
let sessionTimeRemaining = SESSION_TIMEOUT; // 30 minutes in milliseconds
let isTimerVisible = false;

// Events/News variables
let eventsData = [];
let currentFilter = 'all';
let isScrolling = true;
let scrollInterval;

// Enhanced chatbot connection variables
let connectionStatus = 'online';
let connectionCheckInterval;
let pendingMessages = [];
let retryAttempts = new Map();

// JSON Response Notification System
function showNotification(message, type = 'info', title = null) {
    const container = document.getElementById('notification-container');
    if (!container) {
        // Create notification container if it doesn't exist
        const notificationContainer = document.createElement('div');
        notificationContainer.id = 'notification-container';
        notificationContainer.className = 'notification-container';
        document.body.appendChild(notificationContainer);
    }
    
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    
    let iconClass = 'fas fa-info-circle';
    let notificationTitle = title || 'Information';
    
    switch(type) {
        case 'success':
            iconClass = 'fas fa-check-circle';
            notificationTitle = title || 'Success';
            break;
        case 'error':
            iconClass = 'fas fa-exclamation-circle';
            notificationTitle = title || 'Error';
            break;
        case 'warning':
            iconClass = 'fas fa-exclamation-triangle';
            notificationTitle = title || 'Warning';
            break;
        case 'info':
        default:
            iconClass = 'fas fa-info-circle';
            notificationTitle = title || 'Information';
            break;
    }
    
    notification.innerHTML = `
        <div class="notification-icon">
            <i class="${iconClass}"></i>
        </div>
        <div class="notification-content">
            <div class="notification-title">${notificationTitle}</div>
            <div class="notification-message">${message}</div>
        </div>
        <button class="notification-close">
            <i class="fas fa-times"></i>
        </button>
    `;
    
    // Add click handler for close button
    const closeBtn = notification.querySelector('.notification-close');
    closeBtn.addEventListener('click', () => {
        removeNotification(notification);
    });
    
    // Add to container
    const notificationContainer = document.getElementById('notification-container');
    notificationContainer.appendChild(notification);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            removeNotification(notification);
        }
    }, 5000);
}

function removeNotification(notification) {
    notification.style.animation = 'slideOutRight 0.3s ease-out';
    setTimeout(() => {
        if (notification.parentNode) {
            notification.parentNode.removeChild(notification);
        }
    }, 300);
}

// Events/News Functions
function fetchEvents(filter = 'all', customDate = '') {
    $.ajax({
        url: window.location.href,
        type: 'POST',
        data: {
            action: 'fetch_events',
            filter: filter,
            custom_date: customDate,
            csrf_token: CSRF_TOKEN
        },
        dataType: 'json',
        success: function(response) {
            if (response.success) {
                eventsData = response.events;
                displayEvents();
            } else {
                showNotification(response.message || 'Failed to load events', 'error');
            }
        },
        error: function() {
            showNotification('Error loading events', 'error');
        }
    });
}

function displayEvents() {
    const eventsList = document.getElementById('events-list');
    eventsList.innerHTML = '';
    
    if (eventsData.length === 0) {
        eventsList.innerHTML = `
            <div class="event-item">
                <div class="event-title">No events found</div>
                <div class="event-description">There are no events to display for the selected filter.</div>
            </div>
        `;
        return;
    }
    
    eventsData.forEach(event => {
        const eventItem = document.createElement('div');
        eventItem.className = 'event-item';
        
        const eventDate = new Date(event.created_at);
        const formattedDate = eventDate.toLocaleDateString() + ' ' + eventDate.toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'});
        
        let authorLabel = '';
        if (event.posted_by === 'admin') {
            authorLabel = '<i class="fas fa-user-shield"></i> Admin';
        } else if (event.posted_by === 'hospital') {
            authorLabel = `<i class="fas fa-hospital"></i> ${event.hospital_name || 'Hospital'}`;
        }
        
        // Dynamic media handling
        let mediaContent = '';
        let mediaClass = 'no-media';
        
        if (event.image_path && event.image_path.trim() !== '') {
            mediaClass = 'has-media';
            mediaContent = `<img src="${event.image_path}" alt="Event Image" class="event-media ${mediaClass}" onerror="this.className='event-media no-media'">`;
        } else if (event.video_path && event.video_path.trim() !== '') {
            mediaClass = 'has-media';
            mediaContent = `<video src="${event.video_path}" class="event-media ${mediaClass}" controls></video>`;
        }
        
        eventItem.innerHTML = `
            ${mediaContent}
            <div class="event-title">${event.title}</div>
            <div class="event-description">${event.description}</div>
            <div class="event-meta">
                <div class="event-author">${authorLabel}</div>
                <div class="event-date">${formattedDate}</div>
            </div>
        `;
        
        eventsList.appendChild(eventItem);
    });
}

// Scroll Control Functions
function toggleScrolling() {
    const scrollControlBtn = document.getElementById('scroll-control');
    const eventsList = document.getElementById('events-list');
    const scrollContainer = document.getElementById('events-scroll-container');
    
    if (isScrolling) {
        // Stop scrolling
        isScrolling = false;
        eventsList.classList.add('paused');
        eventsList.classList.add('manual');
        scrollContainer.classList.add('manual-scroll');
        scrollControlBtn.innerHTML = '<i class="fas fa-play"></i><span>Start Scrolling</span>';
        showNotification('Auto-scrolling stopped. You can now scroll manually.', 'info', 'Scroll Control');
    } else {
        // Start scrolling
        isScrolling = true;
        eventsList.classList.remove('paused');
        eventsList.classList.remove('manual');
        scrollContainer.classList.remove('manual-scroll');
        scrollContainer.scrollTop = 0; // Reset scroll position
        scrollControlBtn.innerHTML = '<i class="fas fa-pause"></i><span>Stop Scrolling</span>';
        showNotification('Auto-scrolling resumed.', 'success', 'Scroll Control');
    }
}

// Session Timer Functions
function updateSessionTimer() {
    const now = Date.now();
    const timeSinceActivity = now - lastActivity;
    sessionTimeRemaining = SESSION_TIMEOUT - timeSinceActivity;
    
    const timerElement = document.getElementById('session-timer');
    const timerText = document.getElementById('timer-text');
    
    if (sessionTimeRemaining <= 300000 && !isTimerVisible) { // Show timer when 5 minutes left
        isTimerVisible = true;
        timerElement.classList.add('show');
    }
    
    if (sessionTimeRemaining <= 0) {
        // Session timed out
        timerText.textContent = 'Session timed out';
        showNotification('Session timed out. Redirecting to login...', 'error', 'Session Expired');
        setTimeout(() => {
            window.location.href = '../logout.php';
        }, 2000);
        return;
    }
    
    if (isTimerVisible) {
        const minutes = Math.floor(sessionTimeRemaining / 60000);
        const seconds = Math.floor((sessionTimeRemaining % 60000) / 1000);
        timerText.textContent = `Your session will end in ${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
}

function hideSessionTimer() {
    const timerElement = document.getElementById('session-timer');
    timerElement.classList.remove('show');
    isTimerVisible = false;
}

function resetSessionTimer() {
    sessionTimeRemaining = SESSION_TIMEOUT;
    hideSessionTimer();
}

// Optimized security logging function - Only log critical events
function logSecurityEvent(eventType, details = '') {
    // Only log critical security events to prevent database bloat
    const criticalEvents = [
        'UNAUTHORIZED_DASHBOARD_ACCESS',
        'SESSION_TIMEOUT',
        'SESSION_HIJACK_ATTEMPT',
        'CSRF_TOKEN_MISMATCH',
        'RATE_LIMIT_EXCEEDED',
        'MALICIOUS_CHATBOT_INPUT',
        'DEV_TOOLS_DETECTED',
        'LOGIN_FAILURE'
    ];
    
    if (criticalEvents.includes(eventType)) {
        securityEventCount++;
        
        $.ajax({
            url: window.location.href,
            type: 'POST',
            data: {
                action: 'log_security_event',
                event_type: eventType,
                details: details,
                csrf_token: CSRF_TOKEN,
                timestamp: Date.now()
            },
            dataType: 'json',
            success: function(response) {
                if (!response.success) {
                    console.warn('Security logging failed');
                    if (response.message) {
                        showNotification(response.message, response.type || 'error');
                    }
                }
            },
            error: function() {
                console.warn('Security logging request failed');
            }
        });
        
        // If too many critical security events, force logout
        if (securityEventCount > 5) {
            showNotification('Multiple security violations detected. You will be logged out for your protection.', 'error', 'Security Alert');
            setTimeout(() => {
                window.location.href = '../logout.php';
            }, 3000);
        }
    }
}

// Enhanced security functions
function updateActivity() {
    lastActivity = Date.now();
    sessionWarningShown = false;
    resetSessionTimer();
}

function checkSessionTimeout() {
    const now = Date.now();
    const timeSinceActivity = now - lastActivity;
    
    // Show warning at 25 minutes
    if (timeSinceActivity > 1500000 && !sessionWarningShown) {
        sessionWarningShown = true;
        showNotification('Your session will expire in 5 minutes. Any activity will extend your session.', 'warning', 'Session Warning');
    }
    
    // Force logout at 30 minutes
    if (timeSinceActivity > SESSION_TIMEOUT) {
        showNotification('Session expired. Redirecting to login...', 'error', 'Session Expired');
        setTimeout(() => {
            window.location.href = '../logout.php?timeout=1';
        }, 2000);
    }
}

function sendHeartbeat() {
    $.ajax({
        url: window.location.href,
        type: 'POST',
        data: {
            action: 'heartbeat',
            csrf_token: CSRF_TOKEN
        },
        dataType: 'json',
        success: function(response) {
            if (!response.success) {
                logSecurityEvent('HEARTBEAT_FAILED', 'Heartbeat validation failed');
                showNotification('Session validation failed. Please login again.', 'error');
                setTimeout(() => {
                    window.location.href = '../logout.php?session_expired=1';
                }, 2000);
            }
        },
        error: function() {
            // Don't log heartbeat errors to prevent database bloat
        }
    });
}

function secureLogout() {
    if (confirm('Are you sure you want to logout?')) {
        document.getElementById('security-overlay').style.display = 'flex';
        showNotification('Logging out securely...', 'info');
        setTimeout(() => {
            window.location.href = '../logout.php';
        }, 1000);
    }
}

// Enhanced activity detection
function setupActivityDetection() {
    const activityEvents = ['click', 'keypress', 'scroll', 'mousemove', 'touchstart', 'touchmove'];
    
    activityEvents.forEach(event => {
        document.addEventListener(event, updateActivity, { passive: true });
    });
}

// Start session monitoring
function initializeSessionMonitoring() {
    // Check session timeout every minute
    setInterval(checkSessionTimeout, 60000);
    
    // Update session timer every second
    sessionTimerInterval = setInterval(updateSessionTimer, 1000);
    
    // Send heartbeat every 5 minutes
    heartbeatInterval = setInterval(sendHeartbeat, HEARTBEAT_INTERVAL);
}

// Enhanced security - disable developer tools
document.addEventListener('contextmenu', function(e) {
    e.preventDefault();
    logSecurityEvent('RIGHT_CLICK_BLOCKED', 'Right-click context menu blocked');
    showNotification('Right-click is disabled for security reasons.', 'warning');
    return false;
});

document.addEventListener('keydown', function(e) {
    // Disable F12, Ctrl+Shift+I, Ctrl+U, Ctrl+S, Ctrl+Shift+C, Ctrl+A
    if (e.keyCode === 123 || 
        (e.ctrlKey && e.shiftKey && e.keyCode === 73) ||
        (e.ctrlKey && e.keyCode === 85) ||
        (e.ctrlKey && e.keyCode === 83) ||
        (e.ctrlKey && e.shiftKey && e.keyCode === 67) ||
        (e.ctrlKey && e.keyCode === 65)) {
        e.preventDefault();
        logSecurityEvent('DEV_TOOLS_ATTEMPT', 'Developer tools or restricted key combination blocked');
        showNotification('This action is disabled for security reasons.', 'warning');
        return false;
    }
});

// Enhanced developer tools detection
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
            logSecurityEvent('DEV_TOOLS_DETECTED', 'Developer tools opened');
            console.clear();
            showNotification('Developer tools detected. For security reasons, please close them immediately.', 'error', 'Security Alert');
            // Additional security measure
            document.body.style.display = 'none';
            setTimeout(() => {
                document.body.style.display = 'flex';
            }, 2000);
        }
    } else {
        if (devtools.open) {
            devtools.open = false;
        }
    }
}, 500);

// Enhanced DOM elements
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebar-toggle');
const mainContent = document.querySelector('.main-content');

// Sidebar functionality
sidebarToggle.addEventListener('click', function() {
    sidebar.classList.toggle('sidebar-collapsed');
    mainContent.classList.toggle('sidebar-collapsed');
    
    const icon = sidebarToggle.querySelector('i');
    if (sidebar.classList.contains('sidebar-collapsed')) {
        icon.classList.remove('fa-chevron-left');
        icon.classList.add('fa-chevron-right');
    } else {
        icon.classList.remove('fa-chevron-right');
        icon.classList.add('fa-chevron-left');
    }
    updateActivity();
});

// Events filter functionality
const eventsFilter = document.getElementById('events-filter');
const customDate = document.getElementById('custom-date');
const scrollControlBtn = document.getElementById('scroll-control');

eventsFilter.addEventListener('change', function() {
    currentFilter = this.value;
    if (currentFilter === 'custom') {
        customDate.classList.add('show');
    } else {
        customDate.classList.remove('show');
        fetchEvents(currentFilter);
    }
    updateActivity();
});

customDate.addEventListener('change', function() {
    if (currentFilter === 'custom' && this.value) {
        fetchEvents('custom', this.value);
    }
    updateActivity();
});

// Scroll control functionality
scrollControlBtn.addEventListener('click', function() {
    toggleScrolling();
    updateActivity();
});

// Enhanced Chatbot Functionality
const chatToggle = document.getElementById('chat-toggle');
const chatContainer = document.getElementById('chat-container');
const chatBox = document.getElementById('chat-box');
const chatContent = document.getElementById('chat-content');
const chatInput = document.getElementById('chat-input');
const chatSend = document.getElementById('chat-send');
const maximizeBtn = document.getElementById('maximize-btn');
const minimizeBtn = document.getElementById('minimize-btn');

let isMaximized = false;
let chatHistory = [];
let messageCount = 0;

// Enhanced chatbot toggle
chatToggle.addEventListener('click', function() {
    chatContainer.classList.toggle('open');
    updateActivity();
    
    if (chatContainer.classList.contains('open')) {
        // Initialize chat if first time opening
        if (chatHistory.length === 0) {
            addBotMessage("Hello! I'm your healthcare assistant. How can I help you today?", [
                "Who are you.?",
                "I have 1 problem",
                "I want to cunsult a doctor ",
                "Who is the developer",
                "What are the causes of fever?"
            ]);
        }
    }
});

// Chat controls
maximizeBtn.addEventListener('click', function() {
    isMaximized = !isMaximized;
    chatContainer.classList.toggle('maximized', isMaximized);
    
    const icon = maximizeBtn.querySelector('i');
    if (isMaximized) {
        icon.classList.remove('fa-expand-alt');
        icon.classList.add('fa-compress-alt');
        maximizeBtn.title = 'Minimize';
    } else {
        icon.classList.remove('fa-compress-alt');
        icon.classList.add('fa-expand-alt');
        maximizeBtn.title = 'Maximize';
    }
    updateActivity();
});

minimizeBtn.addEventListener('click', function() {
    chatContainer.classList.remove('open');
    updateActivity();
});

// Enhanced chat input handling
chatInput.addEventListener('keypress', function(e) {
    if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendMessage();
    }
    updateActivity();
});

chatInput.addEventListener('input', function() {
    // Monitor for suspicious input patterns
    const value = this.value.toLowerCase();
    const suspiciousPatterns = [
        'script', 'javascript:', 'eval(', 'document.', 'window.',
        'alert(', 'confirm(', 'prompt(', 'console.', 'location.',
        'iframe', 'object', 'embed', 'onload', 'onerror'
    ];
    
    if (suspiciousPatterns.some(pattern => value.includes(pattern))) {
        logSecurityEvent('SUSPICIOUS_CHAT_INPUT', 'Suspicious patterns detected in chat input: ' + value.substring(0, 50));
        this.value = this.value.replace(/[<>]/g, '');
        showNotification('Suspicious content detected and removed.', 'warning');
    }
    updateActivity();
});

chatSend.addEventListener('click', sendMessage);

// Enhanced connection status monitoring
function startConnectionMonitoring() {
    connectionCheckInterval = setInterval(checkConnectionStatus, 30000); // Check every 30 seconds
}

function checkConnectionStatus() {
    // Simple connection check
    fetch(window.location.href, {
        method: 'HEAD',
        cache: 'no-cache'
    }).then(response => {
        if (response.ok) {
            if (connectionStatus === 'offline') {
                connectionStatus = 'online';
                showNotification('Connection restored!', 'success');
                // Process any pending messages
                processPendingMessages();
            }
        } else {
            throw new Error('Connection failed');
        }
    }).catch(() => {
        if (connectionStatus === 'online') {
            connectionStatus = 'offline';
            showNotification('Connection lost. Messages will be retried automatically.', 'warning');
        }
    });
}

function processPendingMessages() {
    if (pendingMessages.length > 0) {
        const messages = [...pendingMessages];
        pendingMessages = [];
        
        messages.forEach(message => {
            sendMessageWithRetry(message, 3);
        });
    }
}

function isRetryableError(xhr, status, error) {
    // Define which errors are worth retrying
    const retryableStatuses = [0, 408, 500, 502, 503, 504];
    const retryableErrors = ['timeout', 'error', 'abort'];
    
    return retryableStatuses.includes(xhr.status) || 
           retryableErrors.includes(status) ||
           error.toLowerCase().includes('timeout') ||
           error.toLowerCase().includes('network');
}

function updateTypingIndicatorForRetry(attempt) {
    const typingIndicator = chatContent.querySelector('.typing-indicator-message');
    if (typingIndicator) {
        const bubble = typingIndicator.querySelector('.message-bubble');
        bubble.innerHTML = `
            <div class="typing-indicator">
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
            </div>
            <div style="font-size: 0.8rem; color: rgba(255,255,255,0.7); margin-top: 0.5rem;">
                Reconnecting... (attempt ${attempt})
            </div>
        `;
    }
}

function sendMessageWithRetry(message, maxRetries, currentAttempt = 1) {
    const messageId = Date.now() + '_' + Math.random();
    const timeoutDuration = Math.min(15000 + (currentAttempt * 5000), 30000); // Progressive timeout

    $.ajax({
        url: window.location.href,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({
            message: message,
            csrf_token: CSRF_TOKEN,
            timestamp: Date.now(),
            attempt: currentAttempt,
            messageId: messageId
        }),
        timeout: timeoutDuration,
        beforeSend: function(xhr) {
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.setRequestHeader('X-CSRF-Token', CSRF_TOKEN);
        },
        success: function(response) {
            hideTypingIndicator();
            retryAttempts.delete(messageId);
            
            try {
                if (typeof response === 'string') {
                    response = JSON.parse(response);
                }
                
                if (response.status === 'success') {
                    addBotMessage(response.message, response.suggestions || []);
                    
                    // Show attempt info for debugging (remove in production)
                    if (response.attempt && response.attempt > 1) {
                        console.log(`Message delivered on attempt ${response.attempt}`);
                    }
                } else {
                    handleChatError(response, message, maxRetries, currentAttempt, messageId);
                }
            } catch (e) {
                console.error('Response parsing error:', e);
                handleChatError({
                    message: "Error processing response",
                    type: "error"
                }, message, maxRetries, currentAttempt, messageId);
            }
            
            updateActivity();
        },
        error: function(xhr, status, error) {
            console.error(`Chat error (attempt ${currentAttempt}):`, error);
            
            if (xhr.status === 403) {
                hideTypingIndicator();
                retryAttempts.delete(messageId);
                showNotification('Session expired. Please refresh the page.', 'error');
                setTimeout(() => {
                    window.location.reload();
                }, 2000);
                return;
            }
            
            if (xhr.status === 429) {
                hideTypingIndicator();
                retryAttempts.delete(messageId);
                addBotMessage("Too many requests. Please wait a moment before sending another message.");
                showNotification('Rate limit exceeded. Please wait before sending another message.', 'warning');
                return;
            }
            
            // Handle retryable errors
            if (currentAttempt < maxRetries && isRetryableError(xhr, status, error)) {
                console.log(`Retrying message (attempt ${currentAttempt + 1}/${maxRetries})`);
                
                // Update typing indicator to show retry
                updateTypingIndicatorForRetry(currentAttempt + 1);
                
                // Exponential backoff
                const delay = Math.min(1000 * Math.pow(2, currentAttempt - 1), 5000);
                setTimeout(() => {
                    sendMessageWithRetry(message, maxRetries, currentAttempt + 1);
                }, delay);
            } else {
                hideTypingIndicator();
                retryAttempts.delete(messageId);
                handleFinalError(xhr, status, error, currentAttempt);
            }
        }
    });
}

function handleChatError(response, originalMessage, maxRetries, currentAttempt, messageId) {
    if (response.retry_suggested && currentAttempt < maxRetries) {
        console.log(`API suggested retry (attempt ${currentAttempt + 1}/${maxRetries})`);
        updateTypingIndicatorForRetry(currentAttempt + 1);
        
        setTimeout(() => {
            sendMessageWithRetry(originalMessage, maxRetries, currentAttempt + 1);
        }, 2000);
    } else {
        hideTypingIndicator();
        retryAttempts.delete(messageId);
        addBotMessage(response.message || "I'm having trouble connecting right now. Please try again in a moment.");
        if (response.message) {
            showNotification(response.message, response.type || 'error');
        }
    }
}

function handleFinalError(xhr, status, error, attempts) {
    let errorMessage = "I'm having trouble connecting right now. ";
    
    if (status === 'timeout') {
        errorMessage += "The connection timed out. Please try again.";
    } else if (xhr.status === 0) {
        errorMessage += "Please check your internet connection and try again.";
    } else if (xhr.status >= 500) {
        errorMessage += "The service is temporarily unavailable. Please try again later.";
    } else {
        errorMessage += "Please try again in a moment.";
    }
    
    addBotMessage(errorMessage);
    showNotification(`Connection failed after ${attempts} attempts. Please try again.`, 'error');
}

// Enhanced secure message sending with retry mechanism
function sendMessage() {
    const message = chatInput.value.trim();
    if (!message) return;

    // Enhanced input validation and sanitization
    if (message.length > 500) {
        showNotification('Message too long. Please keep it under 500 characters.', 'warning');
        return;
    }

    // Security check for malicious content
    const dangerousPatterns = [
        /<script/i,
        /javascript:/i,
        /on\w+\s*=/i,
        /<iframe/i,
        /<object/i,
        /<embed/i,
        /eval\s*\(/i,
        /document\./i,
        /window\./i,
        /location\./i,
        /console\./i
    ];

    if (dangerousPatterns.some(pattern => pattern.test(message))) {
        showNotification('Invalid message content detected.', 'error');
        logSecurityEvent('MALICIOUS_CHAT_INPUT', 'Dangerous patterns in message: ' + message.substring(0, 100));
        chatInput.value = '';
        return;
    }

    messageCount++;
    if (messageCount > 50) {
        showNotification('Too many messages sent. Please wait before sending more.', 'warning');
        return;
    }

    addUserMessage(message);
    chatInput.value = '';
    showTypingIndicator();

    // Check connection status before sending
    if (connectionStatus === 'offline') {
        pendingMessages.push(message);
        showNotification('Connection is offline. Message will be sent when connection is restored.', 'info');
        return;
    }

    // Enhanced retry mechanism
    sendMessageWithRetry(message, 3);
}

// Enhanced message display functions
function addUserMessage(message) {
    const messageElement = createMessageElement('user', sanitizeHTML(message));
    chatContent.appendChild(messageElement);
    chatHistory.push({type: 'user', message: message, timestamp: new Date()});
    scrollToBottom();
}

function addBotMessage(message, suggestions = []) {
    const messageElement = createMessageElement('bot', sanitizeHTML(message), suggestions);
    chatContent.appendChild(messageElement);
    chatHistory.push({type: 'bot', message: message, timestamp: new Date()});
    scrollToBottom();
}

function linkify(text) {
    // Convert https:// links into clickable <a> tags
    return text.replace(/(https:\/\/[^\s]+)/g, function(url) {
        // Escape HTML entities in the URL itself for safety
        const safeUrl = url.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return `<a href="${safeUrl}" target="_blank" rel="noopener noreferrer">${safeUrl}</a>`;
    });
}


function createMessageElement(type, message, suggestions = []) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${type}-message`;
    
    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';
    bubble.innerHTML = linkify(message);

    
    const meta = document.createElement('div');
    meta.className = 'message-meta';
    meta.innerHTML = `<i class="fas fa-clock"></i> ${new Date().toLocaleTimeString([], {hour: '2-digit', minute:'2-digit'})}`;
    
    messageDiv.appendChild(bubble);
    messageDiv.appendChild(meta);
    
    // Add suggestion buttons for bot messages
    if (type === 'bot' && suggestions.length > 0) {
        const suggestionsDiv = document.createElement('div');
        suggestionsDiv.className = 'suggestion-buttons';
        
        suggestions.forEach(suggestion => {
            const btn = document.createElement('button');
            btn.className = 'suggestion-btn';
            btn.textContent = suggestion;
            btn.onclick = () => {
                chatInput.value = suggestion;
                sendMessage();
            };
            suggestionsDiv.appendChild(btn);
        });
        
        messageDiv.appendChild(suggestionsDiv);
    }
    
    return messageDiv;
}

function showTypingIndicator() {
    // Remove any existing typing indicator first
    hideTypingIndicator();
    
    const typingDiv = document.createElement('div');
    typingDiv.className = 'chat-message bot-message typing-indicator-message';
    typingDiv.innerHTML = `
        <div class="message-bubble">
            <div class="typing-indicator">
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
                <div class="typing-dot"></div>
            </div>
        </div>
    `;
    chatContent.appendChild(typingDiv);
    scrollToBottom();
}

function hideTypingIndicator() {
    const typingIndicator = chatContent.querySelector('.typing-indicator-message');
    if (typingIndicator) {
        typingIndicator.remove();
    }
}

function scrollToBottom() {
    chatContent.scrollTop = chatContent.scrollHeight;
}

// Enhanced HTML sanitization
function sanitizeHTML(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

// Enhanced stats animation
function animateStats() {
    const statValues = document.querySelectorAll('.metric-value');
    
    statValues.forEach(stat => {
        const finalValue = parseInt(stat.textContent);
        let currentValue = 0;
        const increment = Math.ceil(finalValue / 50);
        
        const timer = setInterval(() => {
            currentValue += increment;
            if (currentValue >= finalValue) {
                currentValue = finalValue;
                clearInterval(timer);
            }
            stat.textContent = currentValue;
        }, 30);
    });
}

// Enhanced mobile responsiveness
function handleMobileMenu() {
    if (window.innerWidth <= 768) {
        sidebar.classList.add('mobile-menu');
        
        // Add mobile menu toggle
        if (!document.querySelector('.mobile-menu-toggle')) {
            const mobileToggle = document.createElement('button');
            mobileToggle.className = 'mobile-menu-toggle';
            mobileToggle.innerHTML = '<i class="fas fa-bars"></i>';
            mobileToggle.style.cssText = `
                position: fixed;
                top: 1rem;
                left: 1rem;
                z-index: 1001;
                background: var(--primary);
                color: white;
                border: none;
                width: 40px;
                height: 40px;
                border-radius: 8px;
                cursor: pointer;
                display: flex;
                align-items: center;
                justify-content: center;
            `;
            
            mobileToggle.addEventListener('click', () => {
                sidebar.classList.toggle('mobile-open');
                updateActivity();
            });
            
            document.body.appendChild(mobileToggle);
        }
    }
}

// Enhanced initialization
document.addEventListener('DOMContentLoaded', function() {
    // Setup activity detection
    setupActivityDetection();
    
    // Initialize session monitoring
    initializeSessionMonitoring();
    
    // Start connection monitoring
    startConnectionMonitoring();
    
    // Animate stats on load
    setTimeout(animateStats, 500);
    
    // Load events/news
    fetchEvents();
    
    // Handle mobile responsiveness
    handleMobileMenu();
    window.addEventListener('resize', handleMobileMenu);
    
    // Enhanced security - clear sensitive data on page unload
    window.addEventListener('beforeunload', function() {
        // Clear sensitive data
        chatHistory = [];
        pendingMessages = [];
        retryAttempts.clear();
        if (typeof chatInput !== 'undefined') {
            chatInput.value = '';
        }
        
        // Cleanup intervals
        if (connectionCheckInterval) {
            clearInterval(connectionCheckInterval);
        }
        if (heartbeatInterval) {
            clearInterval(heartbeatInterval);
        }
        if (sessionTimerInterval) {
            clearInterval(sessionTimerInterval);
        }
    });
    
    // Enhanced security - prevent iframe embedding
    if (window.top !== window.self) {
        logSecurityEvent('IFRAME_EMBEDDING_DETECTED', 'Page loaded in iframe');
        window.top.location = window.self.location;
    }
    
    // Reset message count every hour
    setInterval(function() {
        messageCount = 0;
    }, 3600000);
    
    // Show welcome notification only once
    if (SHOW_WELCOME) {
        setTimeout(() => {
            showNotification('Welcome to your secure healthcare dashboard!', 'success', 'Welcome');
        }, 1000);
    }
    
    console.log('Enhanced secure dashboard initialized successfully');
});

// Enhanced cleanup on page unload
window.addEventListener('beforeunload', function() {
    if (heartbeatInterval) {
        clearInterval(heartbeatInterval);
    }
    if (sessionTimerInterval) {
        clearInterval(sessionTimerInterval);
    }
    if (connectionCheckInterval) {
        clearInterval(connectionCheckInterval);
    }
});

// Enhanced console warning for security
console.log('%cSTOP!', 'color: red; font-size: 50px; font-weight: bold;');
console.log('%cThis is a browser feature intended for developers. If someone told you to copy-paste something here to enable a feature or "hack" someone\'s account, it is a scam and will give them access to your account.', 'color: red; font-size: 16px;');

    </script>
</body>
</html>
