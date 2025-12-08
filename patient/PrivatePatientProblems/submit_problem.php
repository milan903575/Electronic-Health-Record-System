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
                'script-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://code.jquery.com'],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
                'font-src' => ["'self'", 'https://cdnjs.cloudflare.com'],
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
            'script-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://code.jquery.com'],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://cdn.jsdelivr.net', 'https://cdnjs.cloudflare.com'],
            'font-src' => ["'self'", 'https://cdnjs.cloudflare.com'],
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

require_once '../../connection.php';

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

// Enhanced session validation
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] != 'patient') {
    error_log("Unauthorized access attempt from IP: " . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
    session_destroy();
    header("Location: ../../login.php");
    exit;
}

// Session timeout check (10 minutes = 600 seconds)
$session_timeout = 600;
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $session_timeout) {
    session_destroy();
    header("Location: ../../login.php?timeout=1");
    exit;
}
$_SESSION['last_activity'] = time();

// Handle session extension request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'extend_session') {
    if (validateCSRFToken($_POST['csrf_token'])) {
        $_SESSION['last_activity'] = time();
        echo json_encode(['status' => 'success']);
        exit;
    }
}

// Input sanitization function
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Enhanced CSRF validation for AJAX requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
}

$patient_id = $_SESSION['user_id'];

// Retrieve the encryption key
$key_path = '../../../encryption_key.key';
$encryption_key = trim(file_get_contents($key_path));

if (!$encryption_key) {
    displayMessageAndRedirect("Encryption key is missing!", "submit_problem.php", false);
    exit;
}

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action'])) {
    $problem_description = $_POST['problem_description'];
    $doctor_id = $_POST['doctor_id'];

    if (!$doctor_id) {
        displayMessageAndRedirect("Invalid doctor selected. Please try again.", "submit_problem.php", false);
        exit;
    }

    $sql = "SELECT hospital_id FROM patient_hospital WHERE patient_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $hospital_id = $row['hospital_id'] ?? null;

    if (!$hospital_id) {
        displayMessageAndRedirect("Hospital not found for this patient.", "submit_problem.php", false);
        exit;
    }

    $sql = "SELECT id FROM doctors WHERE id = ? AND hospital_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $doctor_id, $hospital_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        displayMessageAndRedirect("Selected doctor is not associated with the patient's hospital.", "submit_problem.php", false);
        exit;
    }

    $iv_desc = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $tag_desc = '';
    $encrypted_description = openssl_encrypt(
        $problem_description,
        'aes-256-gcm',
        $encryption_key,
        0,
        $iv_desc,
        $tag_desc
    );

    if ($encrypted_description === false) {
        displayMessageAndRedirect("Encryption failed for problem description!", "submit_problem.php", false);
        exit;
    }

    $encrypted_video = null;
    $iv_video = null;
    $tag_video = null;

    if (isset($_FILES['video_upload']) && $_FILES['video_upload']['error'] === UPLOAD_ERR_OK) {
        if ($_FILES['video_upload']['size'] > 200 * 1024 * 1024) {
            displayMessageAndRedirect("File size exceeds the 200 MB limit.", "submit_problem.php", false);
            exit;
        }

        $video_tmp_path = $_FILES['video_upload']['tmp_name'];
        $video_data = file_get_contents($video_tmp_path);

        $iv_video = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $tag_video = '';
        $encrypted_video = openssl_encrypt(
            $video_data,
            'aes-256-gcm',
            $encryption_key,
            0,
            $iv_video,
            $tag_video
        );

        if ($encrypted_video === false) {
            displayMessageAndRedirect("Encryption failed for video file!", "submit_problem.php", false);
            exit;
        }
    }

    $query = "INSERT INTO private_problems 
              (patient_id, doctor_id, hospital_id, problem_description, iv, auth_tag, video_file, video_iv, video_auth_tag) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($query);

    $stmt->bind_param(
        'iiissssss',
        $patient_id,
        $doctor_id,
        $hospital_id,
        $encrypted_description,
        $iv_desc,
        $tag_desc,
        $encrypted_video,
        $iv_video,
        $tag_video
    );

    if ($encrypted_video !== null) {
        $stmt->send_long_data(6, $encrypted_video);
    }

    if ($stmt->execute()) {
        displayMessageAndRedirect("Problem submitted securely.", "../patient_homepage.php", true);
    } else {
        displayMessageAndRedirect("Database error: " . $stmt->error, "submit_problem.php", false);
    }

    $stmt->close();
}

// Enhanced doctor search logic with CSRF protection
if (isset($_GET['query']) && isset($_GET['csrf_token']) && validateCSRFToken($_GET['csrf_token'])) {
    $query = sanitizeInput($_GET['query']);
    
    if (strlen($query) < 2) {
        echo "<div style='padding:10px;'>Please enter at least 2 characters.</div>";
        exit;
    }
    
    $sql = "
        SELECT 
            d.id AS doctor_id,
            d.first_name,
            d.last_name,
            d.specialization,
            h.id AS hospital_id,
            h.hospital_name,
            h.city,
            h.registration_fee,
            ph.registration_status
        FROM doctors d
        INNER JOIN hospitals h ON d.hospital_id = h.id
        LEFT JOIN patient_hospital ph ON h.id = ph.hospital_id AND ph.patient_id = ?
        WHERE 
            CONCAT(d.first_name, ' ', d.last_name) LIKE ? 
            OR d.specialization LIKE ?
        LIMIT 10";

    $stmt = $conn->prepare($sql);
    if (!$stmt) {
        error_log("Database prepare error: " . $conn->error);
        die("Database error occurred");
    }
    
    $search_query = "%" . $query . "%";
    $stmt->bind_param("iss", $patient_id, $search_query, $search_query);
    $stmt->execute();
    $result = $stmt->get_result();

    $output = '';
    while ($row = $result->fetch_assoc()) {
        $output .= '
            <div class="doctor-option" 
                 data-id="' . intval($row['doctor_id']) . '" 
                 data-hospital-id="' . intval($row['hospital_id']) . '" 
                 data-registration-fee="' . floatval($row['registration_fee']) . '" 
                 data-registration-status="' . htmlspecialchars($row['registration_status'], ENT_QUOTES, 'UTF-8') . '">
                <div class="doctor-name">Dr. ' . htmlspecialchars($row['first_name'], ENT_QUOTES, 'UTF-8') . ' ' . htmlspecialchars($row['last_name'], ENT_QUOTES, 'UTF-8') . '</div>
                <div class="doctor-details">' . htmlspecialchars($row['specialization'], ENT_QUOTES, 'UTF-8') . ' | ' . htmlspecialchars($row['hospital_name'], ENT_QUOTES, 'UTF-8') . ', ' . htmlspecialchars($row['city'], ENT_QUOTES, 'UTF-8') . '</div>
            </div>';
    }

    echo $output ?: "<div style='padding:10px;'>No matching doctors found.</div>";
    $stmt->close();
    $conn->close();
    exit;
}

// Function to display a message and redirect with a countdown
function displayMessageAndRedirect($message, $redirect_url, $success) {
    echo "
        <div style='
            display: flex; 
            justify-content: center; 
            align-items: center; 
            height: 100vh; 
            text-align: center; 
            font-family: Arial, sans-serif;'>
            <div>
                <h2>" . htmlspecialchars($message) . "</h2>
                <p>Redirecting in <span id='countdown'>3</span> seconds...</p>
            </div>
        </div>
        <script>
            let countdown = 3;
            const interval = setInterval(() => {
                countdown--;
                document.getElementById('countdown').textContent = countdown;
                if (countdown <= 0) {
                    clearInterval(interval);
                    window.location.href = '" . $redirect_url . "';
                }
            }, 1000);
        </script>
    ";
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrf_token) ?>">
    <title>Submit Medical Consultation</title>
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
        }
        
        .main-container {
            max-width: 900px;
            margin: 40px auto;
            padding: 0 20px;
        }
        
        .card {
            border: none;
            border-radius: 15px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            overflow: hidden;
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
        
        .form-label {
            font-weight: 600;
            margin-bottom: 8px;
            color: var(--dark-color);
        }
        
        .form-control {
            padding: 12px 15px;
            border-radius: 8px;
            border: 1px solid #ced4da;
            transition: all 0.3s;
        }
        
        .form-control:focus {
            border-color: var(--secondary-color);
            box-shadow: 0 0 0 0.2rem rgba(52, 152, 219, 0.25);
        }
        
        .btn-primary {
            background-color: var(--secondary-color);
            border: none;
            padding: 12px 25px;
            font-weight: 600;
            border-radius: 8px;
            transition: all 0.3s;
        }
        
        .btn-primary:hover {
            background-color: #2980b9;
            transform: translateY(-2px);
        }
        
        .btn-primary:disabled {
            background-color: #95a5a6;
            cursor: not-allowed;
        }
        
        .input-wrapper {
            position: relative;
            margin-bottom: 20px;
        }
        
        .autocomplete-suggestions {
            position: absolute;
            background: white;
            border: 1px solid #ddd;
            border-radius: 0 0 8px 8px;
            max-height: 250px;
            overflow-y: auto;
            z-index: 1000;
            top: 100%;
            left: 0;
            width: 100%;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }
        
        .doctor-option {
            padding: 12px 15px;
            cursor: pointer;
            border-bottom: 1px solid #eee;
            transition: all 0.2s;
        }
        
        .doctor-option:last-child {
            border-bottom: none;
        }
        
        .doctor-option:hover {
            background: #f8f9fa;
        }
        
        .doctor-name {
            font-weight: 600;
            color: var(--primary-color);
        }
        
        .doctor-details {
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        #registration_message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .message-success {
            background-color: rgba(46, 204, 113, 0.1);
            border: 1px solid var(--success-color);
            color: var(--success-color);
        }
        
        .message-error {
            background-color: rgba(231, 76, 60, 0.1);
            border: 1px solid var(--danger-color);
            color: var(--danger-color);
        }
        
        .file-upload {
            position: relative;
            display: inline-block;
            width: 100%;
        }
        
        .file-upload-label {
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 15px;
            background-color: #f8f9fa;
            border: 2px dashed #ced4da;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .file-upload-label:hover {
            border-color: var(--secondary-color);
        }
        
        .file-upload-icon {
            margin-right: 10px;
            color: var(--secondary-color);
        }
        
        .file-upload input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }
        
        .file-name {
            margin-top: 8px;
            font-size: 0.9rem;
            color: #7f8c8d;
        }
        
        .security-notice {
            background-color: rgba(231, 76, 60, 0.1);
            border: 1px solid var(--danger-color);
            color: var(--danger-color);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }
        
        .session-timer {
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--warning-color);
            color: white;
            padding: 10px 15px;
            border-radius: 8px;
            font-weight: 600;
            z-index: 9999;
            display: none;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.2);
        }
        
        .session-timer.warning {
            background: var(--danger-color);
            animation: pulse 1s infinite;
        }
        
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }
        
        @media (max-width: 768px) {
            .main-container {
                margin: 20px auto;
            }
            
            .card-body {
                padding: 20px;
            }
            
            .session-timer {
                top: 10px;
                right: 10px;
                font-size: 0.9rem;
            }
        }
    </style>
</head>
<body>
    <!-- Hidden CSRF token for JavaScript -->
    <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
    
    <!-- Session Timer -->
    <div id="session-timer" class="session-timer">
        <i class="fas fa-clock me-2"></i>
        <span id="timer-text">Session expires in: </span>
        <span id="timer-countdown">10:00</span>
    </div>
    
    <div class="main-container">
        <div class="security-notice">
            <i class="fas fa-shield-alt me-2"></i>
            <strong>SECURE MEDICAL PORTAL</strong> - This form contains sensitive medical information. All data is encrypted and protected. For your security, you will be automatically logged out after 10 minutes of inactivity.
        </div>
        
        <div class="card">
            <div class="card-header">
                <h2 class="mb-0"><i class="fas fa-notes-medical me-2"></i>Submit Medical Consultation</h2>
            </div>
            <div class="card-body">
                <form action="submit_problem.php" method="POST" enctype="multipart/form-data">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
                    
                    <div class="mb-4">
                        <label for="doctor_name" class="form-label">Search for a Doctor</label>
                        <div class="input-wrapper">
                            <div class="input-group">
                                <span class="input-group-text"><i class="fas fa-user-md"></i></span>
                                <input type="text" class="form-control" id="doctor_name" name="doctor_name" 
                                    placeholder="Enter doctor's name or specialization" autocomplete="off" required>
                            </div>
                            <input type="hidden" id="doctor_id" name="doctor_id">
                            <input type="hidden" id="hospital_id" name="hospital_id">
                            <div id="doctor_suggestions" class="autocomplete-suggestions"></div>
                        </div>
                    </div>
                    
                    <div id="registration_message" style="display: none;"></div>
                    
                    <div class="mb-4">
                        <label for="problem_description" class="form-label">Describe Your Medical Concern</label>
                        <textarea class="form-control" name="problem_description" id="problem_description" 
                            rows="5" placeholder="Please provide details about your symptoms and concerns" required></textarea>
                    </div>
                    
                    <div class="mb-4">
                        <label class="form-label">Upload Video (Optional)</label>
                        <div class="file-upload">
                            <label for="video_upload" class="file-upload-label">
                                <i class="fas fa-video file-upload-icon"></i>
                                <span id="file-text">Drag and drop a video or click to browse</span>
                            </label>
                            <input type="file" name="video_upload" id="video_upload" accept="video/*">
                            <div id="file-name" class="file-name"></div>
                        </div>
                        <small class="text-muted">Max file size: 200MB. Allowed formats: MP4, AVI, MOV, WMV</small>
                    </div>
                    
                    <div class="d-grid gap-2">
                        <button type="submit" id="submit_button" class="btn btn-primary">
                            <i class="fas fa-paper-plane me-2"></i>Submit Consultation
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        $(document).ready(function () {
            // Get CSRF token
            const csrfToken = document.getElementById('csrf_token').value;
            
            // Enhanced security measures
            
            // 1. Disable right-click context menu
            $(document).on('contextmenu', function(e) {
                e.preventDefault();
                return false;
            });
            
            // 2. Disable text selection
            $(document).on('selectstart', function(e) {
                e.preventDefault();
                return false;
            });
            
            // 3. Disable drag and drop
            $(document).on('dragstart', function(e) {
                e.preventDefault();
                return false;
            });
            
            // 4. Disable keyboard shortcuts
            $(document).keydown(function(e) {
                // Disable F12 (Developer Tools)
                if (e.keyCode == 123) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+Shift+I (Developer Tools)
                if (e.ctrlKey && e.shiftKey && e.keyCode == 73) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+Shift+J (Console)
                if (e.ctrlKey && e.shiftKey && e.keyCode == 74) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+U (View Source)
                if (e.ctrlKey && e.keyCode == 85) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+S (Save Page)
                if (e.ctrlKey && e.keyCode == 83) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+A (Select All)
                if (e.ctrlKey && e.keyCode == 65) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+C (Copy)
                if (e.ctrlKey && e.keyCode == 67) {
                    e.preventDefault();
                    return false;
                }
                
                // Disable Ctrl+P (Print)
                if (e.ctrlKey && e.keyCode == 80) {
                    e.preventDefault();
                    return false;
                }
            });
            
            // Session timeout management with live counter (10 minutes = 600 seconds)
            let sessionTimeLeft = 600;
            let sessionWarningShown = false;
            
            function updateSessionTimer() {
                const minutes = Math.floor(sessionTimeLeft / 60);
                const seconds = sessionTimeLeft % 60;
                const timeString = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                
                $('#timer-countdown').text(timeString);
                
                // Show timer when 2 minutes left
                if (sessionTimeLeft <= 120 && !$('#session-timer').is(':visible')) {
                    $('#session-timer').show();
                }
                
                // Warning at 1 minute
                if (sessionTimeLeft <= 60) {
                    $('#session-timer').addClass('warning');
                    $('#timer-text').text('LOGGING OUT IN: ');
                    
                    if (!sessionWarningShown) {
                        sessionWarningShown = true;
                        if (confirm('Your session will expire in 1 minute due to inactivity. We will log you out to maintain security. Click OK to continue working and reset the timer.')) {
                            extendSession();
                        }
                    }
                }
                
                // Auto logout
                if (sessionTimeLeft <= 0) {
                    alert('Session expired due to inactivity. You will be redirected to login for security.');
                    window.location.href = '../../login.php?timeout=1';
                    return;
                }
                
                sessionTimeLeft--;
            }
            
            function extendSession() {
                $.ajax({
                    url: window.location.href,
                    type: 'POST',
                    data: {
                        action: 'extend_session',
                        csrf_token: csrfToken
                    },
                    success: function(response) {
                        sessionTimeLeft = 600; // Reset to 10 minutes
                        sessionWarningShown = false;
                        $('#session-timer').removeClass('warning').hide();
                        $('#timer-text').text('Session expires in: ');
                    },
                    error: function() {
                        console.log('Failed to extend session');
                    }
                });
            }
            
            // Start session timer
            const sessionTimer = setInterval(updateSessionTimer, 1000);
            
            // Reset timer on user interaction
            $(document).on('click keypress mousemove', function() {
                if (sessionTimeLeft < 540) { // Only extend if less than 9 minutes left
                    extendSession();
                }
            });
            
            // Enhanced doctor search functionality with CSRF protection
            $('#doctor_name').on('input', function () {
                const query = $(this).val();
                
                if (query.length > 2) {
                    $.ajax({
                        url: '', // Current PHP file
                        type: 'GET',
                        data: { 
                            query: query,
                            csrf_token: csrfToken
                        },
                        success: function (response) {
                            $('#doctor_suggestions').html(response).show();
                            $('.doctor-option').click(function () {
                                const doctor_id = $(this).data('id');
                                const hospital_id = $(this).data('hospital-id');
                                const registration_fee = $(this).data('registration-fee');
                                const registration_status = $(this).data('registration-status');

                                $('#doctor_name').val($(this).text().trim());
                                $('#doctor_id').val(doctor_id);
                                $('#hospital_id').val(hospital_id);
                                $('#doctor_suggestions').hide();

                                // Show appropriate registration message
                                $('#registration_message').show();
                                
                                if (!registration_status) {
                                    $('#registration_message')
                                        .html('<i class="fas fa-exclamation-triangle me-2"></i>You are not registered with this hospital. Please register on the login page.')
                                        .removeClass('message-success')
                                        .addClass('message-error');
                                    $('#submit_button').prop('disabled', true);
                                } else if (registration_fee > 0) {
                                    $('#registration_message')
                                        .html('<i class="fas fa-exclamation-circle me-2"></i>This hospital requires a registration fee: $' + registration_fee + '. Please complete your payment in the hospital list on your home page.')
                                        .removeClass('message-success')
                                        .addClass('message-error');
                                    $('#submit_button').prop('disabled', true);
                                } else {
                                    $('#registration_message')
                                        .html('<i class="fas fa-check-circle me-2"></i>Your registration is complete with this hospital. You can submit your consultation.')
                                        .removeClass('message-error')
                                        .addClass('message-success');
                                    $('#submit_button').prop('disabled', false);
                                }
                            });
                        },
                        error: function() {
                            $('#doctor_suggestions').html('<div style="padding:10px;">Error retrieving doctors</div>').show();
                        }
                    });
                } else {
                    $('#doctor_suggestions').hide();
                }
            });
            
            // Enhanced file upload preview with validation
            $('#video_upload').change(function() {
                const file = this.files[0];
                if (file) {
                    // Validate file size (200MB max)
                    const maxSize = 200 * 1024 * 1024; // 200MB in bytes
                    if (file.size > maxSize) {
                        alert('File size exceeds 200MB limit. Please choose a smaller file.');
                        this.value = '';
                        $('#file-text').text('Drag and drop a video or click to browse');
                        $('#file-name').text('');
                        return;
                    }
                    
                    // Validate file type
                    const allowedTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/wmv'];
                    if (!allowedTypes.includes(file.type)) {
                        alert('Invalid file type. Please upload MP4, AVI, MOV, or WMV files only.');
                        this.value = '';
                        $('#file-text').text('Drag and drop a video or click to browse');
                        $('#file-name').text('');
                        return;
                    }
                    
                    $('#file-text').text('Video selected');
                    $('#file-name').text(file.name);
                } else {
                    $('#file-text').text('Drag and drop a video or click to browse');
                    $('#file-name').text('');
                }
            });
            
            // Close suggestions when clicking outside
            $(document).on('click', function(e) {
                if (!$(e.target).closest('.input-wrapper').length) {
                    $('#doctor_suggestions').hide();
                }
            });
            
            // Form validation before submit
            $('form').on('submit', function(e) {
                const doctorId = $('#doctor_id').val();
                const problemDescription = $('#problem_description').val().trim();
                
                if (!doctorId) {
                    e.preventDefault();
                    alert('Please select a doctor from the search results.');
                    return false;
                }
                
                if (problemDescription.length < 10) {
                    e.preventDefault();
                    alert('Please provide a more detailed description of your medical concern (at least 10 characters).');
                    return false;
                }
                
                // Disable submit button to prevent double submission
                $('#submit_button').prop('disabled', true).html('<i class="fas fa-spinner fa-spin me-2"></i>Submitting...');
            });
            
            // Monitor for developer tools
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
                        console.log('Developer tools detected - security logged');
                    }
                } else {
                    devtools.open = false;
                }
            }, 500);
            
            // Disable zoom
            $(document).on('wheel', function(e) {
                if (e.ctrlKey) {
                    e.preventDefault();
                    return false;
                }
            });
            
            // Monitor for window blur (potential screenshot tools)
            $(window).on('blur', function() {
                console.log('Window lost focus - potential screenshot attempt logged');
            });
        });
    </script>
</body>
</html>
