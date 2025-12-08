<?php
// CRITICAL: Handle video streaming FIRST before any other output
if (isset($_GET['stream'])) {
    // Clear any output buffers
    while (ob_get_level()) {
        ob_end_clean();
    }
    
    session_start();
    include '../connection.php';
    
    // Validate history_id for streaming
    $stream_history_id = filter_var($_GET['history_id'], FILTER_VALIDATE_INT);
    if (!$stream_history_id) {
        http_response_code(400);
        exit("Invalid history ID for streaming.");
    }
    
    // Load encryption key
    $key_path = '../../encryption_key.key';
    if (!file_exists($key_path) || !is_readable($key_path)) {
        http_response_code(500);
        exit("Encryption key not accessible!");
    }
    
    $encryption_key = trim(file_get_contents($key_path));
    if (!$encryption_key || strlen($encryption_key) < 32) {
        http_response_code(500);
        exit("Invalid encryption key!");
    }
    
    // Get video details
    $sql_video = "SELECT video_file, video_iv, video_auth_tag FROM patient_history WHERE id = ? LIMIT 1";
    $stmt_video = $conn->prepare($sql_video);
    if (!$stmt_video) {
        http_response_code(500);
        exit("Database error occurred");
    }
    
    $stmt_video->bind_param("i", $stream_history_id);
    $stmt_video->execute();
    $result_video = $stmt_video->get_result();
    
    if ($result_video->num_rows === 0) {
        $stmt_video->close();
        http_response_code(404);
        exit("Video not found.");
    }

    $video_details = $result_video->fetch_assoc();
    $stmt_video->close();
    
    $video_path = $video_details['video_file'];
    $video_iv = $video_details['video_iv'];
    $video_auth_tag = $video_details['video_auth_tag'];

    // Validate video data
    if (empty($video_path) || empty($video_iv) || empty($video_auth_tag)) {
        http_response_code(404);
        exit("Video data incomplete.");
    }

    // Check if video file exists
    if (!file_exists($video_path) || !is_readable($video_path)) {
        http_response_code(404);
        exit("Video file not accessible.");
    }
    
    // Read encrypted video file
    $encrypted_video = file_get_contents($video_path);
    if ($encrypted_video === false) {
        http_response_code(500);
        exit("Failed to read video file.");
    }
    
    // OPTIMIZED SINGLE DECRYPTION METHOD
    $cipher = 'aes-256-gcm';
    $ivlen = openssl_cipher_iv_length($cipher);
    
    // Handle IV format
    $decodedIv = (strlen($video_iv) === $ivlen) ? $video_iv : base64_decode($video_iv, true);
    if ($decodedIv === false || strlen($decodedIv) !== $ivlen) {
        $decodedIv = hex2bin($video_iv);
        if ($decodedIv === false || strlen($decodedIv) !== $ivlen) {
            http_response_code(500);
            exit("Invalid IV format.");
        }
    }
    
    // Handle authentication tag format
    $decodedTag = (strlen($video_auth_tag) === 16) ? $video_auth_tag : base64_decode($video_auth_tag, true);
    if ($decodedTag === false || strlen($decodedTag) !== 16) {
        $decodedTag = hex2bin($video_auth_tag);
        if ($decodedTag === false || strlen($decodedTag) !== 16) {
            http_response_code(500);
            exit("Invalid authentication tag format.");
        }
    }
    
    // Single optimized decryption method
    $dataToDecrypt = base64_decode($encrypted_video, true);
    if ($dataToDecrypt === false) {
        $dataToDecrypt = $encrypted_video;
    }
    
    $decrypted_video = openssl_decrypt(
        $dataToDecrypt,
        $cipher,
        $encryption_key,
        OPENSSL_RAW_DATA,
        $decodedIv,
        $decodedTag
    );
    
    if ($decrypted_video === false) {
        http_response_code(500);
        exit("Failed to decrypt the video.");
    }

    // Close database connection
    $conn->close();
    
    // Stream the video with proper headers
    $filesize = strlen($decrypted_video);
    $start = 0;
    $end = $filesize - 1;
    
    // Clear any previous headers
    header_remove();
    
    // Handle range requests for video seeking
    if (isset($_SERVER['HTTP_RANGE'])) {
        if (preg_match('/bytes=(\d+)-(\d*)/', $_SERVER['HTTP_RANGE'], $matches)) {
            $start = intval($matches[1]);
            $end = !empty($matches[2]) ? intval($matches[2]) : $filesize - 1;
        }
        
        // Validate range
        if ($start > $end || $start >= $filesize || $end >= $filesize) {
            http_response_code(416);
            header("Content-Range: bytes */$filesize");
            exit;
        }
        
        $length = $end - $start + 1;
        
        // Send partial content
        http_response_code(206);
        header('Content-Type: video/mp4');
        header('Accept-Ranges: bytes');
        header("Content-Range: bytes $start-$end/$filesize");
        header("Content-Length: $length");
        header('Cache-Control: public, max-age=3600');
        
        echo substr($decrypted_video, $start, $length);
    } else {
        // Send full content
        http_response_code(200);
        header('Content-Type: video/mp4');
        header('Accept-Ranges: bytes');
        header("Content-Length: $filesize");
        header('Cache-Control: public, max-age=3600');
        
        echo $decrypted_video;
    }
    
    exit; // CRITICAL: Must exit here
}

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
                'script-src' => ["'self'", "'unsafe-inline'"],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
                'font-src' => ["'self'", 'https://fonts.gstatic.com'],
                'img-src' => ["'self'", 'data:'],
                'connect-src' => ["'self'"],
                'media-src' => ["'self'", 'blob:'],
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

// Initialize and send security headers for main page
$securityHeaders = new SecurityHeadersManager([
    'csp' => [
        'enabled' => true,
        'directives' => [
            'default-src' => ["'self'"],
            'script-src' => ["'self'", "'unsafe-inline'"],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
            'font-src' => ["'self'", 'https://fonts.gstatic.com'],
            'img-src' => ["'self'", 'data:'],
            'connect-src' => ["'self'"],
            'media-src' => ["'self'", 'blob:'],
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

// CSRF Validation
if (!isset($_SESSION['csrf_token'])) {
    die("Security token missing. Please login again.");
}

if (!isset($_GET['history_id'])) {
    die("Invalid request.");
}

// Sanitize and validate history_id
$history_id = filter_var($_GET['history_id'], FILTER_VALIDATE_INT);
if (!$history_id) {
    die("Invalid history ID.");
}

// Enhanced encryption key handling with security validation
$key_path = '../../encryption_key.key';

// Validate path is within allowed directory
$real_key_path = realpath($key_path);
$allowed_base = realpath('../../');

if (!$real_key_path || !$allowed_base || strpos($real_key_path, $allowed_base) !== 0) {
    error_log("Invalid encryption key path access attempt");
    die("Security error: Invalid key path");
}

if (!file_exists($real_key_path) || !is_readable($real_key_path)) {
    error_log("Encryption key file not accessible");
    die("Encryption key is missing or not accessible!");
}

$encryption_key = trim(file_get_contents($real_key_path));

if (!$encryption_key || strlen($encryption_key) < 32) {
    error_log("Invalid encryption key format");
    die("Invalid encryption key!");
}

// OPTIMIZED SINGLE DECRYPTION FUNCTION
function decryptData($encryptedData, $iv, $tag, $encryptionKey) {
    if (empty($encryptedData) || empty($iv) || empty($tag) || empty($encryptionKey)) {
        return false;
    }
    
    $cipher = 'aes-256-gcm';
    $ivlen = openssl_cipher_iv_length($cipher);
    
    // Handle IV format - optimized single method
    $decodedIv = (strlen($iv) === $ivlen) ? $iv : base64_decode($iv, true);
    if ($decodedIv === false || strlen($decodedIv) !== $ivlen) {
        $decodedIv = hex2bin($iv);
        if ($decodedIv === false || strlen($decodedIv) !== $ivlen) {
            return false;
        }
    }
    
    // Handle authentication tag format - optimized single method
    $decodedTag = (strlen($tag) === 16) ? $tag : base64_decode($tag, true);
    if ($decodedTag === false || strlen($decodedTag) !== 16) {
        $decodedTag = hex2bin($tag);
        if ($decodedTag === false || strlen($decodedTag) !== 16) {
            return false;
        }
    }
    
    // Single optimized decryption approach
    $dataToDecrypt = base64_decode($encryptedData, true);
    if ($dataToDecrypt === false) {
        $dataToDecrypt = $encryptedData;
    }
    
    return openssl_decrypt(
        $dataToDecrypt,
        $cipher,
        $encryptionKey,
        OPENSSL_RAW_DATA,
        $decodedIv,
        $decodedTag
    );
}

// Fetch patient history details with enhanced security
$sql_detail = "
    SELECT ph.problem, ph.problem_description, ph.problem_iv, ph.problem_auth_tag,
           ph.current_medication, ph.medication_iv, ph.medication_auth_tag,
           ph.doctor_solution, ph.solution_iv, ph.solution_tag,
           ph.date_submitted AS date,
           d.id AS doctor_id, d.first_name AS doctor_first_name, d.last_name AS doctor_last_name,
           d.profile_picture, d.specialization,
           h.hospital_name AS hospital,
           ph.video_file
    FROM patient_history ph
    LEFT JOIN doctors d ON ph.doctor_id = d.id
    LEFT JOIN hospitals h ON ph.hospital_id = h.id
    WHERE ph.id = ? LIMIT 1
";

$stmt_detail = $conn->prepare($sql_detail);
if (!$stmt_detail) {
    error_log("Database prepare error: " . $conn->error);
    die("Database error occurred");
}

$stmt_detail->bind_param("i", $history_id);
$stmt_detail->execute();
$result_detail = $stmt_detail->get_result();

if ($result_detail->num_rows === 0) {
    die("No details found.");
}

$details = $result_detail->fetch_assoc();
$stmt_detail->close();

// Get doctor ratings with prepared statement
$doctor_id = filter_var($details['doctor_id'], FILTER_VALIDATE_INT);
$average_rating = 0;
$rating_count = 0;

if ($doctor_id) {
    $sql_ratings = "SELECT AVG(rating) as average_rating, COUNT(rating) as rating_count FROM ratings WHERE doctor_id = ?";
    $stmt_ratings = $conn->prepare($sql_ratings);
    
    if ($stmt_ratings) {
        $stmt_ratings->bind_param("i", $doctor_id);
        $stmt_ratings->execute();
        $ratings_result = $stmt_ratings->get_result();
        $ratings_data = $ratings_result->fetch_assoc();
        $stmt_ratings->close();
        
        $average_rating = round($ratings_data['average_rating'] ?? 0, 1);
        $rating_count = $ratings_data['rating_count'] ?? 0;
    }
}

// Decrypt the data using the optimized function
$decrypted_problem_description = decryptData(
    $details['problem_description'], 
    $details['problem_iv'], 
    $details['problem_auth_tag'], 
    $encryption_key
);

$decrypted_current_medication = decryptData(
    $details['current_medication'], 
    $details['medication_iv'], 
    $details['medication_auth_tag'], 
    $encryption_key
);

$decrypted_doctor_solution = decryptData(
    $details['doctor_solution'], 
    $details['solution_iv'], 
    $details['solution_tag'], 
    $encryption_key
);

// Handle decryption failures gracefully with sanitization
if ($decrypted_problem_description === false) {
    $decrypted_problem_description = "Unable to decrypt problem description";
} else {
    $decrypted_problem_description = htmlspecialchars($decrypted_problem_description, ENT_QUOTES, 'UTF-8');
}

if ($decrypted_current_medication === false) {
    $decrypted_current_medication = "Unable to decrypt medication information";
} else {
    $decrypted_current_medication = htmlspecialchars($decrypted_current_medication, ENT_QUOTES, 'UTF-8');
}

if ($decrypted_doctor_solution === false) {
    $decrypted_doctor_solution = "Unable to decrypt doctor solution or your problem is pending";
} else {
    $decrypted_doctor_solution = htmlspecialchars($decrypted_doctor_solution, ENT_QUOTES, 'UTF-8');
}

// Check if doctor solution is in progress
$is_solution_in_progress = empty($decrypted_doctor_solution) || 
                          $decrypted_doctor_solution == "Your problem statement is in progress" ||
                          $decrypted_doctor_solution == "Unable to decrypt doctor solution or problem status is pending";

// Fetch medications with enhanced security
$sql_medications = "
    SELECT medication_name, dosage, start_date, end_date, medication_type,
           morning_time, afternoon_time, evening_time, night_time, additional_instructions
    FROM medication_alerts
    WHERE patient_history_id = ?
";

$stmt_medications = $conn->prepare($sql_medications);
$medications = [];

if ($stmt_medications) {
    $stmt_medications->bind_param("i", $history_id);
    $stmt_medications->execute();
    $result_medications = $stmt_medications->get_result();

    while ($row = $result_medications->fetch_assoc()) {
        // Sanitize all medication data
        $medications[] = [
            'medication_name' => htmlspecialchars($row['medication_name'], ENT_QUOTES, 'UTF-8'),
            'dosage' => htmlspecialchars($row['dosage'], ENT_QUOTES, 'UTF-8'),
            'start_date' => htmlspecialchars($row['start_date'], ENT_QUOTES, 'UTF-8'),
            'end_date' => htmlspecialchars($row['end_date'], ENT_QUOTES, 'UTF-8'),
            'medication_type' => htmlspecialchars($row['medication_type'], ENT_QUOTES, 'UTF-8'),
            'morning_time' => htmlspecialchars($row['morning_time'], ENT_QUOTES, 'UTF-8'),
            'afternoon_time' => htmlspecialchars($row['afternoon_time'], ENT_QUOTES, 'UTF-8'),
            'evening_time' => htmlspecialchars($row['evening_time'], ENT_QUOTES, 'UTF-8'),
            'night_time' => htmlspecialchars($row['night_time'], ENT_QUOTES, 'UTF-8'),
            'additional_instructions' => htmlspecialchars($row['additional_instructions'], ENT_QUOTES, 'UTF-8')
        ];
    }
    $stmt_medications->close();
}

// Convert BLOB profile picture to base64 with validation
$profile_picture_src = '';
if (!empty($details['profile_picture'])) {
    $profile_picture_base64 = base64_encode($details['profile_picture']);
    if ($profile_picture_base64) {
        $profile_picture_src = 'data:image/jpeg;base64,' . $profile_picture_base64;
    } else {
        $profile_picture_src = 'default-profile.jpg';
    }
} else {
    $profile_picture_src = 'default-profile.jpg';
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars($csrf_token) ?>">
    <title>Patient History Detail</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #4361ee;
            --primary-light: #edf2ff;
            --primary-dark: #3a56d4;
            --secondary-color: #7209b7;
            --secondary-light: #f3e8ff;
            --accent-color: #f72585;
            --star-color: #ffb700;
            --star-inactive: #e2e8f0;
            --text-primary: #1e293b;
            --text-secondary: #64748b;
            --text-tertiary: #94a3b8;
            --bg-primary: #f8fafc;
            --bg-secondary: #ffffff;
            --bg-tertiary: #f1f5f9;
            --shadow-sm: 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.05), 0 2px 4px rgba(0,0,0,0.03);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.03), 0 4px 6px rgba(0,0,0,0.02);
            --shadow-xl: 0 20px 25px rgba(0,0,0,0.03), 0 8px 10px rgba(0,0,0,0.02);
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 24px;
            --transition: all 0.3s ease;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #f8fafc, #e2e8f0);
            margin: 0;
            padding: 0;
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 40px auto;
            background: var(--bg-secondary);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-xl);
            padding: 0;
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
            color: white;
            padding: 25px 40px;
            position: relative;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
        }

        .header-content {
            flex: 1;
        }

        .header h1 {
            font-size: 24px;
            font-weight: 600;
            margin: 0;
        }

        .header p {
            margin: 5px 0 0;
            opacity: 0.9;
            font-size: 14px;
        }

        .header-timers {
            display: flex;
            align-items: center;
            gap: 20px;
            flex-wrap: wrap;
        }

        .session-timer {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            padding: 12px 16px;
            border-radius: 25px;
            display: flex;
            align-items: center;
            gap: 8px;
            font-size: 14px;
            font-weight: 500;
            color: white;
            border: 1px solid rgba(255, 255, 255, 0.2);
            transition: var(--transition);
            min-width: 140px;
        }

        .session-timer:hover {
            transform: translateY(-2px);
            background: rgba(255, 255, 255, 0.2);
        }

        .session-timer svg {
            width: 18px;
            height: 18px;
            color: white;
        }

        .session-timer.idle {
            background: rgba(255, 193, 7, 0.9);
            color: #856404;
            animation: pulse 2s infinite;
        }

        .session-timer.countdown {
            background: rgba(220, 53, 69, 0.9);
            color: white;
            animation: pulse 1s infinite;
        }

        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.05); }
            100% { transform: scale(1); }
        }

        .date-badge {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            padding: 8px 15px;
            border-radius: 20px;
            font-size: 13px;
            color: white;
            display: flex;
            align-items: center;
            gap: 6px;
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .date-badge svg {
            width: 16px;
            height: 16px;
        }

        .main-card {
            display: flex;
            gap: 30px;
            flex-wrap: wrap;
            padding: 30px 40px 40px;
        }

        .left-card {
            flex: 25%;
            display: flex;
            flex-direction: column;
            align-items: center;
            background: var(--bg-secondary);
            padding: 30px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            position: relative;
            border: 1px solid rgba(0,0,0,0.05);
            transition: var(--transition);
        }

        .left-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }

        .left-card img {
            width: 140px;
            height: 140px;
            border-radius: 50%;
            object-fit: cover;
            border: 4px solid white;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            transition: var(--transition);
        }

        .left-card img:hover {
            transform: scale(1.05);
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
        }

        .doctor-name {
            margin-top: 24px;
            margin-bottom: 10px;
            font-weight: 600;
            color: var(--text-primary);
            font-size: 20px;
            text-align: center;
        }

        .specialization {
            display: inline-block;
            background: var(--primary-light);
            color: var(--primary-dark);
            padding: 8px 16px;
            border-radius: 30px;
            font-size: 14px;
            font-weight: 500;
            margin-top: 12px;
            transition: var(--transition);
        }

        .specialization:hover {
            background: var(--primary-color);
            color: white;
            transform: translateY(-2px);
        }

        .right-card {
            flex: 70%;
        }

        .hospital-name {
            display: flex;
            align-items: center;
            font-size: 18px;
            color: var(--text-secondary);
            margin-bottom: 25px;
            padding-bottom: 15px;
            border-bottom: 1px solid #e2e8f0;
        }

        .hospital-name svg {
            margin-right: 12px;
            color: var(--primary-color);
        }

        .grid-container {
            display: grid;
            grid-template-columns: 30% 70%;
            gap: 24px;
            margin-bottom: 30px;
        }

        .info-box {
            background: var(--bg-secondary);
            padding: 25px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(0,0,0,0.05);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
            margin-bottom: 20px;
        }

        .info-box::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--primary-color);
            opacity: 0.7;
        }

        .info-box:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }

        .info-box h3 {
            margin-top: 0;
            color: var(--text-primary);
            font-size: 18px;
            font-weight: 600;
            display: flex;
            align-items: center;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid #e2e8f0;
        }

        .info-box h3 svg {
            margin-right: 12px;
            color: var(--primary-color);
        }

        .info-box p {
            color: var(--text-secondary);
            line-height: 1.7;
            font-size: 15px;
        }

        .video-container {
            background: var(--bg-secondary);
            padding: 25px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(0,0,0,0.05);
            transition: var(--transition);
            height: 100%;
        }

        .video-container:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }

        .video-wrapper {
            position: relative;
            width: 100%;
            height: 300px;
            border-radius: var(--radius-sm);
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
        }

        .video-container video {
            width: 100%;
            height: 100%;
            border-radius: var(--radius-sm);
            background: var(--bg-tertiary);
            object-fit: cover;
        }

        .no-video {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            background: var(--bg-tertiary);
            border-radius: var(--radius-md);
            padding: 40px;
            text-align: center;
            height: 300px;
        }

        .no-video svg {
            opacity: 0.5;
            margin-bottom: 15px;
        }

        .no-video p {
            margin-top: 15px;
            color: var(--text-tertiary);
            font-size: 16px;
        }

        .section-title {
            margin-top: 40px;
            margin-bottom: 25px;
            color: var(--text-primary);
            font-weight: 600;
            font-size: 20px;
            display: flex;
            align-items: center;
            position: relative;
            padding-bottom: 10px;
        }

        .section-title::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 0;
            width: 60px;
            height: 3px;
            background: var(--primary-color);
            border-radius: 3px;
        }

        .section-title svg {
            margin-right: 12px;
            color: var(--primary-color);
        }

        .medications-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
            gap: 24px;
            margin-bottom: 40px;
        }

        .medication-card {
            background: var(--bg-secondary);
            padding: 25px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(0,0,0,0.05);
            transition: var(--transition);
            position: relative;
            overflow: hidden;
        }

        .medication-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 4px;
            height: 100%;
            background: var(--secondary-color);
            opacity: 0.7;
        }

        .medication-card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-lg);
        }

        .medication-card h4 {
            margin-top: 0;
            color: var(--secondary-color);
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 18px;
            padding-bottom: 12px;
            border-bottom: 1px solid #e2e8f0;
        }

        .medication-card p {
            margin: 10px 0;
            font-size: 14px;
            color: var(--text-secondary);
            line-height: 1.6;
        }

        .medication-card p strong {
            color: var(--text-primary);
            font-weight: 600;
        }

        .timing-grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 10px;
            margin-top: 15px;
        }

        .timing-item {
            text-align: center;
            background: var(--bg-tertiary);
            padding: 10px 6px;
            border-radius: var(--radius-sm);
            font-size: 13px;
            transition: var(--transition);
        }

        .timing-item:hover {
            background: var(--secondary-light);
            transform: translateY(-2px);
        }

        .timing-item span {
            display: block;
            font-size: 18px;
            margin-bottom: 6px;
        }

        .feedback {
            text-align: center;
            margin-top: 50px;
            background: linear-gradient(135deg, var(--primary-light), #f0f9ff);
            padding: 35px;
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            border: 1px solid rgba(0,0,0,0.05);
        }

        .feedback h3 {
            margin-top: 0;
            color: var(--text-primary);
            font-weight: 600;
            margin-bottom: 25px;
            font-size: 20px;
        }

        .feedback a, .feedback button {
            background: var(--primary-color);
            padding: 14px 32px;
            color: #fff;
            border-radius: 50px;
            text-decoration: none;
            font-weight: 500;
            display: inline-block;
            transition: var(--transition);
            border: none;
            cursor: pointer;
            box-shadow: 0 4px 12px rgba(67, 97, 238, 0.3);
            font-size: 16px;
        }

        .feedback a:hover, .feedback button:hover {
            background: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(67, 97, 238, 0.4);
        }
        
        .feedback button:disabled {
            background: #94a3b8;
            cursor: not-allowed;
            transform: none;
            box-shadow: none;
        }

        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 30px;
            background: var(--bg-tertiary);
            border-radius: var(--radius-md);
            color: var(--text-tertiary);
        }

        .empty-state svg {
            opacity: 0.5;
            margin-bottom: 15px;
            width: 48px;
            height: 48px;
        }

        .empty-state p {
            font-size: 16px;
        }

        .rating-stars {
            margin-top: 20px;
            margin-bottom: 5px;
            display: flex;
            justify-content: center;
            gap: 5px;
        }

        .rating-stars .star {
            color: var(--star-color);
            font-size: 24px;
        }

        .rating-stars .star-inactive {
            color: var(--star-inactive);
            font-size: 24px;
        }

        .rating-count {
            font-size: 14px;
            color: var(--text-secondary);
            margin-top: 5px;
            text-align: center;
        }

        .rating-average {
            font-size: 16px;
            font-weight: 600;
            color: var(--text-primary);
            margin-top: 5px;
            text-align: center;
        }
        
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .modal-content {
            background-color: white;
            padding: 30px;
            border-radius: var(--radius-md);
            max-width: 500px;
            width: 90%;
            text-align: center;
            box-shadow: var(--shadow-xl);
        }
        
        .modal-content h3 {
            margin-top: 0;
            color: var(--text-primary);
            font-size: 20px;
            margin-bottom: 20px;
        }
        
        .modal-content p {
            margin-bottom: 25px;
            color: var(--text-secondary);
        }
        
        .modal-content button {
            background: var(--primary-color);
            padding: 12px 25px;
            color: white;
            border: none;
            border-radius: 50px;
            cursor: pointer;
            font-weight: 500;
            transition: var(--transition);
        }
        
        .modal-content button:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
        }

        /* Security Warning Modal */
        .security-modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            z-index: 2000;
            justify-content: center;
            align-items: center;
        }

        .security-modal-content {
            background: linear-gradient(135deg, #ff6b6b, #ee5a52);
            color: white;
            padding: 40px;
            border-radius: var(--radius-lg);
            max-width: 600px;
            width: 90%;
            text-align: center;
            box-shadow: var(--shadow-xl);
            animation: shake 0.5s ease-in-out;
        }

        @keyframes shake {
            0%, 100% { transform: translateX(0); }
            25% { transform: translateX(-10px); }
            75% { transform: translateX(10px); }
        }

        .security-modal-content h3 {
            margin-top: 0;
            font-size: 24px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .security-modal-content p {
            margin-bottom: 25px;
            font-size: 16px;
            line-height: 1.6;
        }

        .security-modal-content .warning-icon {
            font-size: 48px;
            margin-bottom: 20px;
        }

        .security-modal-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .security-modal-buttons button {
            background: rgba(255, 255, 255, 0.2);
            border: 2px solid white;
            color: white;
            padding: 12px 25px;
            border-radius: 50px;
            cursor: pointer;
            font-weight: 500;
            transition: var(--transition);
            font-size: 16px;
        }

        .security-modal-buttons button:hover {
            background: white;
            color: #ff6b6b;
        }

        .security-modal-buttons .stay-button {
            background: white;
            color: #ff6b6b;
        }

        .security-modal-buttons .stay-button:hover {
            background: rgba(255, 255, 255, 0.9);
        }

        @media (max-width: 992px) {
            .container {
                margin: 20px;
                width: auto;
            }
            
            .main-card {
                padding: 25px;
            }
            
            .header {
                padding: 20px 25px;
                flex-direction: column;
                gap: 15px;
            }

            .header-timers {
                width: 100%;
                justify-content: center;
            }
        }

        @media (max-width: 768px) {
            .main-card {
                flex-direction: column;
                padding: 20px;
            }
            
            .left-card, .right-card {
                flex: 100%;
            }
            
            .grid-container {
                grid-template-columns: 1fr;
            }
            
            .medications-grid {
                grid-template-columns: 1fr;
            }
            
            .header h1 {
                font-size: 20px;
            }

            .header-timers {
                flex-direction: column;
                gap: 10px;
            }

            .session-timer, .date-badge {
                width: 100%;
                justify-content: center;
            }
        }

        @media (max-width: 480px) {
            .container {
                margin: 10px;
            }
            
            .timing-grid {
                grid-template-columns: repeat(2, 1fr);
            }

            .security-modal-buttons {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <!-- Hidden CSRF token for JavaScript -->
    <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($csrf_token) ?>">
    
    <div class="container">
        <header class="header">
            <div class="header-content">
                <h1>Patient Medical Record</h1>
                <p>Detailed health information and treatment history</p>
            </div>
            
            <div class="header-timers">
                <div class="session-timer" id="sessionTimer">
                    <svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"></circle>
                        <polyline points="12,6 12,12 16,14"></polyline>
                    </svg>
                    <span id="timerDisplay">Active</span>
                </div>
                
                <div class="date-badge">
                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"></rect><line x1="16" y1="2" x2="16" y2="6"></line><line x1="8" y1="2" x2="8" y2="6"></line><line x1="3" y1="10" x2="21" y2="10"></line></svg>
                    <?= htmlspecialchars(date('F d, Y', strtotime($details['date'] ?? 'now'))) ?>
                </div>
            </div>
        </header>
        
        <div class="main-card">
            <aside class="left-card">
                <img src="<?= htmlspecialchars($profile_picture_src) ?>" alt="Doctor's Profile">
                <h2 class="doctor-name">Dr. <?= htmlspecialchars($details['doctor_first_name'] . ' ' . $details['doctor_last_name']) ?></h2>
                <span class="specialization"><?= htmlspecialchars($details['specialization'] ?: "General Practitioner") ?></span>
                
                <!-- Doctor Rating Stars -->
                <div class="rating-stars">
                    <?php
                    $full_stars = floor($average_rating);
                    $half_star = ($average_rating - $full_stars) >= 0.5;
                    $empty_stars = 5 - $full_stars - ($half_star ? 1 : 0);
                    
                    for ($i = 0; $i < $full_stars; $i++) {
                        echo '<span class="star">★</span>';
                    }
                    
                    if ($half_star) {
                        echo '<span class="star">★</span>';
                    }
                    
                    for ($i = 0; $i < $empty_stars; $i++) {
                        echo '<span class="star-inactive">★</span>';
                    }
                    ?>
                </div>
                <div class="rating-average"><?= number_format($average_rating, 1) ?>/5.0</div>
                <div class="rating-count"><?= $rating_count ?> ratings</div>
            </aside>
            
            <section class="right-card">
                <h3 class="hospital-name">
                    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 3v12h-5c-.023-3.681.184-7.406 5-12zm0 12v6h-1v-3M8 3v18h12v-6M8 6h4m-4 3h4m-4 3h4m-4 3h4"></path><path d="M3 3v18h5V3z"></path></svg>
                    <?= htmlspecialchars($details['hospital'] ?: "Hospital not specified") ?>
                </h3>
                
                <div class="grid-container">
                    <div class="info-box">
                        <h3>
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                            Problem
                        </h3>
                        <p><?= htmlspecialchars($details['problem'] ?: "No problem specified") ?></p>
                    </div>
                    
                    <div class="video-container">
                        <?php if (!empty($details['video_file'])): ?>
                            <div class="video-wrapper">
                                <video id="custom-video" controls 
                                    oncontextmenu="return false;" 
                                    ondragstart="return false;" 
                                    controlsList="nodownload" 
                                    disablepictureinpicture 
                                    playsinline
                                    preload="metadata">
                                    <source src="?stream=1&history_id=<?= htmlspecialchars($history_id); ?>" type="video/mp4">
                                    Your browser does not support the video tag.
                                </video>
                            </div>
                        <?php else: ?>
                            <div class="no-video">
                                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#cbd5e0" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><path d="M23 7l-7 5 7 5V7z"></path><rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect></svg>
                                <p>No video available</p>
                            </div>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="info-box">
                    <h3>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
                        Description
                    </h3>
                    <p><?= $decrypted_problem_description ?: "No description provided" ?></p>
                </div>
                
                <div class="info-box">
                    <h3>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 14l-7 7-7-7m14-8l-7 7-7-7"></path></svg>
                        Current Medication
                    </h3>
                    <p><?= $decrypted_current_medication ?: "No current medication information" ?></p>
                </div>
                
                <div class="info-box">
                    <h3>
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"></path><rect x="8" y="2" width="8" height="4" rx="1" ry="1"></rect><path d="M9 14l2 2 4-4"></path></svg>
                        Doctor's Solution
                    </h3>
                    <p><?= $decrypted_doctor_solution ?: "Your problem statement is in progress" ?></p>
                </div>

                <h3 class="section-title">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 14c1.49-1.46 3-3.21 3-5.5A5.5 5.5 0 0 0 16.5 3c-1.76 0-3 .5-4.5 2-1.5-1.5-2.74-2-4.5-2A5.5 5.5 0 0 0 2 8.5c0 2.3 1.5 4.05 3 5.5l7 7Z"></path></svg>
                    Prescribed Medications
                </h3>
                
                <div class="medications-grid">
                    <?php if (!empty($medications)): ?>
                        <?php foreach ($medications as $medication): ?>
                            <div class="medication-card">
                                <h4><?= $medication['medication_name'] ?: "Not provided" ?></h4>
                                <p><strong>Dosage:</strong> <?= $medication['dosage'] ?: "Not provided" ?></p>
                                <p><strong>Duration:</strong> <?= ($medication['start_date'] === '0000-00-00' || empty($medication['start_date'])) ? "Start: Not set" : "Start: " . $medication['start_date']; ?> → 
                                <?= ($medication['end_date'] === '0000-00-00' || empty($medication['end_date'])) ? "End: Not set" : "End: " . $medication['end_date']; ?>
                                </p>
                                <p><strong>Type:</strong> <?= $medication['medication_type'] ?: "Not provided" ?></p>
                                
                                <p><strong>Schedule:</strong></p>
                                <div class="timing-grid">
                                    <div class="timing-item">
                                        <span>☀️</span>
                                        <?= $medication['morning_time'] ?: "N/A" ?>
                                    </div>
                                    <div class="timing-item">
                                        <span>🌞</span>
                                        <?= $medication['afternoon_time'] ?: "N/A" ?>
                                    </div>
                                    <div class="timing-item">
                                        <span>🌆</span>
                                        <?= $medication['evening_time'] ?: "N/A" ?>
                                    </div>
                                    <div class="timing-item">
                                        <span>🌙</span>
                                        <?= $medication['night_time'] ?: "N/A" ?>
                                    </div>
                                </div>
                                
                                <p style="margin-top: 15px;"><strong>Notes:</strong> <?= $medication['additional_instructions'] ?: "Not provided" ?></p>
                            </div>
                        <?php endforeach; ?>
                    <?php else: ?>
                        <div class="empty-state">
                            <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 11h6"></path><path d="M12 8v6"></path><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"></path></svg>
                            <p>No medications have been prescribed yet.</p>
                        </div>
                    <?php endif; ?>
                </div>
                
                <footer class="feedback">
                    <h3>How was your experience with this doctor?</h3>
                    <?php if ($is_solution_in_progress): ?>
                        <button id="feedbackBtn" disabled>Give Feedback</button>
                    <?php else: ?>
                        <a href="../feedback/doctor_feedback.php?doctor_id=<?= urlencode($details['doctor_id']) ?>">Give Feedback</a>
                    <?php endif; ?>
                </footer>
            </section>
        </div>
    </div>
    
    <!-- Modal for feedback restriction -->
    <div id="feedbackModal" class="modal">
        <div class="modal-content">
            <h3>Feedback Not Available</h3>
            <p>You cannot give feedback yet as the doctor has not resolved your issue.</p>
            <button id="closeModal">Close</button>
        </div>
    </div>

    <!-- Security Warning Modal -->
    <div id="securityModal" class="security-modal">
        <div class="security-modal-content">
            <div class="warning-icon">⚠️</div>
            <h3>
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                    <line x1="12" y1="9" x2="12" y2="13"></line>
                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                </svg>
                Security Alert
            </h3>
            <p>We will log you out in <span id="countdownDisplay">10:00</span> to keep security measures. This page may contain sensitive information.</p>
            <p>If you don't want to be logged out, please interact with the page to reset the timer.</p>
            <div class="security-modal-buttons">
                <button class="stay-button" onclick="resetSessionTimer()">Stay Active</button>
                <button onclick="logoutUser()">Logout Now</button>
            </div>
        </div>
    </div>

    <script>
        // Session Timer Configuration
        const SESSION_CONFIG = {
            IDLE_TIME: 10 * 60 * 1000, // 10 minutes in milliseconds
            COUNTDOWN_TIME: 10 * 60 * 1000, // 10 minutes in milliseconds
            TOTAL_TIME: 20 * 60 * 1000, // 20 minutes total
            CHECK_INTERVAL: 1000 // Check every second
        };

        // Session Timer Class
        class SessionTimer {
            constructor() {
                this.isIdle = false;
                this.isCountdown = false;
                this.lastActivity = Date.now();
                this.idleTimer = null;
                this.countdownTimer = null;
                this.countdownStartTime = null;
                this.checkInterval = null;
                
                this.timerDisplay = document.getElementById('timerDisplay');
                this.sessionTimer = document.getElementById('sessionTimer');
                this.securityModal = document.getElementById('securityModal');
                this.countdownDisplay = document.getElementById('countdownDisplay');
                
                this.init();
            }

            init() {
                this.bindEvents();
                this.startIdleTimer();
                this.startCheckInterval();
                this.updateDisplay();
            }

            bindEvents() {
                // Track user activity
                const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
                events.forEach(event => {
                    document.addEventListener(event, () => this.resetActivity(), true);
                });

                // Prevent context menu and other security measures
                document.addEventListener('contextmenu', (e) => e.preventDefault());
                document.addEventListener('selectstart', (e) => e.preventDefault());
                document.addEventListener('dragstart', (e) => e.preventDefault());

                // Handle visibility change
                document.addEventListener('visibilitychange', () => {
                    if (document.hidden) {
                        this.handlePageHidden();
                    } else {
                        this.handlePageVisible();
                    }
                });

                // Handle beforeunload
                window.addEventListener('beforeunload', (e) => {
                    if (this.isCountdown) {
                        e.preventDefault();
                        e.returnValue = 'You have unsaved changes. Are you sure you want to leave?';
                        return e.returnValue;
                    }
                });
            }

            resetActivity() {
                if (this.isCountdown) {
                    this.resetSessionTimer();
                } else {
                    this.lastActivity = Date.now();
                    if (this.isIdle) {
                        this.resetFromIdle();
                    }
                }
            }

            startIdleTimer() {
                this.clearTimers();
                this.idleTimer = setTimeout(() => {
                    this.startIdlePhase();
                }, SESSION_CONFIG.IDLE_TIME);
            }

            startIdlePhase() {
                this.isIdle = true;
                this.updateDisplay();
                
                // Start countdown after idle period
                this.countdownTimer = setTimeout(() => {
                    this.startCountdownPhase();
                }, 0); // Start countdown immediately after idle
            }

            startCountdownPhase() {
                this.isIdle = false;
                this.isCountdown = true;
                this.countdownStartTime = Date.now();
                this.showSecurityModal();
                this.updateDisplay();
                
                // Auto logout after countdown
                this.countdownTimer = setTimeout(() => {
                    this.logoutUser();
                }, SESSION_CONFIG.COUNTDOWN_TIME);
            }

            resetFromIdle() {
                this.isIdle = false;
                this.updateDisplay();
                this.startIdleTimer();
            }

            resetSessionTimer() {
                this.clearTimers();
                this.isIdle = false;
                this.isCountdown = false;
                this.lastActivity = Date.now();
                this.hideSecurityModal();
                this.updateDisplay();
                this.startIdleTimer();
            }

            clearTimers() {
                if (this.idleTimer) {
                    clearTimeout(this.idleTimer);
                    this.idleTimer = null;
                }
                if (this.countdownTimer) {
                    clearTimeout(this.countdownTimer);
                    this.countdownTimer = null;
                }
            }

            startCheckInterval() {
                this.checkInterval = setInterval(() => {
                    this.updateDisplay();
                }, SESSION_CONFIG.CHECK_INTERVAL);
            }

            updateDisplay() {
                if (this.isCountdown) {
                    const elapsed = Date.now() - this.countdownStartTime;
                    const remaining = Math.max(0, SESSION_CONFIG.COUNTDOWN_TIME - elapsed);
                    const minutes = Math.floor(remaining / 60000);
                    const seconds = Math.floor((remaining % 60000) / 1000);
                    
                    this.timerDisplay.textContent = `Logout in ${minutes}:${seconds.toString().padStart(2, '0')}`;
                    this.countdownDisplay.textContent = `${minutes}:${seconds.toString().padStart(2, '0')}`;
                    
                    this.sessionTimer.className = 'session-timer countdown';
                    
                    if (remaining <= 0) {
                        this.logoutUser();
                    }
                } else if (this.isIdle) {
                    this.timerDisplay.textContent = 'Idle - Please interact';
                    this.sessionTimer.className = 'session-timer idle';
                } else {
                    const timeSinceActivity = Date.now() - this.lastActivity;
                    const remaining = Math.max(0, SESSION_CONFIG.IDLE_TIME - timeSinceActivity);
                    const minutes = Math.floor(remaining / 60000);
                    const seconds = Math.floor((remaining % 60000) / 1000);
                    
                    this.timerDisplay.textContent = `Active (${minutes}:${seconds.toString().padStart(2, '0')})`;
                    this.sessionTimer.className = 'session-timer';
                }
            }

            showSecurityModal() {
                this.securityModal.style.display = 'flex';
                document.body.style.overflow = 'hidden';
            }

            hideSecurityModal() {
                this.securityModal.style.display = 'none';
                document.body.style.overflow = 'auto';
            }

            handlePageHidden() {
                // Optionally pause timers when page is hidden
                console.log('Page hidden - session timer continues');
            }

            handlePageVisible() {
                // Reset activity when page becomes visible again
                this.resetActivity();
            }

            logoutUser() {
                this.clearTimers();
                if (this.checkInterval) {
                    clearInterval(this.checkInterval);
                }
                
                // Clear sensitive data
                this.clearSensitiveData();
                
                // Redirect to logout page
                window.location.href = '../logout.php';
            }

            clearSensitiveData() {
                // Clear any cached data
                if ('caches' in window) {
                    caches.keys().then(names => {
                        names.forEach(name => {
                            caches.delete(name);
                        });
                    });
                }
                
                // Clear session storage
                sessionStorage.clear();
                
                // Clear any form data
                const forms = document.querySelectorAll('form');
                forms.forEach(form => form.reset());
            }

            destroy() {
                this.clearTimers();
                if (this.checkInterval) {
                    clearInterval(this.checkInterval);
                }
                
                // Remove event listeners
                const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'];
                events.forEach(event => {
                    document.removeEventListener(event, this.resetActivity, true);
                });
            }
        }

        // Global functions for modal buttons
        function resetSessionTimer() {
            if (window.sessionTimer) {
                window.sessionTimer.resetSessionTimer();
            }
        }

        function logoutUser() {
            if (window.sessionTimer) {
                window.sessionTimer.logoutUser();
            }
        }

        // Initialize session timer when DOM is loaded
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize session timer
            window.sessionTimer = new SessionTimer();
            
            // Modal functionality for feedback restriction
            const feedbackBtn = document.getElementById('feedbackBtn');
            const feedbackModal = document.getElementById('feedbackModal');
            const closeModal = document.getElementById('closeModal');

            if (feedbackBtn) {
                feedbackBtn.addEventListener('click', function() {
                    if (this.disabled) {
                        feedbackModal.style.display = 'flex';
                    }
                });
            }

            if (closeModal) {
                closeModal.addEventListener('click', function() {
                    feedbackModal.style.display = 'none';
                });
            }

            // Close modal when clicking outside
            if (feedbackModal) {
                feedbackModal.addEventListener('click', function(e) {
                    if (e.target === this) {
                        this.style.display = 'none';
                    }
                });
            }

            // Video security enhancements
            const video = document.getElementById('custom-video');
            if (video) {
                // Prevent video download and right-click
                video.addEventListener('contextmenu', (e) => e.preventDefault());
                video.addEventListener('dragstart', (e) => e.preventDefault());
                
                // Disable keyboard shortcuts for video
                video.addEventListener('keydown', function(e) {
                    // Disable common video shortcuts
                    const disabledKeys = ['s', 'S', 'd', 'D', 'c', 'C', 'v', 'V'];
                    if (disabledKeys.includes(e.key) || 
                        (e.ctrlKey && (e.key === 's' || e.key === 'S')) ||
                        (e.ctrlKey && e.shiftKey && (e.key === 'I' || e.key === 'i'))) {
                        e.preventDefault();
                        e.stopPropagation();
                    }
                });

                // Monitor video events for security
                video.addEventListener('loadstart', function() {
                    console.log('Video loading started');
                });

                video.addEventListener('error', function(e) {
                    console.error('Video error:', e);
                    // Handle video errors gracefully
                    const videoContainer = video.closest('.video-wrapper');
                    if (videoContainer) {
                        videoContainer.innerHTML = `
                            <div class="no-video">
                                <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="#cbd5e0" stroke-width="1" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M23 7l-7 5 7 5V7z"></path>
                                    <rect x="1" y="5" width="15" height="14" rx="2" ry="2"></rect>
                                </svg>
                                <p>Video temporarily unavailable</p>
                            </div>
                        `;
                    }
                });
            }

            // Additional security measures
            
            // Disable text selection on sensitive areas
            document.addEventListener('selectstart', function(e) {
                const sensitiveElements = ['video', 'img'];
                if (sensitiveElements.includes(e.target.tagName.toLowerCase())) {
                    e.preventDefault();
                }
            });

            // Disable drag and drop
            document.addEventListener('dragstart', function(e) {
                e.preventDefault();
            });

            // Monitor for developer tools
            let devtools = false;
            setInterval(function() {
                if (window.outerHeight - window.innerHeight > 200 || 
                    window.outerWidth - window.innerWidth > 200) {
                    if (!devtools) {
                        devtools = true;
                        console.clear();
                        console.log('%cSecurity Warning!', 'color: red; font-size: 30px; font-weight: bold;');
                        console.log('%cThis page contains sensitive medical information. Unauthorized access is prohibited.', 'color: red; font-size: 16px;');
                    }
                } else {
                    devtools = false;
                }
            }, 1000);

            // Disable common keyboard shortcuts
            document.addEventListener('keydown', function(e) {
                // Disable F12, Ctrl+Shift+I, Ctrl+Shift+J, Ctrl+U, Ctrl+S
                if (e.keyCode === 123 || // F12
                    (e.ctrlKey && e.shiftKey && (e.keyCode === 73 || e.keyCode === 74)) || // Ctrl+Shift+I/J
                    (e.ctrlKey && e.keyCode === 85) || // Ctrl+U
                    (e.ctrlKey && e.keyCode === 83)) { // Ctrl+S
                    e.preventDefault();
                    e.stopPropagation();
                    return false;
                }
            });

            // Clear console periodically
            setInterval(function() {
                console.clear();
            }, 5000);

            // Warn about page refresh/close during sensitive operations
            let hasInteracted = false;
            document.addEventListener('click', function() {
                hasInteracted = true;
            });

            window.addEventListener('beforeunload', function(e) {
                if (hasInteracted && window.sessionTimer && window.sessionTimer.isCountdown) {
                    const message = 'You have a security countdown active. Are you sure you want to leave?';
                    e.returnValue = message;
                    return message;
                }
            });

            // Performance monitoring
            if ('performance' in window) {
                window.addEventListener('load', function() {
                    setTimeout(function() {
                        const perfData = performance.getEntriesByType('navigation')[0];
                        if (perfData && perfData.loadEventEnd - perfData.loadEventStart > 5000) {
                            console.log('Page load time was longer than expected');
                        }
                    }, 0);
                });
            }

            // Memory cleanup on page unload
            window.addEventListener('unload', function() {
                if (window.sessionTimer) {
                    window.sessionTimer.destroy();
                }
                
                // Clear any remaining timers
                const highestTimeoutId = setTimeout(function(){}, 0);
                for (let i = 0; i < highestTimeoutId; i++) {
                    clearTimeout(i);
                }
                
                const highestIntervalId = setInterval(function(){}, 0);
                for (let i = 0; i < highestIntervalId; i++) {
                    clearInterval(i);
                }
            });

            console.log('Session timer and security measures initialized successfully');
        });

        // Additional utility functions
        function formatTime(milliseconds) {
            const minutes = Math.floor(milliseconds / 60000);
            const seconds = Math.floor((milliseconds % 60000) / 1000);
            return `${minutes}:${seconds.toString().padStart(2, '0')}`;
        }

        function isPageVisible() {
            return !document.hidden;
        }

        function logSecurityEvent(event, details = {}) {
            const timestamp = new Date().toISOString();
            console.log(`[SECURITY] ${timestamp}: ${event}`, details);
            
            // In a real application, you might want to send this to a logging service
            // fetch('/api/security-log', {
            //     method: 'POST',
            //     headers: { 'Content-Type': 'application/json' },
            //     body: JSON.stringify({ event, details, timestamp })
            // });
        }

        // Log initial page load
        logSecurityEvent('Page loaded', {
            userAgent: navigator.userAgent,
            timestamp: Date.now(),
            url: window.location.href
        });
    </script>
</body>
</html>
