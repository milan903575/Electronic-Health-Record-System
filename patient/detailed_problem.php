<?php
session_start();
include '../connection.php';

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
                'script-src' => ["'self'", "'unsafe-inline'", 'https://ajax.googleapis.com', 'https://maxcdn.bootstrapcdn.com'],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://maxcdn.bootstrapcdn.com'],
                'img-src' => ["'self'", 'data:', 'https:'],
                'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://maxcdn.bootstrapcdn.com'],
                'connect-src' => ["'self'"],
                'media-src' => ["'self'", 'data:'],
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
            'script-src' => ["'self'", "'unsafe-inline'", 'https://ajax.googleapis.com', 'https://maxcdn.bootstrapcdn.com'],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://maxcdn.bootstrapcdn.com'],
            'img-src' => ["'self'", 'data:', 'https:'],
            'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://maxcdn.bootstrapcdn.com'],
            'connect-src' => ["'self'", 'https://cancerdetectionsystem.pythonanywhere.com', 'https://milan903575-medical-ai-assistant.hf.space'],
            'media-src' => ["'self'", 'data:'],
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

// Ensure user is logged in as a patient
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] != 'patient') {
    header("Location: ../login.html");
    exit;
}

$patient_id = $_SESSION['user_id'];

// Input validation and sanitization functions
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function validateFileUpload($file) {
    $allowed_types = ['video/mp4', 'video/avi', 'video/mov', 'video/wmv', 'video/webm'];
    $max_size = 50 * 1024 * 1024; // 50MB
    
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    
    if (!in_array($file['type'], $allowed_types)) {
        throw new Exception('Invalid file type. Only video files are allowed.');
    }
    
    if ($file['size'] > $max_size) {
        throw new Exception('File size too large. Maximum 50MB allowed.');
    }
    
    return true;
}

function validateImageUpload($file) {
    $allowed_types = ['image/jpeg', 'image/jpg', 'image/png'];
    $max_size = 10 * 1024 * 1024; // 10MB
    
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    
    if (!in_array($file['type'], $allowed_types)) {
        throw new Exception('Invalid file type. Only JPEG and PNG images are allowed.');
    }
    
    if ($file['size'] > $max_size) {
        throw new Exception('File size too large. Maximum 10MB allowed.');
    }
    
    return true;
}

// Image Analysis with PythonAnywhere API - WITH LANGUAGE SUPPORT
function analyzeImageWithPythonAnywhere($imagePath, $language = 'en') {
    $apiUrl = "https://cancerdetectionsystem.pythonanywhere.com/api/predict";
    
    try {
        if (!file_exists($imagePath)) {
            throw new Exception("Image file not found");
        }
        
        $imageInfo = getimagesize($imagePath);
        if (!$imageInfo) {
            throw new Exception("Invalid image file");
        }
        
        $mimeType = $imageInfo['mime'];
        $cfile = new CURLFile($imagePath, $mimeType, basename($imagePath));
        
        $postData = [
            'image' => $cfile,
            'language' => $language
        ];
        
        $ch = curl_init();
        curl_setopt_array($ch, [
            CURLOPT_URL => $apiUrl,
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $postData,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 300,
            CURLOPT_CONNECTTIMEOUT => 300,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 3,
            CURLOPT_USERAGENT => 'Medical-AI-Client/1.0'
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            throw new Exception("Connection Error: " . $error);
        }
        
        if ($httpCode !== 200) {
            throw new Exception("API Error: HTTP " . $httpCode . " - Service temporarily unavailable");
        }
        
        $result = json_decode($response, true);
        
        if (json_last_error() !== JSON_ERROR_NONE) {
            throw new Exception("Response Error: Unable to parse API response");
        }
        
        if (!isset($result['success']) || !$result['success']) {
            $errorMsg = isset($result['error']) ? $result['error'] : 'Unknown API error';
            throw new Exception("API Error: " . $errorMsg);
        }
        
        $analysis = $result['analysis'] ?? 'No analysis available';
        $audioUrl = $result['audio_url'] ?? null;
        $returnedLanguage = $result['language'] ?? $language;
        
        return [
            'success' => true,
            'analysis' => $analysis,
            'audio_url' => $audioUrl,
            'language' => $returnedLanguage,
            'method_used' => 'PythonAnywhere API'
        ];
        
    } catch (Exception $e) {
        return [
            'success' => false,
            'error' => $e->getMessage()
        ];
    }
}

// Hospital search with CSRF protection
if (isset($_GET['query']) && isset($_GET['csrf_token']) && validateCSRFToken($_GET['csrf_token'])) {
    $query = sanitizeInput($_GET['query']);

    if (strlen($query) < 2) {
        echo "<div style='padding:10px; font-size: 1.125rem;'>Please enter at least 2 characters.</div>";
        exit;
    }

    $sql = "SELECT id, hospital_name, registration_fee FROM hospitals 
            WHERE hospital_name LIKE ? OR zipcode LIKE ? LIMIT 10";
    $stmt = $conn->prepare($sql);
    $search_query = "%" . $query . "%";
    $stmt->bind_param("ss", $search_query, $search_query);
    $stmt->execute();
    $result = $stmt->get_result();

    $output = '';
    while ($row = $result->fetch_assoc()) {
        $output .= '<div class="hospital-option" data-id="' . intval($row['id']) . '" data-fee="' . floatval($row['registration_fee']) . '">' 
                 . htmlspecialchars($row['hospital_name']) . 
                 '</div>';
    }

    echo $output ?: "<div style='padding:10px; font-size: 1.125rem;'>No matching hospitals found.</div>";
    $stmt->close();
    $conn->close();
    exit;
}

// Check Registration Status with CSRF protection - UPDATED MESSAGING
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['hospital_id']) && !isset($_POST['problem_description']) && !isset($_POST['image_analysis'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        echo "CSRF token validation failed";
        exit;
    }

    $hospital_id = intval($_POST['hospital_id']);

    if ($hospital_id <= 0) {
        echo "Invalid hospital ID";
        exit;
    }

    $sql = "SELECT ph.registration_status, h.registration_fee
            FROM patient_hospital ph
            LEFT JOIN hospitals h ON ph.hospital_id = h.id
            WHERE ph.hospital_id = ? AND ph.patient_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $hospital_id, $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $response = '';

    if ($row = $result->fetch_assoc()) {
        if ($row['registration_status'] === 'pending' || $row['registration_status'] === 'Pending') {
            $response = "<p style='color: #ef4444; font-weight: bold; font-size: 1.125rem;'>This hospital requires a registration fee.</p>";
        } else {
            $response = "<p style='color: #10b981; font-weight: bold; font-size: 1.125rem;'>Registration complete. You can submit the form.</p>";
        }
    } else {
        $response = "<p style='color: #ef4444; font-weight: bold; font-size: 1.125rem;'>You have not registered to this hospital, please register in the login page.</p>";
    }

    echo $response;
    $stmt->close();
    exit;
}

// Image Analysis with CSRF protection - PythonAnywhere API WITH LANGUAGE
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['image_analysis'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        echo json_encode(['error' => 'CSRF token validation failed']);
        exit;
    }

    $language = isset($_POST['image_language']) ? sanitizeInput($_POST['image_language']) : 'en';
    $allowed_languages = ['en', 'hi', 'kn', 'ta', 'te', 'bn', 'gu'];
    if (!in_array($language, $allowed_languages)) {
        $language = 'en';
    }

    if (!isset($_FILES['analysis_image']) || $_FILES['analysis_image']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['error' => 'Please upload an image for analysis']);
        exit;
    }

    try {
        validateImageUpload($_FILES['analysis_image']);
        
        $result = analyzeImageWithPythonAnywhere($_FILES['analysis_image']['tmp_name'], $language);
        
        echo json_encode([
            'success' => $result['success'],
            'analysis' => $result['analysis'] ?? null,
            'audio_url' => $result['audio_url'] ?? null,
            'language' => $result['language'] ?? $language,
            'method_used' => $result['method_used'] ?? 'PythonAnywhere API',
            'error' => $result['error'] ?? null
        ]);
        
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

// AI Solution Generation with Hugging Face API - UPDATED WITH LANGUAGE SUPPORT
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['problem_description']) && !isset($_POST['problem'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        echo json_encode(['error' => 'CSRF token validation failed']);
        exit;
    }

    $problem_description = sanitizeInput($_POST['problem_description']);
    $language = isset($_POST['language']) ? sanitizeInput($_POST['language']) : 'en';

    $allowed_languages = ['en', 'hi', 'kn', 'ta', 'te', 'bn', 'gu'];
    if (!in_array($language, $allowed_languages)) {
        $language = 'en';
    }

    if (empty($problem_description)) {
        echo json_encode(['error' => 'Problem description is required']);
        exit;
    }

    // Hugging Face API call with language support
    $hf_api_url = "$hf_url = 'https://username-spacename.hf.space/space';";
    
    $postData = json_encode([
        'question' => $problem_description,
        'language' => $language  // Send selected language
    ]);

    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $hf_api_url,
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $postData,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 300,
        CURLOPT_CONNECTTIMEOUT => 30,
        CURLOPT_HTTPHEADER => [
            'Content-Type: application/json',
            'Content-Length: ' . strlen($postData)
        ],
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 3,
        CURLOPT_USERAGENT => 'Medical-AI-Client/1.0'
    ]);

    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);

    if ($error) {
        echo json_encode(['error' => 'Connection Error: ' . $error]);
        exit;
    }

    if ($httpCode !== 200) {
        echo json_encode(['error' => 'API Error: HTTP ' . $httpCode]);
        exit;
    }

    $result = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        echo json_encode(['error' => 'Response Error: Unable to parse API response']);
        exit;
    }

    if (isset($result['answer'])) {
        echo json_encode([
            'solution' => htmlspecialchars($result['answer']),
            'language' => $result['language'] ?? $language,
            'status' => $result['status'] ?? 'success',
            'audio_path' => '', // No audio from Hugging Face API
        ]);
    } else {
        echo json_encode(['error' => 'No answer received from AI']);
    }
    exit;
}


// Main form submission with CSRF protection
if ($_SERVER['REQUEST_METHOD'] == 'POST' && isset($_POST['problem'])) {
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        die('CSRF token validation failed');
    }

    $problem = sanitizeInput($_POST['problem']);
    $problem_description = sanitizeInput($_POST['problem_description']);
    $current_medication = sanitizeInput($_POST['current_medication']);
    $hospital_id = intval($_POST['hospital_id']);

    if (empty($problem) || empty($problem_description) || empty($current_medication) || $hospital_id <= 0) {
        echo "<script>alert('All fields are required and hospital must be selected.');</script>";
    } else {
        $video_path = null;
        if (isset($_FILES['video']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
            try {
                validateFileUpload($_FILES['video']);
                
                $upload_dir = '../uploads/videos/';
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }
                
                $filename = uniqid() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $_FILES['video']['name']);
                $video_path = $upload_dir . $filename;
                
                if (!move_uploaded_file($_FILES['video']['tmp_name'], $video_path)) {
                    throw new Exception('Failed to upload video file');
                }
            } catch (Exception $e) {
                echo "<script>alert('File upload error: " . $e->getMessage() . "');</script>";
                $video_path = null;
            }
        }

        $sql = "INSERT INTO patient_problems (patient_id, hospital_id, problem_type, problem_description, current_medication, video_path, created_at) VALUES (?, ?, ?, ?, ?, ?, NOW())";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iissss", $patient_id, $hospital_id, $problem, $problem_description, $current_medication, $video_path);
        
        if ($stmt->execute()) {
            echo "<script>alert('Problem submitted successfully!'); window.location.href = 'patient_dashboard.php';</script>";
        } else {
            echo "<script>alert('Error submitting problem. Please try again.');</script>";
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Submit Problem</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #4a6fff;
            --primary-light: #eef2ff;
            --secondary-color: #5d6c89;
            --background-color: #f8fafc;
            --card-background: #ffffff;
            --text-color: #2d3748;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --success-color: #10b981;
            --error-color: #ef4444;
            --shadow-sm: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --radius-sm: 0.25rem;
            --radius: 0.5rem;
            --radius-lg: 0.75rem;
            --transition: all 0.2s ease;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }

        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
            font-size: 1.125rem; /* Increased from 1rem */
        }

        .container {
            max-width: 800px;
            margin: 2rem auto;
            padding: 0 1rem;
        }

        .page-title {
            text-align: center;
            margin-bottom: 2rem;
            color: var(--primary-color);
            font-weight: 600;
            font-size: 2.5rem; /* Increased from 2rem */
        }

        .form-card {
            background: var(--card-background);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            padding: 2rem;
            margin-bottom: 2rem;
            transition: var(--transition);
        }

        .form-card:hover {
            box-shadow: var(--shadow-lg);
        }

        .form-section {
            margin-bottom: 1.5rem;
            padding-bottom: 1.5rem;
            border-bottom: 1px solid var(--border-color);
        }

        .form-section:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }

        .section-title {
            margin-bottom: 1.5rem;
            font-weight: 600;
            color: var(--primary-color);
            font-size: 1.5rem; /* Increased from 1.25rem */
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-group:last-child {
            margin-bottom: 0;
        }

        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--secondary-color);
            font-size: 1rem; /* Increased from 0.875rem */
        }

        input[type="text"],
        textarea,
        select {
            width: 100%;
            padding: 0.75rem 1rem;
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            background-color: var(--card-background);
            color: var(--text-color);
            font-family: 'Inter', sans-serif;
            font-size: 1.125rem; /* Increased from 1rem */
            transition: var(--transition);
            box-shadow: var(--shadow-sm);
        }

        input[type="file"] {
            padding: 0.5rem 0;
            border: none;
            box-shadow: none;
            font-size: 1.125rem; /* Added font-size */
        }

        input[type="text"]:focus,
        textarea:focus,
        select:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(74, 111, 255, 0.2);
        }

        textarea {
            min-height: 100px;
            resize: vertical;
        }

        select {
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%235d6c89' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 1rem center;
            padding-right: 2.5rem;
        }

        .file-input-container {
            position: relative;
            overflow: hidden;
            display: inline-block;
            width: 100%;
        }

        .file-input-label {
            display: block;
            padding: 0.75rem 1rem;
            background: var(--primary-light);
            color: var(--primary-color);
            border-radius: var(--radius-sm);
            font-weight: 500;
            text-align: center;
            cursor: pointer;
            transition: var(--transition);
            font-size: 1.125rem; /* Added font-size */
        }

        .file-input-label:hover {
            background: rgba(74, 111, 255, 0.15);
        }

        .file-input-container input[type="file"] {
            position: absolute;
            left: 0;
            top: 0;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .file-name {
            margin-top: 0.5rem;
            font-size: 1rem; /* Increased from 0.875rem */
            color: var(--text-muted);
        }

        .btn {
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: var(--radius-sm);
            font-weight: 500;
            font-size: 1.125rem; /* Increased from 1rem */
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
        }

        .btn:hover {
            background: #3a5eef;
            transform: translateY(-1px);
        }

        .btn:active {
            transform: translateY(0);
        }

        .btn-secondary {
            background: var(--secondary-color);
        }

        .btn-secondary:hover {
            background: #4e5b75;
        }

        .btn-block {
            display: block;
            width: 100%;
        }

        .hospital-search-container {
            position: relative;
        }

        #hospital_list {
            position: absolute;
            width: 100%;
            background: var(--card-background);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            box-shadow: var(--shadow);
        }

        .hospital-option {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: var(--transition);
            font-size: 1.125rem; /* Added font-size */
        }

        .hospital-option:hover {
            background-color: var(--primary-light);
        }

        #registration_message {
            margin-top: 0.5rem;
            padding: 0.75rem;
            border-radius: var(--radius-sm);
            font-size: 1.125rem; /* Increased from 0.875rem */
        }

        .ai-solution {
            margin-top: 1rem;
            padding: 1.25rem;
            background: var(--primary-light);
            border-radius: var(--radius);
            color: var(--text-color);
            transition: var(--transition);
            font-size: 1.125rem; /* Added font-size */
        }

        .image-analysis-section {
            background: #ffffff;
            color: var(--text-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow);
        }

        .image-analysis-title {
            font-size: 1.75rem; /* Increased from 1.5rem */
            font-weight: 600;
            margin-bottom: 1rem;
            text-align: center;
            color: var(--primary-color);
        }

        .image-analysis-subtitle {
            text-align: center;
            margin-bottom: 1.5rem;
            color: var(--text-muted);
            font-size: 1.125rem; /* Added font-size */
        }

        .image-upload-area {
            background: var(--primary-light);
            border: 2px dashed var(--primary-color);
            border-radius: var(--radius);
            padding: 2rem;
            text-align: center;
            margin-bottom: 1rem;
            transition: var(--transition);
        }

        .image-upload-area:hover {
            background: rgba(74, 111, 255, 0.15);
            border-color: #3a5eef;
        }

        .image-upload-area input[type="file"] {
            display: none;
        }

        .image-upload-label {
            cursor: pointer;
            display: block;
            color: var(--primary-color);
            font-size: 1.125rem; /* Added font-size */
        }

        .upload-icon {
            font-size: 3rem;
            margin-bottom: 1rem;
            color: var(--primary-color);
        }

        .image-analysis-controls {
            display: flex;
            gap: 1rem;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
        }

        .image-language-select {
            background: var(--card-background);
            color: var(--text-color);
            border: 1px solid var(--border-color);
            border-radius: var(--radius-sm);
            padding: 0.5rem 1rem;
            font-size: 1.125rem; /* Added font-size */
        }

        .analyze-btn {
            background: var(--primary-color);
            color: white;
            border: 1px solid var(--primary-color);
            padding: 0.5rem 1.5rem;
            border-radius: var(--radius-sm);
            cursor: pointer;
            transition: var(--transition);
            font-size: 1.125rem; /* Added font-size */
        }

        .analyze-btn:hover {
            background: #3a5eef;
        }

        .image-analysis-result {
            background: var(--primary-light);
            border-radius: var(--radius);
            padding: 1.5rem;
            margin-top: 1rem;
            display: none;
            border: 1px solid var(--border-color);
            font-size: 1.125rem; /* Added font-size */
        }

        .caution {
            margin-bottom: 0.75rem;
            padding: 0.5rem 0.75rem;
            background-color: rgba(239, 68, 68, 0.1);
            color: var(--error-color);
            font-weight: 500;
            border-radius: var(--radius-sm);
            font-size: 1rem; /* Increased from 0.875rem */
            display: inline-block;
        }

        .language-select-container {
            display: flex;
            align-items: center;
            gap: 1rem;
            margin-bottom: 1rem;
        }

        .language-select-container select {
            flex: 1;
            max-width: 150px;
        }

        .audio-controls {
            margin-top: 1rem;
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        #play_audio, .play_image_audio {
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: var(--radius-sm);
            padding: 0.5rem 1rem;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            gap: 0.5rem;
            font-size: 1.125rem; /* Added font-size */
        }

        #play_audio:hover, .play_image_audio:hover {
            background: #3a5eef;
        }

        .loader {
            border: 3px solid var(--border-color);
            border-top: 3px solid var(--primary-color);
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-left: 0.5rem;
            vertical-align: middle;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .submit-container {
            margin-top: 2rem;
            text-align: center;
        }

        .submit-btn {
            padding: 0.875rem 2rem;
            background: linear-gradient(to right, #4a6fff, #3a5eef);
            color: white;
            border: none;
            border-radius: var(--radius);
            font-weight: 600;
            font-size: 1.25rem; /* Increased from 1.125rem */
            cursor: pointer;
            transition: var(--transition);
            box-shadow: 0 4px 6px rgba(74, 111, 255, 0.2);
        }

        .submit-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 7px 10px rgba(74, 111, 255, 0.3);
        }

        .submit-btn:active {
            transform: translateY(0);
        }

        .api-status {
            padding: 0.5rem 1rem;
            border-radius: var(--radius-sm);
            font-size: 1rem; /* Increased from 0.875rem */
            margin-top: 0.5rem;
        }

        .api-success {
            background-color: rgba(16, 185, 129, 0.1);
            color: var(--success-color);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .api-error {
            background-color: rgba(239, 68, 68, 0.1);
            color: var(--error-color);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .language-indicator {
            background-color: rgba(74, 111, 255, 0.1);
            color: var(--primary-color);
            border: 1px solid rgba(74, 111, 255, 0.2);
            padding: 0.25rem 0.5rem;
            border-radius: var(--radius-sm);
            font-size: 0.875rem; /* Increased from 0.75rem */
            margin-left: 0.5rem;
        }

        /* Enhanced styles for suggestions */
        .suggestion-list {
            margin: 15px 0 20px 0;
        }

        .suggestion-item {
            margin-bottom: 8px;
            display: flex;
            align-items: center;
        }

        .suggestion-item input[type="text"] {
            width: 90%;
            border: none;
            background: #f5f5f5;
            color: #333;
            font-size: 1.125rem; /* Increased from 15px */
            padding: 6px 10px; /* Increased padding */
            border-radius: 4px;
            margin-right: 8px;
        }

        .copy-suggestion {
            padding: 4px 10px; /* Increased padding */
            font-size: 1rem; /* Increased from 13px */
            border-radius: 4px;
            border: 1px solid #ccc;
            background: #fff;
            cursor: pointer;
            transition: var(--transition);
        }

        .copy-suggestion:hover {
            background: var(--primary-light);
            border-color: var(--primary-color);
        }

        .show-more-btn {
            background: var(--primary-color);
            color: white;
            border: none;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-sm);
            cursor: pointer;
            font-size: 1rem;
            margin-top: 10px;
            transition: var(--transition);
        }

        .show-more-btn:hover {
            background: #3a5eef;
        }

        /* Loading animation styles */
        .loading-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 2rem;
        }

        .loading-spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--border-color);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin-bottom: 1rem;
        }

        .loading-message {
            font-size: 1.125rem;
            font-weight: 500;
            color: var(--primary-color);
            margin-bottom: 0.5rem;
            text-align: center;
        }

        .loading-timer {
            font-size: 1rem;
            color: var(--text-muted);
            font-weight: 400;
        }

        .progress-bar {
            width: 100%;
            height: 8px;
            background-color: var(--border-color);
            border-radius: 4px;
            overflow: hidden;
            margin-bottom: 1rem;
        }

        .progress-fill {
            height: 100%;
            background: linear-gradient(to right, var(--primary-color), #3a5eef);
            width: 0%;
            transition: width 0.3s ease;
            animation: progressAnimation 30s linear infinite;
        }

        @keyframes progressAnimation {
            0% { width: 0%; }
            100% { width: 100%; }
        }

        @media (max-width: 768px) {
            .container {
                padding: 0 0.75rem;
                margin: 1rem auto;
            }

            .form-card {
                padding: 1.5rem;
            }

            .language-select-container {
                flex-direction: column;
                align-items: flex-start;
                gap: 0.5rem;
            }

            .language-select-container select {
                max-width: 100%;
            }

            .image-analysis-controls {
                flex-direction: column;
            }

            .suggestion-item {
                flex-direction: column;
                align-items: stretch;
            }

            .suggestion-item input[type="text"] {
                width: 100%;
                margin-right: 0;
                margin-bottom: 4px;
            }

            .page-title {
                font-size: 2rem; /* Smaller on mobile but still increased */
            }

            .section-title {
                font-size: 1.25rem; /* Smaller on mobile but still increased */
            }
        }
    </style>
</head>
<body>
    <input type="hidden" id="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
    
    <div class="container">
        <h1 class="page-title">Submit Your Problem</h1>
        
        <div class="form-card">
            <form action="submit_detailed_problem.php" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token); ?>">
                <input type="hidden" name="pdf_path" value="">
                
                <!-- Problem Details Section -->
                <div class="form-section">
                    <h2 class="section-title">Problem Details</h2>
                    
                    <div class="form-group">
                        <label for="specialization">Select Problem Type</label>
                        <select name="problem" id="specialization" required>
                            <option value="" disabled selected>Select a specialization</option>
                            <option value="General Physician">General Physician: Fever, headache, weakness, general checkup</option>
                            <option value="Pulmonologist">Pulmonologist: Lung, respiratory issues, asthma, bronchitis, breathing problems</option>
                            <option value="Cardiologist">Cardiologist: Heart, chest pain, blood pressure, palpitations</option>
                            <option value="Dermatologist">Dermatologist: Skin, rash, eczema, acne, psoriasis</option>
                            <option value="Neurologist">Neurologist: Brain, nerves, seizures, stroke, paralysis</option>
                            <option value="Pediatrician">Pediatrician: Child health, vaccination, development issues</option>
                            <option value="Orthopedist">Orthopedist: Bones, fractures, arthritis, joint pain</option>
                            <option value="Gastroenterologist">Gastroenterologist: Stomach, digestion, ulcers, IBS, liver issues</option>
                            <option value="Endocrinologist">Endocrinologist: Hormonal imbalance, thyroid, diabetes</option>
                            <option value="Urologist">Urologist: Urinary tract, kidney stones, bladder issues</option>
                            <option value="Oncologist">Oncologist: Cancer, tumors, chemotherapy</option>
                            <option value="Psychiatrist">Psychiatrist: Mental health, depression, anxiety, PTSD</option>
                            <option value="Rheumatologist">Rheumatologist: Arthritis, autoimmune disorders, chronic pain</option>
                            <option value="Ophthalmologist">Ophthalmologist: Eyes, vision problems, cataracts</option>
                            <option value="ENT Specialist">ENT Specialist: Ear, nose, throat, sinusitis, hearing loss</option>
                            <option value="Nephrologist">Nephrologist: Kidney, dialysis, nephritis</option>
                            <option value="Surgeon">Surgeon: Surgeries, wounds, hernia</option>
                            <option value="Gynecologist">Gynecologist: Women's health, pregnancy, menstrual disorders</option>
                        </select>
                    </div>

                    <div class="form-group">
                        <label for="problem_description">Problem Description</label>
                        <textarea name="problem_description" id="problem_description" placeholder="Describe your symptoms and health concerns in detail..." required></textarea>
                    </div>

                    <div class="form-group">
                        <label for="current_medication">Current Medication</label>
                        <textarea name="current_medication" id="current_medication" placeholder="List any medications you are currently taking..." required></textarea>
                    </div>
                </div>

                <!-- Hospital Selection Section -->
                <div class="form-section">
                    <h2 class="section-title">Hospital Selection</h2>
                    
                    <div class="form-group">
                        <label for="hospital_search">Search Hospital</label>
                        <div class="hospital-search-container">
                            <input type="text" name="hospital_search" id="hospital_search" placeholder="Search by hospital name or zip code">
                            <input type="hidden" name="hospital_id" id="hospital_id">
                            <div id="hospital_list" style="display: none;"></div>
                        </div>
                        <div id="registration_message"></div>
                    </div>
                </div>

                <!-- Media Upload Section -->
                <div class="form-section">
                    <h2 class="section-title">Additional Information</h2>
                    
                    <div class="form-group">
                        <label for="video">Upload Video (Optional)</label>
                        <div class="file-input-container">
                            <label class="file-input-label" for="video">
                                <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                    <polyline points="17 8 12 3 7 8"></polyline>
                                    <line x1="12" y1="3" x2="12" y2="15"></line>
                                </svg>
                                Choose Video File
                            </label>
                            <input type="file" name="video" id="video" accept="video/*">
                        </div>
                        <div class="file-name" id="video_file_name">No file chosen</div>
                        <small>Max 50MB. Allowed: MP4, AVI, MOV, WMV, WEBM</small>
                    </div>
                </div>

                <!-- AI Solution Section -->
                <div class="form-section">
                    <h2 class="section-title">AI Generated Solution</h2>
                    
                    <div class="caution">
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 5px; vertical-align: -3px;">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            <line x1="12" y1="9" x2="12" y2="13"></line>
                            <line x1="12" y1="17" x2="12.01" y2="17"></line>
                        </svg>
                        Caution: Use for minor problems. AI can make mistakes.
                    </div>
                    
                    <div class="language-select-container">
                        <label for="language">Select Language:</label>
                        <select id="language">
                            <option value="en" selected>English</option>
                            <option value="hi">Hindi</option>
                            <option value="kn">Kannada</option>
                            <option value="ta">Tamil</option>
                            <option value="te">Telugu</option>
                            <option value="bn">Bengali</option>
                            <option value="gu">Gujarati</option>
                        </select>
                        <button type="button" id="generate_solution" class="btn">Get AI Generated Solution</button>
                    </div>
                    
                    <div class="ai-solution" id="ai_solution_display">
                        <p style="color: #64748b; font-size: 1.125rem;">Hello, I am Sana, your personal health care assistant.</p>
                        <div class="suggestion-list" id="suggestion_list">
                            <!-- Initial 10 suggestions will be loaded here -->
                        </div>
                        <button type="button" id="show_more_suggestions" class="show-more-btn" style="display: none;">Show More Questions</button>
                    </div>
                    
                    <div class="audio-controls">
                        <button type="button" id="play_audio" style="display:none;">
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
                                <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path>
                            </svg>
                            Play Audio
                        </button>
                        <audio id="audio_player" style="display:none;" controls></audio>
                    </div>
                </div>

                <!-- Quick Image Analysis Section -->
                <div class="form-section">
                    <div class="image-analysis-section">
                        <h2 class="image-analysis-title">🔍 Quickly Identify Your Disease</h2>
                        <p class="image-analysis-subtitle">Please upload your image and get immediate results</p>
                        
                        <div class="image-upload-area">
                            <label for="analysis_image" class="image-upload-label">
                                <div class="upload-icon">📷</div>
                                <p>Click to upload image or drag and drop</p>
                                <small>Supports JPEG, PNG (Max 10MB)</small>
                            </label>
                            <input type="file" id="analysis_image" accept="image/jpeg,image/jpg,image/png">
                        </div>
                        
                        <div class="image-analysis-controls">
                            <select id="image_language" class="image-language-select">
                                <option value="en">English</option>
                                <option value="hi">Hindi</option>
                                <option value="kn">Kannada</option>
                                <option value="ta">Tamil</option>
                                <option value="te">Telugu</option>
                                <option value="bn">Bengali</option>
                                <option value="gu">Gujarati</option>
                            </select>
                            <button type="button" id="analyze_image_btn" class="analyze-btn">Analyze Image</button>
                        </div>
                        
                        <div id="image_analysis_result" class="image-analysis-result">
                            <div id="image_analysis_text"></div>
                            <div id="api_status_indicator"></div>
                            <div class="audio-controls">
                                <button type="button" class="play_image_audio" id="play_image_audio" style="display:none;">
                                    🔊 Play Audio
                                </button>
                                <audio id="image_audio_player" style="display:none;" controls></audio>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Submit Button -->
                <div class="submit-container">
                    <input type="submit" value="Submit Problem" class="submit-btn">
                </div>
            </form>
        </div>
    </div>

    <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
    <script>
        const csrfToken = document.getElementById('csrf_token').value;
        
        // 20 Common Patient Questions
        const patientQuestions = [
            "What are the causes of fever?",
            "How much water should I drink daily?",
            "I had a fever of 100°F since yesterday, I drank cold drink, what should I do?",
            "What are the symptoms of dehydration?",
            "Is it safe to exercise with a mild cold?",
            "How can I reduce my blood pressure naturally?",
            "What foods should I avoid with diabetes?",
            "How long should I rest after surgery?",
            "What are the side effects of common pain medications?",
            "How do I know if my wound is healing properly?",
            "What should I do if I have chest pain?",
            "How can I improve my sleep quality?",
            "What are the warning signs of a heart attack?",
            "How do I manage stress and anxiety?",
            "What vaccinations do I need as an adult?",
            "How can I boost my immune system?",
            "What should I eat to recover from illness faster?",
            "How do I know if I need to see a specialist?",
            "What are the symptoms of common allergies?",
            "How can I prevent kidney stones?"
        ];

        // Pagination state
        const suggestionsPerPage = 5;
        let currentSuggestionPage = 1;
        const totalSuggestionPages = Math.ceil(patientQuestions.length / suggestionsPerPage);

        // Render paginated suggestions
        function renderSuggestionPage(page) {
            const suggestionList = document.getElementById('suggestion_list');
            suggestionList.innerHTML = '';
            const startIdx = (page - 1) * suggestionsPerPage;
            const endIdx = Math.min(startIdx + suggestionsPerPage, patientQuestions.length);

            for (let i = startIdx; i < endIdx; i++) {
                const suggestionDiv = document.createElement('div');
                suggestionDiv.className = 'suggestion-item';
                suggestionDiv.innerHTML = `
                    <input type="text" readonly value="${i + 1}. ${patientQuestions[i]}" style="width: 90%; border: none; background: #f5f5f5; color: #333; font-size: 1.125rem; padding: 6px 10px; border-radius: 4px; margin-right: 8px;">
                    <button type="button" class="copy-suggestion" data-suggestion="${patientQuestions[i]}" style="padding: 4px 10px; font-size: 1rem; border-radius: 4px; border: 1px solid #ccc; background: #fff; cursor: pointer;">Copy</button>
                `;
                suggestionList.appendChild(suggestionDiv);
            }

            // Add event listeners for copy buttons
            document.querySelectorAll('.copy-suggestion').forEach(function(btn) {
                btn.addEventListener('click', function() {
                    const text = this.getAttribute('data-suggestion');
                    document.getElementById('problem_description').value = text;
                    this.textContent = 'Copied!';
                    setTimeout(() => { this.textContent = 'Copy'; }, 1200);
                });
            });

            // Update pagination controls
            updateSuggestionPaginationControls();
        }

        // Create pagination controls if not present
        function createSuggestionPaginationControls() {
            let controls = document.getElementById('suggestion_pagination_controls');
            if (!controls) {
                controls = document.createElement('div');
                controls.id = 'suggestion_pagination_controls';
                controls.style = 'display: flex; justify-content: center; align-items: center; gap: 12px; margin-top: 10px;';
                controls.innerHTML = `
                    <button type="button" id="suggestion_prev_btn" class="show-more-btn">Previous</button>
                    <span id="suggestion_page_info" style="font-size:1rem;"></span>
                    <button type="button" id="suggestion_next_btn" class="show-more-btn">Next</button>
                `;
                document.getElementById('ai_solution_display').appendChild(controls);
            }
            // Attach event listeners
            document.getElementById('suggestion_prev_btn').onclick = function() {
                if (currentSuggestionPage > 1) {
                    currentSuggestionPage--;
                    renderSuggestionPage(currentSuggestionPage);
                }
            };
            document.getElementById('suggestion_next_btn').onclick = function() {
                if (currentSuggestionPage < totalSuggestionPages) {
                    currentSuggestionPage++;
                    renderSuggestionPage(currentSuggestionPage);
                }
            };
        }

        // Update pagination controls state
        function updateSuggestionPaginationControls() {
            createSuggestionPaginationControls();
            document.getElementById('suggestion_page_info').textContent =
                `Page ${currentSuggestionPage} of ${totalSuggestionPages}`;
            document.getElementById('suggestion_prev_btn').disabled = (currentSuggestionPage === 1);
            document.getElementById('suggestion_next_btn').disabled = (currentSuggestionPage === totalSuggestionPages);
        }

        // Initialize on page load
        renderSuggestionPage(currentSuggestionPage);

        // Updated Loading Animation System - No Progress Bar, Messages Cycle Once
        function createLoadingAnimation(containerId, messages) {
            const container = document.getElementById(containerId);
            let messageIndex = 0;
            let seconds = 0;
            let messageInterval, timerInterval;
            
            // Only loader (spinner) and loading message - NO PROGRESS BAR
            const loadingHTML = `
                <div class="loading-container">
                    <div class="loading-spinner"></div>
                    <div class="loading-message" id="${containerId}_message">${messages[0]}</div>
                    <div class="loading-timer" id="${containerId}_timer">0 seconds</div>
                </div>
            `;
            
            container.innerHTML = loadingHTML;
            
            // Cycle through messages ONCE, then stop at last message until response
            messageInterval = setInterval(() => {
                if (messageIndex < messages.length - 1) {
                    messageIndex++;
                    const messageElement = document.getElementById(`${containerId}_message`);
                    if (messageElement) {
                        messageElement.textContent = messages[messageIndex];
                    }
                } else {
                    clearInterval(messageInterval); // Stop cycling messages
                }
            }, 6000);
            
            // Update timer every second
            timerInterval = setInterval(() => {
                seconds++;
                const timerElement = document.getElementById(`${containerId}_timer`);
                if (timerElement) {
                    timerElement.textContent = `${seconds} seconds, please be patient — this may take some time.`;
                }
            }, 1000);
            
            // Return cleanup function
            return function cleanup() {
                if (messageInterval) clearInterval(messageInterval);
                if (timerInterval) clearInterval(timerInterval);
            };
        }

        // File upload handlers
        document.getElementById('video').addEventListener('change', function() {
            const fileName = this.files[0] ? this.files[0].name : 'No file chosen';
            document.getElementById('video_file_name').textContent = fileName;
        });

        // Enhanced Image Analysis with Loading Animation
        document.getElementById('analyze_image_btn').addEventListener('click', function() {
            const imageInput = document.getElementById('analysis_image');
            const language = document.getElementById('image_language').value;
            const resultDiv = document.getElementById('image_analysis_result');
            const textDiv = document.getElementById('image_analysis_text');
            const statusDiv = document.getElementById('api_status_indicator');
            const playButton = document.getElementById('play_image_audio');
            const audioPlayer = document.getElementById('image_audio_player');

            if (!imageInput || !imageInput.files || imageInput.files.length === 0) {
                alert('Please select an image file first');
                return;
            }

            const imageFile = imageInput.files[0];
            
            // Show loading animation
            resultDiv.style.display = 'block';
            const loadingMessages = [
                "Analyzing your query...",
                "Preparing the best solution for you...",
                "Checking patient records carefully...",
                "Consulting the best available advice...",
                "Getting result..."
            ];
            
            const cleanupLoading = createLoadingAnimation('image_analysis_text', loadingMessages);
            statusDiv.innerHTML = '';
            if (playButton) playButton.style.display = 'none';
            if (audioPlayer) audioPlayer.style.display = 'none';

            const formData = new FormData();
            formData.append('analysis_image', imageFile);
            formData.append('image_language', language);
            formData.append('image_analysis', '1');
            formData.append('csrf_token', csrfToken);

            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                cleanupLoading(); // Clean up loading animation
                
                if (data.success) {
                    textDiv.innerHTML = data.analysis.replace(/\n/g, '<br>');
                    
                    const languageNames = {
                        'en': 'English', 'hi': 'Hindi', 'kn': 'Kannada',
                        'ta': 'Tamil', 'te': 'Telugu', 'bn': 'Bengali', 'gu': 'Gujarati'
                    };
                    
                    const languageName = languageNames[data.language] || data.language;
                    statusDiv.innerHTML = `<div class="api-status api-success">✅ Generated Successfully <span class="language-indicator">${languageName}</span></div>`;
                    
                    if (data.audio_url && audioPlayer && playButton) {
                        audioPlayer.src = data.audio_url;
                        audioPlayer.style.display = 'block';
                        playButton.style.display = 'inline-block';
                        playButton.onclick = () => audioPlayer.play();
                    }
                } else {
                    textDiv.innerHTML = `<p style="color: #ef4444;">❌ Error: ${data.error}</p>`;
                    statusDiv.innerHTML = '<div class="api-status api-error">❌ PythonAnywhere API Error</div>';
                }
            })
            .catch(error => {
                cleanupLoading(); // Clean up loading animation
                console.error('Error:', error);
                textDiv.innerHTML = '<p style="color: #ef4444;">❌ Error occurred while analyzing image</p>';
                statusDiv.innerHTML = '<div class="api-status api-error">❌ Network error</div>';
            });
        });

        // Enhanced Hospital Search with debouncing
        let searchTimeout;
        function searchHospital() {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(() => {
                let query = $('#hospital_search').val().trim();
                if (query.length >= 2) {
                    $.ajax({
                        url: '',
                        method: 'GET',
                        data: { 
                            query: query,
                            csrf_token: csrfToken
                        },
                        success: function(response) {
                            $('#hospital_list').html(response).show();
                            $('.hospital-option').click(function() {
                                let hospital_id = $(this).data('id');
                                let registration_fee = $(this).data('fee');
                                $('#hospital_search').val($(this).text());
                                $('#hospital_id').val(hospital_id);
                                $('#hospital_list').hide();
                                checkRegistrationStatus(hospital_id, registration_fee);
                            });
                        },
                        error: function() {
                            $('#hospital_list').html('<div style="padding:10px; font-size: 1.125rem;">Error retrieving hospitals</div>').show();
                        }
                    });
                } else {
                    $('#hospital_list').hide();
                }
            }, 300); // 300ms debounce
        }

        $('#hospital_search').on('keyup input', searchHospital);

        function checkRegistrationStatus(hospital_id, registration_fee) {
            $.ajax({
                url: '',
                method: 'POST',
                data: { 
                    hospital_id: hospital_id,
                    csrf_token: csrfToken
                },
                success: function(response) {
                    $('#registration_message').html(response);
                },
                error: function() {
                    $('#registration_message').html('<p style="color: #ef4444; font-size: 1.125rem;">Error checking registration status</p>');
                }
            });
        }

        $(document).click(function(event) {
            if (!$(event.target).closest('#hospital_search, #hospital_list').length) {
                $('#hospital_list').hide();
            }
        });

        // Enhanced AI Solution Generation with Loading Animation
        $('#generate_solution').click(function() {
            let problem_description = $('#problem_description').val().trim();
            let language = $('#language').val();
            
            if (problem_description === '') {
                alert('Please enter a problem description first');
                return;
            }
            
            $(this).prop('disabled', true);
            
            // Show loading animation
            const loadingMessages = [
                "Analyzing your query...",
                "Preparing the best solution for you...",
                "Checking patient records carefully...",
                "Consulting the best available advice...",
                "Getting result..."
            ];
            
            const cleanupLoading = createLoadingAnimation('ai_solution_display', loadingMessages);
            
            $.ajax({
                url: '',
                method: 'POST',
                data: {
                    problem_description: problem_description,
                    language: language,
                    csrf_token: csrfToken
                },
                dataType: 'json',
                success: function(response) {
                    cleanupLoading(); // Clean up loading animation
                    
                    if (response.solution) {
                        $('#ai_solution_display').html(response.solution.replace(/\n/g, '<br>'));
                        
                        if (response.audio_path && response.audio_path !== '') {
                            $('#audio_player').attr('src', response.audio_path).show();
                            $('#play_audio').show().click(function() {
                                document.getElementById('audio_player').play();
                            });
                        }
                    } else if (response.error) {
                        $('#ai_solution_display').html('<p style="color: #ef4444;">Error: ' + response.error + '</p>');
                    }
                },
                error: function(xhr, status, error) {
                    cleanupLoading(); // Clean up loading animation
                    $('#ai_solution_display').html('<p style="color: #ef4444;">Error generating solution. Please try again.</p>');
                    console.error('AJAX Error:', error);
                },
                complete: function() {
                    $('#generate_solution').prop('disabled', false);
                }
            });
        });

        // Form validation
        $('form').submit(function(e) {
            let hospital_id = $('#hospital_id').val();
            if (!hospital_id) {
                e.preventDefault();
                alert('Please select a hospital before submitting');
                return false;
            }
        });

        // Enhanced drag and drop functionality
        const imageUploadArea = document.querySelector('.image-upload-area');
        const imageInput = document.getElementById('analysis_image');

        if (imageUploadArea && imageInput) {
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
                imageUploadArea.addEventListener(eventName, preventDefaults, false);
            });

            function preventDefaults(e) {
                e.preventDefault();
                e.stopPropagation();
            }

            ['dragenter', 'dragover'].forEach(eventName => {
                imageUploadArea.addEventListener(eventName, highlight, false);
            });

            ['dragleave', 'drop'].forEach(eventName => {
                imageUploadArea.addEventListener(eventName, unhighlight, false);
            });

            function highlight(e) {
                imageUploadArea.style.backgroundColor = 'rgba(74, 111, 255, 0.2)';
            }

            function unhighlight(e) {
                imageUploadArea.style.backgroundColor = '';
            }

            imageUploadArea.addEventListener('drop', handleDrop, false);

            function handleDrop(e) {
                const dt = e.dataTransfer;
                const files = dt.files;
                
                if (files.length > 0) {
                    const file = files[0];
                    if (file.type.startsWith('image/')) {
                        imageInput.files = files;
                        updateFileName(file.name);
                    } else {
                        alert('Please upload only image files (JPEG, PNG)');
                    }
                }
            }

            imageInput.addEventListener('change', function() {
                if (this.files && this.files[0]) {
                    updateFileName(this.files[0].name);
                }
            });

            function updateFileName(fileName) {
                const uploadLabel = imageUploadArea.querySelector('.image-upload-label p');
                if (uploadLabel) {
                    uploadLabel.textContent = `Selected: ${fileName}`;
                }
            }
        }

        // Auto-resize textareas
        function autoResize(textarea) {
            textarea.style.height = 'auto';
            textarea.style.height = textarea.scrollHeight + 'px';
        }

        document.querySelectorAll('textarea').forEach(function(textarea) {
            textarea.addEventListener('input', function() {
                autoResize(this);
            });
            autoResize(textarea); // Initial resize
        });

        // Enhanced file validation
        function validateFile(file, maxSize, allowedTypes) {
            if (file.size > maxSize) {
                return `File size too large. Maximum ${Math.round(maxSize / (1024 * 1024))}MB allowed.`;
            }
            
            if (!allowedTypes.includes(file.type)) {
                return `Invalid file type. Allowed types: ${allowedTypes.join(', ')}`;
            }
            
            return null;
        }

        // Video file validation
        $('#video').change(function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                const maxSize = 50 * 1024 * 1024; // 50MB
                const allowedTypes = ['video/mp4', 'video/avi', 'video/mov', 'video/wmv', 'video/webm'];
                
                const error = validateFile(file, maxSize, allowedTypes);
                if (error) {
                    alert(error);
                    this.value = '';
                    $('#video_file_name').text('No file chosen');
                    return;
                }
                
                $('#video_file_name').text(file.name);
            }
        });

        // Image file validation for analysis
        $('#analysis_image').change(function() {
            if (this.files && this.files[0]) {
                const file = this.files[0];
                const maxSize = 10 * 1024 * 1024; // 10MB
                const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
                
                const error = validateFile(file, maxSize, allowedTypes);
                if (error) {
                    alert(error);
                    this.value = '';
                    return;
                }
            }
        });

        // Form auto-save functionality
        let autoSaveTimer;
        function autoSaveForm() {
            const formData = {
                problem_description: $('#problem_description').val(),
                current_medication: $('#current_medication').val(),
                specialization: $('#specialization').val()
            };
            
            localStorage.setItem('medical_form_draft', JSON.stringify(formData));
        }

        $('#problem_description, #current_medication, #specialization').on('input change', function() {
            clearTimeout(autoSaveTimer);
            autoSaveTimer = setTimeout(autoSaveForm, 30000);
        });

        // Load saved draft on page load
        $(document).ready(function() {
            const savedDraft = localStorage.getItem('medical_form_draft');
            if (savedDraft) {
                try {
                    const formData = JSON.parse(savedDraft);
                    if (confirm('Would you like to restore your previously saved draft?')) {
                        $('#problem_description').val(formData.problem_description || '');
                        $('#current_medication').val(formData.current_medication || '');
                        $('#specialization').val(formData.specialization || '');
                        
                        document.querySelectorAll('textarea').forEach(autoResize);
                    }
                } catch (e) {
                    console.error('Error loading saved draft:', e);
                }
            }
        });

        // Clear draft after successful submission
        $('form').on('submit', function() {
            localStorage.removeItem('medical_form_draft');
        });

        // Prevent form submission on Enter key in search fields
        $('#hospital_search').keypress(function(e) {
            if (e.which === 13) {
                e.preventDefault();
                return false;
            }
        });

        // Clear hospital selection when search is cleared
        $('#hospital_search').on('input', function() {
            if ($(this).val().trim() === '') {
                $('#hospital_id').val('');
                $('#registration_message').html('');
                $('#hospital_list').hide();
            }
        });

        // Enhanced error handling
        $(document).ajaxError(function(event, xhr, settings, thrownError) {
            console.error('AJAX Error:', {
                url: settings.url,
                status: xhr.status,
                error: thrownError,
                response: xhr.responseText
            });
        });
</script>
</body>
</html>