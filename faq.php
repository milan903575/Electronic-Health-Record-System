<?php
session_start();
include 'connection.php';

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
                'style-src' => ["'self'", "'unsafe-inline'"],
                'img-src' => ["'self'", 'data:', 'https:'],
                'font-src' => ["'self'"],
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
            'script-src' => ["'self'", "'unsafe-inline'"],
            'style-src' => ["'self'", "'unsafe-inline'"],
            'img-src' => ["'self'", 'data:', 'https:'],
            'font-src' => ["'self'"],
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

// Check if user is authenticated
if (!isset($_SESSION['user_id']) || !isset($_SESSION['user_type'])) {
    header('Location: logout.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$user_type = $_SESSION['user_type'];

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
    
    // Handle different actions
    if (isset($_POST['action'])) {
        switch ($_POST['action']) {
            case 'ask_question':
                handleAskQuestion($conn, $user_id, $user_type);
                break;
            case 'provide_answer':
                handleProvideAnswer($conn, $user_id, $user_type);
                break;
            case 'rate_faq':
                handleRating($conn, $user_id, $user_type);
                break;
            case 'update_status':
                handleStatusUpdate($conn, $user_id, $user_type);
                break;
        }
    }
}

// Function to handle file upload
function handleFileUpload($file) {
    if (!isset($file) || $file['error'] !== UPLOAD_ERR_OK) {
        return null;
    }
    
    $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'];
    $max_size = 5 * 1024 * 1024; // 5MB
    
    if (!in_array($file['type'], $allowed_types)) {
        throw new Exception('Invalid file type');
    }
    
    if ($file['size'] > $max_size) {
        throw new Exception('File size too large');
    }
    
    $upload_dir = 'uploads/';
    if (!is_dir($upload_dir)) {
        mkdir($upload_dir, 0755, true);
    }
    
    $filename = uniqid() . '_' . preg_replace('/[^a-zA-Z0-9._-]/', '', $file['name']);
    $filepath = $upload_dir . $filename;
    
    if (move_uploaded_file($file['tmp_name'], $filepath)) {
        return ['filename' => $filename, 'type' => $file['type']];
    }
    
    return null;
}

// Function to handle asking questions
function handleAskQuestion($conn, $user_id, $user_type) {
    $question = trim($_POST['question']);
    $category = trim($_POST['category']);
    
    if (empty($question)) {
        return;
    }
    
    $attachment = null;
    $attachment_type = null;
    
    if (isset($_FILES['attachment'])) {
        try {
            $upload_result = handleFileUpload($_FILES['attachment']);
            if ($upload_result) {
                $attachment = $upload_result['filename'];
                $attachment_type = $upload_result['type'];
            }
        } catch (Exception $e) {
            echo "<script>showNotification('File upload error: " . $e->getMessage() . "', 'error');</script>";
            return;
        }
    }
    
    $stmt = $conn->prepare("INSERT INTO faq (user_id, user_type, question, category, attachment, attachment_type) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("isssss", $user_id, $user_type, $question, $category, $attachment, $attachment_type);
    
    if ($stmt->execute()) {
        $faq_id = $conn->insert_id;
        
        // Create conversion tracking entry
        $conv_stmt = $conn->prepare("INSERT INTO faq_conversion (faq_id) VALUES (?)");
        $conv_stmt->bind_param("i", $faq_id);
        $conv_stmt->execute();
        
        echo "<script>showNotification('Question posted successfully!', 'success');</script>";
    }
}

// Function to handle providing answers
function handleProvideAnswer($conn, $user_id, $user_type) {
    $faq_id = intval($_POST['faq_id']);
    $answer = trim($_POST['answer']);
    
    if (empty($answer)) {
        return;
    }
    
    $attachment = null;
    $attachment_type = null;
    
    if (isset($_FILES['answer_attachment'])) {
        try {
            $upload_result = handleFileUpload($_FILES['answer_attachment']);
            if ($upload_result) {
                $attachment = $upload_result['filename'];
                $attachment_type = $upload_result['type'];
            }
        } catch (Exception $e) {
            echo "<script>showNotification('File upload error: " . $e->getMessage() . "', 'error');</script>";
            return;
        }
    }
    
    $stmt = $conn->prepare("INSERT INTO faq (user_id, user_type, parent_id, answer, attachment, attachment_type) VALUES (?, ?, ?, ?, ?, ?)");
    $stmt->bind_param("isisss", $user_id, $user_type, $faq_id, $answer, $attachment, $attachment_type);
    
    if ($stmt->execute()) {
        echo "<script>showNotification('Answer posted successfully!', 'success');</script>";
    }
}

// Function to handle rating
function handleRating($conn, $user_id, $user_type) {
    $faq_id = intval($_POST['faq_id']);
    $rating = $_POST['rating'];
    
    if (!in_array($rating, ['like', 'dislike'])) {
        return;
    }
    
    $stmt = $conn->prepare("INSERT INTO faq_rating (faq_id, user_id, user_type, rating) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE rating = VALUES(rating)");
    $stmt->bind_param("iiss", $faq_id, $user_id, $user_type, $rating);
    $stmt->execute();
    
    echo "<script>showNotification('Rating updated!', 'success');</script>";
}

// Function to handle status updates
function handleStatusUpdate($conn, $user_id, $user_type) {
    $faq_id = intval($_POST['faq_id']);
    $status = $_POST['status'];
    $notes = trim($_POST['notes']);
    
    if (!in_array($status, ['pending', 'resolved', 'closed'])) {
        return;
    }
    
    $resolved_at = ($status === 'resolved') ? date('Y-m-d H:i:s') : null;
    $resolved_by_user_id = ($status === 'resolved') ? $user_id : null;
    $resolved_by_user_type = ($status === 'resolved') ? $user_type : null;
    
    $stmt = $conn->prepare("UPDATE faq_conversion SET status = ?, resolved_by_user_id = ?, resolved_by_user_type = ?, resolved_at = ?, notes = ? WHERE faq_id = ?");
    $stmt->bind_param("sisssi", $status, $resolved_by_user_id, $resolved_by_user_type, $resolved_at, $notes, $faq_id);
    $stmt->execute();
    
    echo "<script>showNotification('Status updated successfully!', 'success');</script>";
}

// Get FAQ data with search and filter functionality
function getFAQData($conn, $search = '', $category_filter = '', $status_filter = '', $user_type_filter = '', $sort_by = 'created_at', $sort_order = 'DESC') {
    $where_conditions = ["f.parent_id IS NULL"];
    $params = [];
    $types = "";
    
    if (!empty($search)) {
        $where_conditions[] = "(f.question LIKE ? OR f.answer LIKE ?)";
        $search_param = "%$search%";
        $params[] = $search_param;
        $params[] = $search_param;
        $types .= "ss";
    }
    
    if (!empty($category_filter)) {
        $where_conditions[] = "f.category = ?";
        $params[] = $category_filter;
        $types .= "s";
    }
    
    if (!empty($status_filter)) {
        $where_conditions[] = "fc.status = ?";
        $params[] = $status_filter;
        $types .= "s";
    }
    
    if (!empty($user_type_filter)) {
        $where_conditions[] = "f.user_type = ?";
        $params[] = $user_type_filter;
        $types .= "s";
    }
    
    $where_clause = implode(" AND ", $where_conditions);
    
    $allowed_sort = ['created_at', 'likes', 'answer_count'];
    $allowed_order = ['ASC', 'DESC'];
    
    if (!in_array($sort_by, $allowed_sort)) $sort_by = 'created_at';
    if (!in_array($sort_order, $allowed_order)) $sort_order = 'DESC';
    
    $sql = "SELECT f.*, fc.status, fc.resolved_at, fc.notes,
                   (SELECT COUNT(*) FROM faq_rating fr WHERE fr.faq_id = f.id AND fr.rating = 'like') as likes,
                   (SELECT COUNT(*) FROM faq_rating fr WHERE fr.faq_id = f.id AND fr.rating = 'dislike') as dislikes,
                   (SELECT COUNT(*) FROM faq WHERE parent_id = f.id) as answer_count
            FROM faq f 
            LEFT JOIN faq_conversion fc ON f.id = fc.faq_id 
            WHERE $where_clause
            ORDER BY $sort_by $sort_order";
    
    if (!empty($params)) {
        $stmt = $conn->prepare($sql);
        $stmt->bind_param($types, ...$params);
        $stmt->execute();
        return $stmt->get_result();
    } else {
        return $conn->query($sql);
    }
}

// Get answers for a specific FAQ
function getAnswers($conn, $faq_id) {
    $stmt = $conn->prepare("SELECT f.*, 
                                  (SELECT COUNT(*) FROM faq_rating fr WHERE fr.faq_id = f.id AND fr.rating = 'like') as likes,
                                  (SELECT COUNT(*) FROM faq_rating fr WHERE fr.faq_id = f.id AND fr.rating = 'dislike') as dislikes
                           FROM faq f 
                           WHERE f.parent_id = ? 
                           ORDER BY f.created_at ASC");
    $stmt->bind_param("i", $faq_id);
    $stmt->execute();
    return $stmt->get_result();
}

// Get filter parameters
$search = isset($_GET['search']) ? trim($_GET['search']) : '';
$category_filter = isset($_GET['category']) ? $_GET['category'] : '';
$status_filter = isset($_GET['status']) ? $_GET['status'] : '';
$user_type_filter = isset($_GET['user_type']) ? $_GET['user_type'] : '';
$sort_by = isset($_GET['sort_by']) ? $_GET['sort_by'] : 'created_at';
$sort_order = isset($_GET['sort_order']) ? $_GET['sort_order'] : 'DESC';

$faqs = getFAQData($conn, $search, $category_filter, $status_filter, $user_type_filter, $sort_by, $sort_order);

// Get categories for filter dropdown
$categories_result = $conn->query("SELECT DISTINCT category FROM faq WHERE category IS NOT NULL AND category != '' ORDER BY category");
$categories = [];
while ($row = $categories_result->fetch_assoc()) {
    $categories[] = $row['category'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Enhanced FAQ System - Sky Blue Edition</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            /* Enhanced Sky Blue Theme Colors - Perfect Contrast */
            --primary-color: #0284c7;
            --primary-light: #0ea5e9;
            --primary-dark: #0369a1;
            --primary-darker: #075985;
            --secondary-color: #e0f2fe;
            --accent-color: #06b6d4;
            --accent-light: #22d3ee;
            
            /* Success, Warning, Danger Colors */
            --success-color: #059669;
            --success-light: #10b981;
            --warning-color: #d97706;
            --warning-light: #f59e0b;
            --danger-color: #dc2626;
            --danger-light: #ef4444;
            --info-color: #2563eb;
            --info-light: #3b82f6;
            
            /* Background Colors - Enhanced Contrast */
            --bg-primary: #f0f9ff;
            --bg-secondary: #e0f2fe;
            --bg-tertiary: #bae6fd;
            --bg-card: #ffffff;
            --bg-card-hover: #fefefe;
            --bg-overlay: rgba(14, 165, 233, 0.03);
            --bg-input: #ffffff;
            --bg-input-focus: #ffffff;
            --bg-answer: #fafbfc;
            --bg-answer-hover: #f1f5f9;
            
            /* Text Colors - High Contrast */
            --text-primary: #0f172a;
            --text-secondary: #1e293b;
            --text-tertiary: #334155;
            --text-muted: #475569;
            --text-light: #64748b;
            --text-white: #ffffff;
            --text-on-primary: #ffffff;
            --text-on-secondary: #0f172a;
            
            /* Border Colors */
            --border-color: #cbd5e1;
            --border-light: #e2e8f0;
            --border-lighter: #f1f5f9;
            --border-focus: #0ea5e9;
            --border-error: #ef4444;
            --border-success: #10b981;
            
            /* Shadow System */
            --shadow-xs: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
            --shadow-sm: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
            --shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-md: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
            --shadow-xl: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
            --shadow-2xl: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
            --shadow-inner: inset 0 2px 4px 0 rgba(0, 0, 0, 0.06);
            
            /* Border Radius System */
            --radius-xs: 4px;
            --radius-sm: 6px;
            --radius: 8px;
            --radius-md: 12px;
            --radius-lg: 16px;
            --radius-xl: 20px;
            --radius-2xl: 24px;
            --radius-full: 9999px;
            
            /* Transitions */
            --transition-fast: all 0.15s ease-out;
            --transition: all 0.25s ease-out;
            --transition-slow: all 0.35s ease-out;
            
            /* Spacing System */
            --space-1: 0.25rem;
            --space-2: 0.5rem;
            --space-3: 0.75rem;
            --space-4: 1rem;
            --space-5: 1.25rem;
            --space-6: 1.5rem;
            --space-8: 2rem;
            --space-10: 2.5rem;
            --space-12: 3rem;
            --space-16: 4rem;
            --space-20: 5rem;
            
            /* Typography Scale */
            --text-xs: 0.75rem;
            --text-sm: 0.875rem;
            --text-base: 1rem;
            --text-lg: 1.125rem;
            --text-xl: 1.25rem;
            --text-2xl: 1.5rem;
            --text-3xl: 1.875rem;
            --text-4xl: 2.25rem;
            --text-5xl: 3rem;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, var(--bg-primary) 0%, var(--bg-secondary) 50%, var(--bg-tertiary) 100%);
            min-height: 100vh;
            color: var(--text-primary);
            line-height: 1.6;
            font-weight: 400;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
            font-size: var(--text-base);
        }

        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: var(--space-8);
        }

        /* Enhanced Header */
        .header {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-2xl);
            padding: var(--space-12);
            margin-bottom: var(--space-8);
            box-shadow: var(--shadow-xl);
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .header::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color), var(--primary-light));
            border-radius: var(--radius-2xl) var(--radius-2xl) 0 0;
        }

        .header h1 {
            font-size: var(--text-4xl);
            font-weight: 800;
            background: linear-gradient(135deg, var(--primary-color), var(--accent-color));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: var(--space-4);
            letter-spacing: -0.025em;
            line-height: 1.2;
        }

        .user-info {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            background: var(--bg-secondary);
            color: var(--text-secondary);
            padding: var(--space-3) var(--space-6);
            border-radius: var(--radius-full);
            font-weight: 600;
            font-size: var(--text-sm);
            border: 1px solid var(--border-light);
            box-shadow: var(--shadow-sm);
        }

        .user-info i {
            color: var(--primary-color);
            font-size: var(--text-base);
        }

        /* Enhanced Search and Filter Section */
        .search-filter-section {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-2xl);
            padding: var(--space-8);
            margin-bottom: var(--space-8);
            box-shadow: var(--shadow-lg);
        }

        .search-bar {
            position: relative;
            margin-bottom: var(--space-6);
        }

        .search-input {
            width: 100%;
            padding: var(--space-4) var(--space-16) var(--space-4) var(--space-6);
            border: 2px solid var(--border-light);
            border-radius: var(--radius-full);
            font-size: var(--text-lg);
            font-weight: 400;
            transition: var(--transition);
            background: var(--bg-input);
            color: var(--text-primary);
            box-shadow: var(--shadow-sm);
        }

        .search-input:focus {
            outline: none;
            border-color: var(--border-focus);
            box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.1), var(--shadow-md);
            transform: translateY(-1px);
            background: var(--bg-input-focus);
        }

        .search-input::placeholder {
            color: var(--text-muted);
            font-weight: 400;
        }

        .search-icon {
            position: absolute;
            right: var(--space-6);
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-muted);
            cursor: pointer;
            font-size: var(--text-xl);
            transition: var(--transition);
            padding: var(--space-2);
            border-radius: var(--radius);
        }

        .search-icon:hover {
            color: var(--primary-color);
            background: var(--bg-overlay);
            transform: translateY(-50%) scale(1.05);
        }

        .filters-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: var(--space-5);
            margin-bottom: var(--space-6);
        }

        .filter-group {
            position: relative;
        }

        .filter-label {
            display: block;
            margin-bottom: var(--space-2);
            font-weight: 600;
            color: var(--text-secondary);
            font-size: var(--text-sm);
        }

        .filter-select {
            width: 100%;
            padding: var(--space-3) var(--space-4);
            border: 2px solid var(--border-light);
            border-radius: var(--radius-md);
            background: var(--bg-input);
            font-size: var(--text-base);
            font-weight: 500;
            color: var(--text-primary);
            transition: var(--transition);
            cursor: pointer;
            box-shadow: var(--shadow-xs);
        }

        .filter-select:focus {
            outline: none;
            border-color: var(--border-focus);
            box-shadow: 0 0 0 3px rgba(14, 165, 233, 0.1), var(--shadow-sm);
        }

        .filter-select:hover {
            border-color: var(--primary-light);
            background: var(--bg-card-hover);
        }

        .sort-controls {
            display: flex;
            gap: var(--space-4);
            align-items: center;
            justify-content: space-between;
            flex-wrap: wrap;
            padding-top: var(--space-6);
            border-top: 1px solid var(--border-lighter);
        }

        .results-count {
            color: var(--text-secondary);
            font-weight: 600;
            font-size: var(--text-base);
            display: flex;
            align-items: center;
            gap: var(--space-2);
        }

        .results-count i {
            color: var(--primary-color);
            font-size: var(--text-lg);
        }

        .clear-filters {
            background: var(--danger-color);
            color: var(--text-white);
            border: none;
            padding: var(--space-3) var(--space-5);
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: var(--text-sm);
            font-weight: 600;
            transition: var(--transition);
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            box-shadow: var(--shadow-sm);
        }

        .clear-filters:hover {
            background: var(--danger-light);
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        /* Enhanced Form Section */
        .form-section {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-2xl);
            padding: var(--space-8);
            margin-bottom: var(--space-8);
            box-shadow: var(--shadow-lg);
        }

        .form-section h2 {
            font-size: var(--text-2xl);
            font-weight: 700;
            margin-bottom: var(--space-6);
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: var(--space-3);
        }

        .form-section h2 i {
            color: var(--primary-color);
            font-size: var(--text-2xl);
        }

        .form-group {
            margin-bottom: var(--space-6);
        }

        .form-label {
            display: block;
            margin-bottom: var(--space-3);
            font-weight: 600;
            color: var(--text-primary);
            font-size: var(--text-base);
            display: flex;
            align-items: center;
            gap: var(--space-2);
        }

        .form-label i {
            color: var(--primary-color);
            font-size: var(--text-lg);
        }

        .form-input, .form-textarea, .form-select {
            width: 100%;
            padding: var(--space-4) var(--space-5);
            border: 2px solid var(--border-light);
            border-radius: var(--radius-md);
            font-size: var(--text-base);
            font-weight: 400;
            transition: var(--transition);
            background: var(--bg-input);
            color: var(--text-primary);
            box-shadow: var(--shadow-sm);
            font-family: inherit;
        }

        .form-input:focus, .form-textarea:focus, .form-select:focus {
            outline: none;
            border-color: var(--border-focus);
            box-shadow: 0 0 0 4px rgba(14, 165, 233, 0.1), var(--shadow-md);
            transform: translateY(-1px);
            background: var(--bg-input-focus);
        }

        .form-input::placeholder, .form-textarea::placeholder {
            color: var(--text-muted);
            font-weight: 400;
        }

        .form-textarea {
            resize: vertical;
            min-height: 140px;
            line-height: 1.6;
        }

        .file-input-wrapper {
            position: relative;
            display: block;
            width: 100%;
        }

        .file-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .file-input-display {
            display: flex;
            align-items: center;
            gap: var(--space-3);
            padding: var(--space-5);
            border: 2px dashed var(--border-color);
            border-radius: var(--radius-md);
            background: var(--bg-secondary);
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
            justify-content: center;
            color: var(--text-secondary);
        }

        .file-input-display:hover {
            border-color: var(--primary-color);
            background: rgba(14, 165, 233, 0.05);
            transform: translateY(-1px);
            color: var(--text-primary);
        }

        .file-input-display i {
            color: var(--primary-color);
            font-size: var(--text-2xl);
        }

        .file-input-display span {
            font-weight: 500;
            font-size: var(--text-base);
        }

        /* Enhanced Button Styles */
        .btn {
            display: inline-flex;
            align-items: center;
            gap: var(--space-2);
            padding: var(--space-3) var(--space-6);
            border: none;
            border-radius: var(--radius-md);
            font-size: var(--text-base);
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            text-decoration: none;
            font-family: inherit;
            box-shadow: var(--shadow-sm);
            position: relative;
            overflow: hidden;
            line-height: 1.5;
        }

        .btn::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
            transition: left 0.5s;
        }

        .btn:hover::before {
            left: 100%;
        }

        .btn-primary {
            background: linear-gradient(135deg, var(--primary-color), var(--primary-light));
            color: var(--text-on-primary);
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, var(--primary-dark), var(--primary-color));
            transform: translateY(-2px);
            box-shadow: var(--shadow-lg);
        }

        .btn-secondary {
            background: linear-gradient(135deg, var(--text-muted), var(--text-light));
            color: var(--text-white);
        }

        .btn-secondary:hover {
            background: linear-gradient(135deg, var(--text-tertiary), var(--text-muted));
            transform: translateY(-2px);
            box-shadow: var(--shadow-md);
        }

        /* Enhanced Like/Dislike Buttons */
        .btn-like {
            background: linear-gradient(135deg, var(--success-color), var(--success-light));
            color: var(--text-white);
            position: relative;
            overflow: hidden;
        }

        .btn-like:hover {
            background: linear-gradient(135deg, #047857, var(--success-color));
            transform: translateY(-2px) scale(1.05);
            box-shadow: var(--shadow-lg);
        }

        .btn-like.liked {
            background: linear-gradient(135deg, var(--success-light), #34d399);
            animation: likeAnimation 0.6s ease-out;
        }

        .btn-dislike {
            background: linear-gradient(135deg, var(--danger-color), var(--danger-light));
            color: var(--text-white);
            position: relative;
            overflow: hidden;
        }

        .btn-dislike:hover {
            background: linear-gradient(135deg, #b91c1c, var(--danger-color));
            transform: translateY(-2px) scale(1.05);
            box-shadow: var(--shadow-lg);
        }

        .btn-dislike.disliked {
            background: linear-gradient(135deg, var(--danger-light), #f87171);
            animation: dislikeAnimation 0.6s ease-out;
        }

        .btn-small {
            padding: var(--space-2) var(--space-4);
            font-size: var(--text-sm);
            font-weight: 500;
        }

        .btn-large {
            padding: var(--space-4) var(--space-8);
            font-size: var(--text-lg);
            font-weight: 600;
        }

        /* Beautiful Like/Dislike Animations */
        @keyframes likeAnimation {
            0% { transform: scale(1); }
            50% { transform: scale(1.2) rotate(10deg); }
            100% { transform: scale(1); }
        }

        @keyframes dislikeAnimation {
            0% { transform: scale(1); }
            50% { transform: scale(1.2) rotate(-10deg); }
            100% { transform: scale(1); }
        }

        @keyframes heartBeat {
            0%, 100% { transform: scale(1); }
            25% { transform: scale(1.1); }
            50% { transform: scale(1.2); }
            75% { transform: scale(1.1); }
        }

        @keyframes thumbsUp {
            0% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(-5px) rotate(15deg); }
            100% { transform: translateY(0) rotate(0deg); }
        }

        @keyframes thumbsDown {
            0% { transform: translateY(0) rotate(0deg); }
            50% { transform: translateY(5px) rotate(-15deg); }
            100% { transform: translateY(0) rotate(0deg); }
        }

        .btn-like:active i {
            animation: thumbsUp 0.3s ease-out;
        }

        .btn-dislike:active i {
            animation: thumbsDown 0.3s ease-out;
        }

        /* Ripple Effect for Buttons */
        .btn {
            position: relative;
            overflow: hidden;
        }

        .btn::after {
            content: '';
            position: absolute;
            top: 50%;
            left: 50%;
            width: 0;
            height: 0;
            border-radius: 50%;
            background: rgba(255, 255, 255, 0.3);
            transform: translate(-50%, -50%);
            transition: width 0.3s, height 0.3s;
        }

        .btn:active::after {
            width: 300px;
            height: 300px;
        }

        /* Enhanced FAQ Item Styles */
        .faq-item {
            background: var(--bg-card);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-2xl);
            margin-bottom: var(--space-8);
            box-shadow: var(--shadow-lg);
            overflow: hidden;
            transition: var(--transition);
        }

        .faq-item:hover {
            transform: translateY(-4px);
            box-shadow: var(--shadow-2xl);
            border-color: var(--primary-light);
        }

        .faq-header {
            padding: var(--space-8);
            border-bottom: 1px solid var(--border-lighter);
            background: linear-gradient(135deg, rgba(14, 165, 233, 0.02), rgba(56, 189, 248, 0.02));
        }

        .faq-question {
            font-size: var(--text-xl);
            font-weight: 700;
            margin-bottom: var(--space-5);
            color: var(--text-primary);
            line-height: 1.4;
        }

        .faq-meta {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: var(--space-5);
            flex-wrap: wrap;
            gap: var(--space-4);
        }

        .faq-info {
            display: flex;
            align-items: center;
            gap: var(--space-4);
            font-size: var(--text-sm);
            color: var(--text-secondary);
            flex-wrap: wrap;
        }

        .faq-info span {
            display: flex;
            align-items: center;
            gap: var(--space-1);
            font-weight: 500;
        }

        .faq-info i {
            color: var(--primary-color);
            font-size: var(--text-base);
        }

        .user-badge {
            display: inline-flex;
            align-items: center;
            gap: var(--space-1);
            padding: var(--space-1) var(--space-3);
            background: var(--bg-secondary);
            border: 1px solid var(--border-light);
            border-radius: var(--radius-full);
            font-size: var(--text-xs);
            font-weight: 600;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .user-badge i {
            color: var(--primary-color);
            font-size: var(--text-sm);
        }

        .status-badge {
            padding: var(--space-2) var(--space-4);
            border-radius: var(--radius-full);
            font-size: var(--text-xs);
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid;
        }

        .status-pending {
            background: linear-gradient(135deg, #fef3c7, #fde68a);
            color: #92400e;
            border-color: var(--warning-color);
        }

        .status-resolved {
            background: linear-gradient(135deg, #d1fae5, #a7f3d0);
            color: #065f46;
            border-color: var(--success-color);
        }

        .status-closed {
            background: linear-gradient(135deg, #fee2e2, #fecaca);
            color: #991b1b;
            border-color: var(--danger-color);
        }

        .faq-actions {
            display: flex;
            gap: var(--space-3);
            align-items: center;
            flex-wrap: wrap;
        }

        .rating-section {
            display: flex;
            gap: var(--space-2);
            align-items: center;
        }

        .attachment-link {
            display: inline-flex;
            align-items: center;
            gap: var(--space-1);
            color: var(--primary-color);
            text-decoration: none;
            font-size: var(--text-sm);
            font-weight: 600;
            margin-top: var(--space-2);
            padding: var(--space-2) var(--space-3);
            border-radius: var(--radius-sm);
            transition: var(--transition);
            background: rgba(14, 165, 233, 0.05);
            border: 1px solid rgba(14, 165, 233, 0.2);
        }

        .attachment-link:hover {
            background: rgba(14, 165, 233, 0.1);
            transform: translateX(2px);
            color: var(--primary-dark);
        }

        /* Enhanced Answers Section - Fixed Visibility */
        .answers-section {
            border-top: 1px solid var(--border-lighter);
            background: var(--bg-answer);
        }

        .answer-item {
            padding: var(--space-6);
            border-bottom: 1px solid var(--border-lighter);
            transition: var(--transition);
            background: var(--bg-card);
            margin: var(--space-2);
            border-radius: var(--radius-lg);
            box-shadow: var(--shadow-xs);
        }

        .answer-item:hover {
            background: var(--bg-answer-hover);
            transform: translateX(4px);
            box-shadow: var(--shadow-sm);
        }

        .answer-item:last-child {
            border-bottom: none;
        }

        .answer-content {
            margin-bottom: var(--space-4);
            line-height: 1.7;
            color: var(--text-primary);
            font-size: var(--text-base);
            font-weight: 400;
            background: transparent;
        }

        .answer-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: var(--text-sm);
            color: var(--text-secondary);
            flex-wrap: wrap;
            gap: var(--space-3);
        }

        .answer-form {
            padding: var(--space-8);
            background: var(--bg-card);
            border-top: 1px solid var(--border-lighter);
            margin: var(--space-2);
            border-radius: var(--radius-lg);
        }

        .answer-form h3 {
            font-size: var(--text-xl);
            font-weight: 700;
            margin-bottom: var(--space-5);
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: var(--space-2);
        }

        .answer-form h3 i {
            color: var(--primary-color);
            font-size: var(--text-xl);
        }

        .toggle-btn {
            background: none;
            border: none;
            color: var(--primary-color);
            cursor: pointer;
            font-size: var(--text-sm);
            font-weight: 600;
            text-decoration: none;
            transition: var(--transition);
            padding: var(--space-2) var(--space-3);
            border-radius: var(--radius-sm);
            display: inline-flex;
            align-items: center;
            gap: var(--space-1);
        }

        .toggle-btn:hover {
            background: var(--bg-secondary);
            color: var(--primary-dark);
            transform: translateY(-1px);
        }

        .hidden {
            display: none;
        }

        .file-preview {
            margin-top: var(--space-3);
            padding: var(--space-4);
            background: var(--bg-secondary);
            border-radius: var(--radius-md);
            font-size: var(--text-sm);
            border-left: 4px solid var(--primary-color);
            box-shadow: var(--shadow-sm);
            color: var(--text-secondary);
        }

        .file-preview div {
            margin-bottom: var(--space-1);
            font-weight: 500;
        }

        .file-preview div:last-child {
            margin-bottom: 0;
        }

        /* Enhanced Notification System */
        .notification {
            position: fixed;
            top: var(--space-6);
            right: var(--space-6);
            padding: var(--space-4) var(--space-6);
            border-radius: var(--radius-lg);
            color: var(--text-white);
            font-weight: 600;
            z-index: 1000;
            transform: translateX(400px);
            transition: var(--transition);
            box-shadow: var(--shadow-2xl);
            display: flex;
            align-items: center;
            gap: var(--space-3);
            max-width: 400px;
            font-size: var(--text-base);
        }

        .notification.show {
            transform: translateX(0);
        }

        .notification.success {
            background: linear-gradient(135deg, var(--success-color), var(--success-light));
        }

        .notification.error {
            background: linear-gradient(135deg, var(--danger-color), var(--danger-light));
        }

        .notification.info {
            background: linear-gradient(135deg, var(--info-color), var(--info-light));
        }

        .notification i {
            font-size: var(--text-xl);
        }

        /* Enhanced Empty State */
        .empty-state {
            text-align: center;
            padding: var(--space-12) var(--space-6);
            color: var(--text-muted);
            background: var(--bg-card);
            border-radius: var(--radius-lg);
            margin: var(--space-4);
        }

        .empty-state i {
            font-size: 4rem;
            margin-bottom: var(--space-6);
            opacity: 0.5;
            color: var(--primary-light);
        }

        .empty-state h3 {
            font-size: var(--text-2xl);
            font-weight: 700;
            margin-bottom: var(--space-3);
            color: var(--text-secondary);
        }

        .empty-state p {
            font-size: var(--text-lg);
            line-height: 1.6;
            color: var(--text-tertiary);
        }

        /* Loading Spinner */
        .loading {
            display: flex;
            justify-content: center;
            align-items: center;
            padding: var(--space-12);
        }

        .spinner {
            width: 40px;
            height: 40px;
            border: 4px solid var(--border-light);
            border-top: 4px solid var(--primary-color);
            border-radius: 50%;
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        /* Beautiful Submit Animation */
        .btn-submit {
            position: relative;
            overflow: hidden;
        }

        .btn-submit.submitting {
            pointer-events: none;
        }

        .btn-submit.submitting::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.4), transparent);
            animation: shimmer 1.5s infinite;
        }

        @keyframes shimmer {
            0% { transform: translateX(-100%); }
            100% { transform: translateX(100%); }
        }

        /* Enhanced Responsive Design */
        @media (max-width: 1024px) {
            .container {
                padding: var(--space-6);
            }
            
            .filters-grid {
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            }

            .header h1 {
                font-size: var(--text-3xl);
            }
        }

        @media (max-width: 768px) {
            .container {
                padding: var(--space-4);
            }

            .header h1 {
                font-size: var(--text-2xl);
            }

            .header {
                padding: var(--space-6);
            }

            .form-section, .search-filter-section {
                padding: var(--space-6);
            }

            .filters-grid {
                grid-template-columns: 1fr;
            }

            .faq-meta {
                flex-direction: column;
                align-items: flex-start;
            }

            .faq-actions {
                width: 100%;
                justify-content: flex-start;
            }

            .sort-controls {
                flex-direction: column;
                align-items: flex-start;
                gap: var(--space-4);
            }

            .faq-info {
                flex-direction: column;
                align-items: flex-start;
                gap: var(--space-2);
            }

            .answer-meta {
                flex-direction: column;
                align-items: flex-start;
            }

            .notification {
                right: var(--space-4);
                left: var(--space-4);
                max-width: none;
            }

            .search-input {
                padding: var(--space-3) var(--space-12) var(--space-3) var(--space-4);
                font-size: var(--text-base);
            }

            .search-icon {
                right: var(--space-4);
            }

            .rating-section {
                flex-wrap: wrap;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: var(--text-xl);
            }

            .btn {
                padding: var(--space-2) var(--space-4);
                font-size: var(--text-sm);
            }

            .faq-header {
                padding: var(--space-5);
            }

            .answer-form {
                padding: var(--space-5);
            }

            .answer-item {
                margin: var(--space-1);
                padding: var(--space-4);
            }
        }

        /* Accessibility Improvements */
        @media (prefers-reduced-motion: reduce) {
            *, *::before, *::after {
                animation-duration: 0.01ms !important;
                animation-iteration-count: 1 !important;
                transition-duration: 0.01ms !important;
            }
        }

        /* Focus Styles for Better Accessibility */
        .btn:focus-visible, .toggle-btn:focus-visible, .search-icon:focus-visible {
            outline: 2px solid var(--primary-color);
            outline-offset: 2px;
        }

        /* High Contrast Mode Support */
        @media (prefers-contrast: high) {
            :root {
                --border-light: #000000;
                --text-muted: #000000;
                --bg-secondary: #ffffff;
                --text-secondary: #000000;
                --bg-answer: #ffffff;
            }
        }

        /* Enhanced Animations */
        .fade-in {
            animation: fadeIn 0.5s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }

        /* Tooltip System */
        .tooltip {
            position: relative;
            cursor: help;
        }

        .tooltip::before {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--text-primary);
            color: var(--text-white);
            padding: var(--space-2) var(--space-3);
            border-radius: var(--radius-sm);
            font-size: var(--text-xs);
            white-space: nowrap;
            opacity: 0;
            visibility: hidden;
            transition: var(--transition);
            z-index: 1000;
        }

        .tooltip:hover::before {
            opacity: 1;
            visibility: visible;
        }

        /* Button Group */
        .btn-group {
            display: flex;
            gap: var(--space-2);
            flex-wrap: wrap;
        }

        .btn-group .btn {
            flex: 1;
            min-width: 120px;
        }

        /* Enhanced Form Validation Styles */
        .form-input.error, .form-textarea.error, .form-select.error {
            border-color: var(--border-error);
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
        }

        .form-input.success, .form-textarea.success, .form-select.success {
            border-color: var(--border-success);
            box-shadow: 0 0 0 3px rgba(16, 185, 129, 0.1);
        }

        .error-message {
            color: var(--danger-color);
            font-size: var(--text-sm);
            margin-top: var(--space-1);
            font-weight: 500;
        }

        .success-message {
            color: var(--success-color);
            font-size: var(--text-sm);
            margin-top: var(--space-1);
            font-weight: 500;
        }

        /* Count Animation */
        .count-animation {
            animation: countUp 0.3s ease-out;
        }

        @keyframes countUp {
            0% { transform: scale(1.2); color: var(--primary-light); }
            100% { transform: scale(1); }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Enhanced Header -->
        <div class="header fade-in">
            <h1><i class="fas fa-question-circle"></i> FAQ System</h1>
            <div class="user-info">
                <i class="fas fa-user"></i>
                <span><?php echo ucfirst($user_type); ?> (ID: <?php echo $user_id; ?>)</span>
            </div>
        </div>

        <!-- Enhanced Search and Filter Section -->
        <div class="search-filter-section fade-in">
            <form method="GET" id="filterForm">
                <div class="search-bar">
                    <input type="text" name="search" class="search-input" placeholder="Search FAQs, answers, and more..." 
                           value="<?php echo htmlspecialchars($search); ?>" autocomplete="off">
                    <i class="fas fa-search search-icon" onclick="document.getElementById('filterForm').submit();" tabindex="0"></i>
                </div>

                <div class="filters-grid">
                    <div class="filter-group">
                        <label class="filter-label">Category</label>
                        <select name="category" class="filter-select">
                            <option value="">All Categories</option>
                            <?php foreach ($categories as $category): ?>
                                <option value="<?php echo htmlspecialchars($category); ?>" 
                                        <?php echo $category_filter === $category ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($category); ?>
                                </option>
                            <?php endforeach; ?>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Status</label>
                        <select name="status" class="filter-select">
                            <option value="">All Status</option>
                            <option value="pending" <?php echo $status_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
                            <option value="resolved" <?php echo $status_filter === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                            <option value="closed" <?php echo $status_filter === 'closed' ? 'selected' : ''; ?>>Closed</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">User Type</label>
                        <select name="user_type" class="filter-select">
                            <option value="">All User Types</option>
                            <option value="patient" <?php echo $user_type_filter === 'patient' ? 'selected' : ''; ?>>Patient</option>
                            <option value="doctor" <?php echo $user_type_filter === 'doctor' ? 'selected' : ''; ?>>Doctor</option>
                            <option value="receptionist" <?php echo $user_type_filter === 'receptionist' ? 'selected' : ''; ?>>Receptionist</option>
                        </select>
                    </div>

                    <div class="filter-group">
                        <label class="filter-label">Sort By</label>
                        <select name="sort_by" class="filter-select">
                            <option value="created_at" <?php echo $sort_by === 'created_at' ? 'selected' : ''; ?>>Date Created</option>
                            <option value="likes" <?php echo $sort_by === 'likes' ? 'selected' : ''; ?>>Most Liked</option>
                            <option value="answer_count" <?php echo $sort_by === 'answer_count' ? 'selected' : ''; ?>>Most Answered</option>
                        </select>
                    </div>
                </div>

                <div class="sort-controls">
                    <div class="results-count">
                        <i class="fas fa-list-ul"></i>
                        <span><?php echo $faqs->num_rows; ?> FAQs found</span>
                    </div>
                    
                    <div class="btn-group">
                        <select name="sort_order" class="filter-select" style="width: auto; min-width: 150px;">
                            <option value="DESC" <?php echo $sort_order === 'DESC' ? 'selected' : ''; ?>>Newest First</option>
                            <option value="ASC" <?php echo $sort_order === 'ASC' ? 'selected' : ''; ?>>Oldest First</option>
                        </select>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-filter"></i> Apply Filters
                        </button>
                        
                        <a href="?" class="clear-filters">
                            <i class="fas fa-times"></i> Clear All
                        </a>
                    </div>
                </div>
            </form>
        </div>

        <!-- Enhanced Ask Question Form -->
        <div class="form-section fade-in">
            <h2><i class="fas fa-plus-circle"></i> Ask a New Question</h2>
            <form method="POST" enctype="multipart/form-data" id="questionForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="action" value="ask_question">
                
                <div class="form-group">
                    <label class="form-label" for="question">
                        <i class="fas fa-question"></i> Your Question *
                    </label>
                    <textarea name="question" id="question" class="form-textarea" required 
                              placeholder="Describe your question in detail. Be specific to get better answers..."></textarea>
                    <div class="error-message" id="question-error"></div>
                </div>

                <div class="form-group">
                    <label class="form-label" for="category">
                        <i class="fas fa-tags"></i> Category
                    </label>
                    <select name="category" id="category" class="form-select">
                        <option value="">Select a Category</option>
                        <option value="General">General Inquiry</option>
                        <option value="Medical">Medical Question</option>
                        <option value="Appointment">Appointment Related</option>
                        <option value="Billing">Billing & Payment</option>
                        <option value="Insurance">Insurance Coverage</option>
                        <option value="Technical">Technical Support</option>
                        <option value="Emergency">Emergency</option>
                        <option value="Other">Other</option>
                    </select>
                </div>
                
                <div class="form-group">
                    <label class="form-label">
                        <i class="fas fa-paperclip"></i> Attachment (Optional)
                    </label>
                    <div class="file-input-wrapper">
                        <input type="file" name="attachment" id="attachment" class="file-input" 
                               accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx">
                               <div class="file-input-display">
                            <i class="fas fa-cloud-upload-alt"></i>
                            <span>Choose file or drag and drop here</span>
                        </div>
                    </div>
                    <div id="file-preview" class="file-preview hidden"></div>
                    <small style="color: var(--text-muted); font-size: var(--text-xs); margin-top: var(--space-2); display: block;">
                        Supported formats: JPG, PNG, GIF, PDF, DOC, DOCX (Max 5MB)
                    </small>
                </div>
                
                <div class="btn-group">
                    <button type="submit" class="btn btn-primary btn-large btn-submit">
                        <i class="fas fa-paper-plane"></i> Post Question
                    </button>
                    <button type="reset" class="btn btn-secondary">
                        <i class="fas fa-undo"></i> Reset Form
                    </button>
                </div>
            </form>
        </div>

        <!-- Enhanced FAQ List -->
        <div class="faq-list">
            <?php if ($faqs->num_rows === 0): ?>
                <div class="empty-state fade-in">
                    <i class="fas fa-search"></i>
                    <h3>No FAQs Found</h3>
                    <p>No questions match your current search criteria. Try adjusting your filters or be the first to ask a question!</p>
                </div>
            <?php else: ?>
                <?php while ($faq = $faqs->fetch_assoc()): ?>
                    <div class="faq-item fade-in" data-faq-id="<?php echo $faq['id']; ?>">
                        <div class="faq-header">
                            <div class="faq-question"><?php echo htmlspecialchars($faq['question']); ?></div>
                            
                            <div class="faq-meta">
                                <div class="faq-info">
                                    <div class="user-badge">
                                        <i class="fas fa-user"></i>
                                        <?php echo ucfirst($faq['user_type']); ?>
                                    </div>
                                    <span><i class="fas fa-clock"></i> <?php echo date('M j, Y g:i A', strtotime($faq['created_at'])); ?></span>
                                    <?php if ($faq['category']): ?>
                                        <div class="user-badge">
                                            <i class="fas fa-tag"></i>
                                            <?php echo htmlspecialchars($faq['category']); ?>
                                        </div>
                                    <?php endif; ?>
                                    <?php if ($faq['attachment']): ?>
                                        <a href="uploads/<?php echo $faq['attachment']; ?>" target="_blank" class="attachment-link">
                                            <i class="fas fa-paperclip"></i> View Attachment
                                        </a>
                                    <?php endif; ?>
                                </div>
                                
                                <div class="faq-actions">
                                    <span class="status-badge status-<?php echo $faq['status']; ?>">
                                        <?php echo ucfirst($faq['status']); ?>
                                    </span>
                                    
                                    <div class="rating-section">
                                        <button type="button" class="btn btn-small btn-like tooltip" 
                                                data-tooltip="Like this question" 
                                                onclick="handleRating(<?php echo $faq['id']; ?>, 'like', this)">
                                            <i class="fas fa-thumbs-up"></i> 
                                            <span class="like-count"><?php echo $faq['likes']; ?></span>
                                        </button>
                                        
                                        <button type="button" class="btn btn-small btn-dislike tooltip" 
                                                data-tooltip="Dislike this question" 
                                                onclick="handleRating(<?php echo $faq['id']; ?>, 'dislike', this)">
                                            <i class="fas fa-thumbs-down"></i> 
                                            <span class="dislike-count"><?php echo $faq['dislikes']; ?></span>
                                        </button>
                                    </div>
                                    
                                    <button class="toggle-btn tooltip" onclick="toggleAnswers(<?php echo $faq['id']; ?>)" data-tooltip="View answers">
                                        <i class="fas fa-comments"></i> <?php echo $faq['answer_count']; ?> Answers
                                    </button>
                                    
                                    <?php if ($user_type === 'doctor' || $user_type === 'receptionist'): ?>
                                        <button class="toggle-btn tooltip" onclick="toggleStatus(<?php echo $faq['id']; ?>)" data-tooltip="Update status">
                                            <i class="fas fa-edit"></i> Update Status
                                        </button>
                                    <?php endif; ?>
                                </div>
                            </div>
                        </div>

                        <!-- Enhanced Answers Section -->
                        <div id="answers-<?php echo $faq['id']; ?>" class="answers-section hidden">
                            <?php
                            $answers = getAnswers($conn, $faq['id']);
                            if ($answers->num_rows === 0):
                            ?>
                                <div class="empty-state">
                                    <i class="fas fa-comment-slash"></i>
                                    <h3>No Answers Yet</h3>
                                    <p>Be the first to help by providing a helpful answer!</p>
                                </div>
                            <?php else: ?>
                                <?php while ($answer = $answers->fetch_assoc()): ?>
                                    <div class="answer-item">
                                        <div class="answer-content"><?php echo nl2br(htmlspecialchars($answer['answer'])); ?></div>
                                        <div class="answer-meta">
                                            <div style="display: flex; align-items: center; gap: var(--space-3); flex-wrap: wrap;">
                                                <span class="user-badge">
                                                    <i class="fas fa-user"></i>
                                                    <?php echo ucfirst($answer['user_type']); ?>
                                                </span>
                                                <span style="color: var(--text-secondary); font-weight: 500;">
                                                    <i class="fas fa-clock"></i> <?php echo date('M j, Y g:i A', strtotime($answer['created_at'])); ?>
                                                </span>
                                                <?php if ($answer['attachment']): ?>
                                                    <a href="uploads/<?php echo $answer['attachment']; ?>" target="_blank" class="attachment-link">
                                                        <i class="fas fa-paperclip"></i> View Attachment
                                                    </a>
                                                <?php endif; ?>
                                            </div>
                                            
                                            <div class="rating-section">
                                                <button type="button" class="btn btn-small btn-like tooltip" 
                                                        data-tooltip="Helpful answer" 
                                                        onclick="handleRating(<?php echo $answer['id']; ?>, 'like', this)">
                                                    <i class="fas fa-thumbs-up"></i> 
                                                    <span class="like-count"><?php echo $answer['likes']; ?></span>
                                                </button>
                                                
                                                <button type="button" class="btn btn-small btn-dislike tooltip" 
                                                        data-tooltip="Not helpful" 
                                                        onclick="handleRating(<?php echo $answer['id']; ?>, 'dislike', this)">
                                                    <i class="fas fa-thumbs-down"></i> 
                                                    <span class="dislike-count"><?php echo $answer['dislikes']; ?></span>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                <?php endwhile; ?>
                            <?php endif; ?>
                            
                            <!-- Enhanced Answer Form -->
                            <div class="answer-form">
                                <h3><i class="fas fa-reply"></i> Post Your Answer</h3>
                                <form method="POST" enctype="multipart/form-data" class="answer-form-element">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                    <input type="hidden" name="action" value="provide_answer">
                                    <input type="hidden" name="faq_id" value="<?php echo $faq['id']; ?>">
                                    
                                    <div class="form-group">
                                        <label class="form-label">
                                            <i class="fas fa-comment"></i> Your Answer *
                                        </label>
                                        <textarea name="answer" class="form-textarea" required 
                                                  placeholder="Provide a detailed and helpful answer..."></textarea>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label class="form-label">
                                            <i class="fas fa-paperclip"></i> Supporting Document (Optional)
                                        </label>
                                        <div class="file-input-wrapper">
                                            <input type="file" name="answer_attachment" class="file-input" 
                                                   accept=".jpg,.jpeg,.png,.gif,.pdf,.doc,.docx">
                                            <div class="file-input-display">
                                                <i class="fas fa-cloud-upload-alt"></i>
                                                <span>Choose file or drag and drop here</span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <button type="submit" class="btn btn-primary btn-submit">
                                        <i class="fas fa-paper-plane"></i> Post Answer
                                    </button>
                                </form>
                            </div>
                        </div>

                        <!-- Enhanced Status Update Form -->
                        <?php if ($user_type === 'doctor' || $user_type === 'receptionist'): ?>
                            <div id="status-<?php echo $faq['id']; ?>" class="answer-form hidden">
                                <h3><i class="fas fa-edit"></i> Update Question Status</h3>
                                <form method="POST" class="status-form">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                    <input type="hidden" name="action" value="update_status">
                                    <input type="hidden" name="faq_id" value="<?php echo $faq['id']; ?>">
                                    
                                    <div class="form-group">
                                        <label class="form-label">
                                            <i class="fas fa-flag"></i> Status *
                                        </label>
                                        <select name="status" class="form-select" required>
                                            <option value="pending" <?php echo $faq['status'] === 'pending' ? 'selected' : ''; ?>>Pending Review</option>
                                            <option value="resolved" <?php echo $faq['status'] === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                                            <option value="closed" <?php echo $faq['status'] === 'closed' ? 'selected' : ''; ?>>Closed</option>
                                        </select>
                                    </div>
                                    
                                    <div class="form-group">
                                        <label class="form-label">
                                            <i class="fas fa-sticky-note"></i> Notes
                                        </label>
                                        <textarea name="notes" class="form-textarea" 
                                                  placeholder="Add notes about the status change..."><?php echo htmlspecialchars($faq['notes'] ?? ''); ?></textarea>
                                    </div>
                                    
                                    <div class="btn-group">
                                        <button type="submit" class="btn btn-primary btn-submit">
                                            <i class="fas fa-save"></i> Update Status
                                        </button>
                                        <button type="button" class="btn btn-secondary" onclick="toggleStatus(<?php echo $faq['id']; ?>)">
                                            <i class="fas fa-times"></i> Cancel
                                        </button>
                                    </div>
                                </form>
                            </div>
                        <?php endif; ?>
                    </div>
                <?php endwhile; ?>
            <?php endif; ?>
        </div>
    </div>

    <!-- Enhanced JavaScript with Beautiful Animations -->
    <script>
        // Enhanced toggle functions with better UX
        function toggleAnswers(faqId) {
            const answersSection = document.getElementById('answers-' + faqId);
            const toggleBtn = event.target.closest('.toggle-btn');
            
            if (answersSection.classList.contains('hidden')) {
                answersSection.classList.remove('hidden');
                answersSection.classList.add('fade-in');
                toggleBtn.innerHTML = '<i class="fas fa-chevron-up"></i> Hide Answers';
                toggleBtn.setAttribute('data-tooltip', 'Hide answers');
            } else {
                answersSection.classList.add('hidden');
                answersSection.classList.remove('fade-in');
                const answerCount = answersSection.querySelectorAll('.answer-item').length;
                toggleBtn.innerHTML = `<i class="fas fa-comments"></i> ${answerCount} Answers`;
                toggleBtn.setAttribute('data-tooltip', 'View answers');
            }
        }

        function toggleStatus(faqId) {
            const statusSection = document.getElementById('status-' + faqId);
            const toggleBtn = event.target.closest('.toggle-btn');
            
            if (statusSection.classList.contains('hidden')) {
                statusSection.classList.remove('hidden');
                statusSection.classList.add('fade-in');
                toggleBtn.innerHTML = '<i class="fas fa-chevron-up"></i> Cancel';
                toggleBtn.setAttribute('data-tooltip', 'Cancel status update');
            } else {
                statusSection.classList.add('hidden');
                statusSection.classList.remove('fade-in');
                toggleBtn.innerHTML = '<i class="fas fa-edit"></i> Update Status';
                toggleBtn.setAttribute('data-tooltip', 'Update status');
            }
        }

        // Enhanced Like/Dislike Handler with Beautiful Animations
        async function handleRating(faqId, rating, button) {
            // Prevent multiple clicks
            if (button.classList.contains('processing')) return;
            
            button.classList.add('processing');
            
            // Add beautiful animation
            if (rating === 'like') {
                button.classList.add('liked');
                button.querySelector('i').style.animation = 'heartBeat 0.6s ease-out';
            } else {
                button.classList.add('disliked');
                button.querySelector('i').style.animation = 'thumbsDown 0.6s ease-out';
            }

            try {
                // Create form data
                const formData = new FormData();
                formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');
                formData.append('action', 'rate_faq');
                formData.append('faq_id', faqId);
                formData.append('rating', rating);

                // Send AJAX request
                const response = await fetch(window.location.href, {
                    method: 'POST',
                    body: formData
                });

                if (response.ok) {
                    // Update count with animation
                    const countSpan = button.querySelector(rating === 'like' ? '.like-count' : '.dislike-count');
                    const currentCount = parseInt(countSpan.textContent);
                    const newCount = currentCount + 1;
                    
                    countSpan.textContent = newCount;
                    countSpan.classList.add('count-animation');
                    
                    // Show success notification
                    showNotification('Rating updated successfully!', 'success', 2000);
                    
                    // Remove animation class after animation completes
                    setTimeout(() => {
                        countSpan.classList.remove('count-animation');
                    }, 300);
                } else {
                    throw new Error('Failed to update rating');
                }
            } catch (error) {
                console.error('Error updating rating:', error);
                showNotification('Failed to update rating. Please try again.', 'error');
                
                // Revert button state
                button.classList.remove('liked', 'disliked');
            } finally {
                // Remove processing state and animation
                setTimeout(() => {
                    button.classList.remove('processing', 'liked', 'disliked');
                    button.querySelector('i').style.animation = '';
                }, 600);
            }
        }

        // Enhanced file handling with better preview
        document.addEventListener('DOMContentLoaded', function() {
            // Handle main attachment file input
            const attachmentInput = document.getElementById('attachment');
            const filePreview = document.getElementById('file-preview');
            
            if (attachmentInput) {
                attachmentInput.addEventListener('change', function(e) {
                    handleFilePreview(e.target, filePreview);
                });
            }

            // Handle all file inputs for drag and drop
            const fileInputs = document.querySelectorAll('.file-input');
            fileInputs.forEach(input => {
                const wrapper = input.closest('.file-input-wrapper');
                const display = wrapper.querySelector('.file-input-display');
                
                // File selection
                input.addEventListener('change', function(e) {
                    updateFileDisplay(display, e.target.files[0]);
                });

                // Enhanced drag and drop functionality
                display.addEventListener('dragover', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    display.style.borderColor = 'var(--primary-color)';
                    display.style.background = 'rgba(14, 165, 233, 0.1)';
                    display.style.transform = 'scale(1.02)';
                });

                display.addEventListener('dragleave', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    display.style.borderColor = 'var(--border-color)';
                    display.style.background = 'var(--bg-secondary)';
                    display.style.transform = 'scale(1)';
                });

                display.addEventListener('drop', function(e) {
                    e.preventDefault();
                    e.stopPropagation();
                    display.style.borderColor = 'var(--border-color)';
                    display.style.background = 'var(--bg-secondary)';
                    display.style.transform = 'scale(1)';
                    
                    const files = e.dataTransfer.files;
                    if (files.length > 0) {
                        input.files = files;
                        updateFileDisplay(display, files[0]);
                        
                        // Trigger change event for preview
                        const changeEvent = new Event('change', { bubbles: true });
                        input.dispatchEvent(changeEvent);
                    }
                });
            });

            // Enhanced search functionality
            const searchInput = document.querySelector('.search-input');
            if (searchInput) {
                let searchTimeout;
                
                searchInput.addEventListener('input', function(e) {
                    clearTimeout(searchTimeout);
                    searchTimeout = setTimeout(() => {
                        if (e.target.value.length >= 3 || e.target.value.length === 0) {
                            document.getElementById('filterForm').submit();
                        }
                    }, 500);
                });

                searchInput.addEventListener('keypress', function(e) {
                    if (e.key === 'Enter') {
                        clearTimeout(searchTimeout);
                        document.getElementById('filterForm').submit();
                    }
                });
            }

            // Auto-submit filters with debounce
            const filterSelects = document.querySelectorAll('.filter-select');
            filterSelects.forEach(select => {
                select.addEventListener('change', function() {
                    setTimeout(() => {
                        document.getElementById('filterForm').submit();
                    }, 200);
                });
            });

            // Enhanced form validation
            const forms = document.querySelectorAll('form');
            forms.forEach(form => {
                form.addEventListener('submit', function(e) {
                    if (!validateForm(form)) {
                        e.preventDefault();
                        showNotification('Please fill in all required fields correctly.', 'error');
                    } else {
                        // Add beautiful submit animation
                        const submitBtn = form.querySelector('.btn-submit');
                        if (submitBtn) {
                            submitBtn.classList.add('submitting');
                        }
                    }
                });
            });

            // Initialize tooltips
            initializeTooltips();
            
            // Initialize auto-save for textareas
            setupAutoSave();
        });

        function handleFilePreview(input, previewElement) {
            const file = input.files[0];
            if (file) {
                const fileInfo = `
                    <div><strong>File:</strong> ${file.name}</div>
                    <div><strong>Size:</strong> ${formatFileSize(file.size)}</div>
                    <div><strong>Type:</strong> ${file.type}</div>
                    <div><strong>Last Modified:</strong> ${new Date(file.lastModified).toLocaleDateString()}</div>
                `;
                previewElement.innerHTML = fileInfo;
                previewElement.classList.remove('hidden');
                previewElement.classList.add('fade-in');
            } else {
                previewElement.classList.add('hidden');
                previewElement.classList.remove('fade-in');
            }
        }

        function updateFileDisplay(display, file) {
            if (file) {
                const fileIcon = getFileIcon(file.type);
                display.innerHTML = `
                    <i class="${fileIcon}"></i>
                    <span>${file.name} (${formatFileSize(file.size)})</span>
                `;
                display.style.borderColor = 'var(--success-color)';
                display.style.background = 'rgba(16, 185, 129, 0.05)';
            } else {
                display.innerHTML = `
                    <i class="fas fa-cloud-upload-alt"></i>
                    <span>Choose file or drag and drop here</span>
                `;
                display.style.borderColor = 'var(--border-color)';
                display.style.background = 'var(--bg-secondary)';
            }
        }

        function getFileIcon(fileType) {
            if (fileType.startsWith('image/')) return 'fas fa-image';
            if (fileType === 'application/pdf') return 'fas fa-file-pdf';
            if (fileType.includes('word')) return 'fas fa-file-word';
            return 'fas fa-file';
        }

        function formatFileSize(bytes) {
            if (bytes === 0) return '0 Bytes';
            const k = 1024;
            const sizes = ['Bytes', 'KB', 'MB', 'GB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        // Enhanced notification system
        function showNotification(message, type = 'success', duration = 5000) {
            // Remove existing notifications
            const existingNotifications = document.querySelectorAll('.notification');
            existingNotifications.forEach(notification => {
                notification.remove();
            });

            // Create new notification
            const notification = document.createElement('div');
            notification.className = `notification ${type}`;
            
            const icons = {
                success: 'fas fa-check-circle',
                error: 'fas fa-exclamation-circle',
                info: 'fas fa-info-circle',
                warning: 'fas fa-exclamation-triangle'
            };
            
            notification.innerHTML = `
                <i class="${icons[type] || icons.info}"></i>
                <span>${message}</span>
                <button onclick="this.parentElement.remove()" style="background: none; border: none; color: inherit; margin-left: auto; cursor: pointer; padding: 0 var(--space-2);">
                    <i class="fas fa-times"></i>
                </button>
            `;

            document.body.appendChild(notification);

            // Show notification with animation
            setTimeout(() => {
                notification.classList.add('show');
            }, 100);

            // Auto-hide notification
            setTimeout(() => {
                notification.classList.remove('show');
                setTimeout(() => {
                    if (notification.parentElement) {
                        notification.remove();
                    }
                }, 300);
            }, duration);
        }

        // Enhanced form validation
        function validateForm(form) {
            const requiredFields = form.querySelectorAll('[required]');
            let isValid = true;

            requiredFields.forEach(field => {
                const value = field.value.trim();
                const errorElement = field.parentElement.querySelector('.error-message');
                
                if (!value) {
                    field.classList.add('error');
                    field.classList.remove('success');
                    if (errorElement) {
                        errorElement.textContent = 'This field is required';
                    }
                    isValid = false;
                } else {
                    field.classList.remove('error');
                    field.classList.add('success');
                    if (errorElement) {
                        errorElement.textContent = '';
                    }
                }
            });

            return isValid;
        }

        // Initialize tooltips
        function initializeTooltips() {
            const tooltipElements = document.querySelectorAll('.tooltip');
            tooltipElements.forEach(element => {
                element.addEventListener('mouseenter', function() {
                    this.style.position = 'relative';
                });
            });
        }

        // Auto-save functionality
        function setupAutoSave() {
            const textareas = document.querySelectorAll('.form-textarea');
            textareas.forEach(textarea => {
                const saveKey = `draft_${textarea.name}_${window.location.pathname}`;
                
                // Load saved draft
                const savedDraft = localStorage.getItem(saveKey);
                if (savedDraft && !textarea.value) {
                    textarea.value = savedDraft;
                    showNotification('Draft restored', 'info', 3000);
                }

                // Save draft on input
                let saveTimeout;
                textarea.addEventListener('input', function() {
                    clearTimeout(saveTimeout);
                    saveTimeout = setTimeout(() => {
                        if (textarea.value.trim()) {
                            localStorage.setItem(saveKey, textarea.value);
                        }
                    }, 1000);
                });

                // Clear draft on successful submit
                textarea.closest('form').addEventListener('submit', function() {
                    localStorage.removeItem(saveKey);
                });
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', function(e) {
            // Ctrl/Cmd + K to focus search
            if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
                e.preventDefault();
                const searchInput = document.querySelector('.search-input');
                if (searchInput) {
                    searchInput.focus();
                    searchInput.select();
                }
            }

            // Escape to close any open sections
            if (e.key === 'Escape') {
                const openSections = document.querySelectorAll('.answers-section:not(.hidden), [id^="status-"]:not(.hidden)');
                openSections.forEach(section => {
                    section.classList.add('hidden');
                });
                
                // Update toggle buttons
                const toggleButtons = document.querySelectorAll('.toggle-btn');
                toggleButtons.forEach(btn => {
                    if (btn.innerHTML.includes('Hide') || btn.innerHTML.includes('Cancel')) {
                        btn.click();
                    }
                });
            }
        });

        // Enhanced search icon functionality
        document.querySelector('.search-icon').addEventListener('click', function() {
            document.getElementById('filterForm').submit();
        });

        // Add Enter key support for search icon
        document.querySelector('.search-icon').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                document.getElementById('filterForm').submit();
            }
        });

        // Initialize fade-in animations for existing elements
        document.addEventListener('DOMContentLoaded', function() {
            const elements = document.querySelectorAll('.fade-in');
            elements.forEach((element, index) => {
                setTimeout(() => {
                    element.style.opacity = '1';
                    element.style.transform = 'translateY(0)';
                }, index * 100);
            });
        });

        // Performance optimization: Intersection Observer for animations
        if ('IntersectionObserver' in window) {
            const observer = new IntersectionObserver((entries) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('fade-in');
                        observer.unobserve(entry.target);
                    }
                });
            }, { threshold: 0.1 });

            document.querySelectorAll('.faq-item').forEach(item => {
                observer.observe(item);
            });
        }
    </script>
</body>
</html>
