<?php
session_start();
include '../connection.php';

// Complete Security Headers Manager Class
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
                'script-src' => ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
                'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
                'img-src' => ["'self'", 'data:', 'https:'],
                'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
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
            'script-src' => ["'self'", "'unsafe-inline'", 'https://cdnjs.cloudflare.com'],
            'style-src' => ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
            'img-src' => ["'self'", 'data:', 'https:'],
            'font-src' => ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
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

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Validate CSRF token for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        die('CSRF token validation failed');
    }
}

// Input sanitization function
function sanitizeInput($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

// Session validation
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] != 'patient') {
    header("Location: ../login.html");
    exit;
}

$patient_id = filter_var($_SESSION['user_id'], FILTER_VALIDATE_INT);
if (!$patient_id) {
    header("Location: ../login.html");
    exit;
}

// Get regular history with prepared statements
$sql_history = "
    SELECT 
        ph.id AS history_id, 
        ph.problem,
        ph.doctor_solution,
        ph.date_completed,
        ph.status,
        CASE 
            WHEN ph.status = 'completed' THEN 'Completed'
            WHEN ph.status = 'pending' THEN 'Pending'
            ELSE 'Pending'
        END AS display_status,
        CASE 
            WHEN ph.doctor_id IS NULL THEN 'Not Selected' 
            ELSE CONCAT('Dr. ', COALESCE(d.first_name, ''), ' ', COALESCE(d.last_name, '')) 
        END AS doctor_name, 
        ph.treatment_type, 
        ph.appointment_date, 
        COALESCE(h.hospital_name, 'Unknown Hospital') AS hospital,
        'regular' AS problem_type,
        ph.date_submitted
    FROM patient_history ph
    LEFT JOIN hospitals h ON ph.hospital_id = h.id
    LEFT JOIN doctors d ON ph.doctor_id = d.id
    WHERE ph.patient_id = ?
    ORDER BY ph.date_submitted DESC
";

$stmt_history = $conn->prepare($sql_history);
if (!$stmt_history) {
    error_log('Database prepare error: ' . $conn->error);
    die('Database error occurred');
}

$stmt_history->bind_param("i", $patient_id);
if (!$stmt_history->execute()) {
    error_log('Database execute error: ' . $stmt_history->error);
    die('Database error occurred');
}
$result_history = $stmt_history->get_result();
$regular_history = [];
while ($row = $result_history->fetch_assoc()) {
    if ($row['date_completed'] === null || $row['date_completed'] === '') {
        $row['date_completed'] = null;
    }
    $regular_history[] = $row;
}
$stmt_history->close();

// Get private history
$private_history = [];
try {
    $check_private_sql = "SELECT id FROM private_problems WHERE patient_id = ?";
    $check_stmt = $conn->prepare($check_private_sql);
    $check_stmt->bind_param("i", $patient_id);
    $check_stmt->execute();
    $check_result = $check_stmt->get_result();
    
    $private_check_ids = [];
    while ($check_row = $check_result->fetch_assoc()) {
        $private_check_ids[] = $check_row['id'];
    }
    $check_stmt->close();
    
    if (!empty($private_check_ids)) {
        $key_path = '../../encryption_key.key';
        $real_key_path = realpath($key_path);
        $allowed_base = realpath('../../');
        
        if ($real_key_path && $allowed_base && strpos($real_key_path, $allowed_base) === 0 && 
            file_exists($real_key_path) && is_readable($real_key_path)) {
            
            $encryption_key = trim(file_get_contents($real_key_path));
            
            if ($encryption_key && strlen($encryption_key) >= 32) {
                $sql_private = "
                    SELECT 
                        pp.id AS history_id, 
                        pp.problem_description, 
                        pp.iv AS problem_iv, 
                        pp.auth_tag AS problem_auth_tag, 
                        pp.doctor_solution, 
                        pp.solution_iv, 
                        pp.solution_auth_tag, 
                        pp.status,
                        CASE 
                            WHEN pp.status = 'completed' AND pp.updated_at IS NOT NULL 
                            THEN pp.updated_at
                            ELSE NULL
                        END AS date_completed,
                        CONCAT('Dr. ', COALESCE(d.first_name, ''), ' ', COALESCE(d.last_name, '')) AS doctor_name, 
                        pp.created_at AS date_submitted,
                        h.hospital_name AS hospital,
                        'private' AS problem_type
                    FROM private_problems pp
                    INNER JOIN hospitals h ON pp.hospital_id = h.id
                    INNER JOIN doctors d ON pp.doctor_id = d.id
                    WHERE pp.patient_id = ?
                    ORDER BY pp.created_at DESC
                ";

                $stmt_private = $conn->prepare($sql_private);
                if (!$stmt_private) {
                    throw new Exception('Database prepare error: ' . $conn->error);
                }

                $stmt_private->bind_param("i", $patient_id);
                if (!$stmt_private->execute()) {
                    throw new Exception('Database execute error: ' . $stmt_private->error);
                }
                $result_private = $stmt_private->get_result();
                
                while ($row = $result_private->fetch_assoc()) {
                    try {
                        if (!$row['problem_description'] || !$row['problem_iv'] || !$row['problem_auth_tag']) {
                            continue;
                        }

                        $decrypted_problem = openssl_decrypt(
                            $row['problem_description'],
                            'aes-256-gcm',
                            $encryption_key,
                            0,
                            $row['problem_iv'],
                            $row['problem_auth_tag']
                        );

                        if ($decrypted_problem === false) {
                            $row['problem'] = '[Encrypted Data - Decryption Failed]';
                        } else {
                            $row['problem'] = $decrypted_problem;
                        }

                        $decrypted_solution = null;
                        if ($row['doctor_solution'] && $row['solution_iv'] && $row['solution_auth_tag']) {
                            $decrypted_solution = openssl_decrypt(
                                $row['doctor_solution'],
                                'aes-256-gcm',
                                $encryption_key,
                                0,
                                $row['solution_iv'],
                                $row['solution_auth_tag']
                            );
                            
                            if ($decrypted_solution === false) {
                                $decrypted_solution = null;
                            }
                        }

                        $row['doctor_solution'] = $decrypted_solution;
                        $row['display_status'] = ($row['status'] === 'completed') ? 'Completed' : 'Pending';
                        $row['treatment_type'] = 'online';
                        $row['appointment_date'] = null;
                        
                        if ($row['date_completed'] === null || $row['date_completed'] === '') {
                            $row['date_completed'] = null;
                        }
                        
                        $private_history[] = $row;
                        
                    } catch (Exception $decrypt_error) {
                        $row['problem'] = '[Decryption Error]';
                        $row['doctor_solution'] = null;
                        $row['display_status'] = ($row['status'] === 'completed') ? 'Completed' : 'Pending';
                        $row['treatment_type'] = 'online';
                        $row['appointment_date'] = null;
                        $row['date_completed'] = null;
                        $private_history[] = $row;
                    }
                }
                $stmt_private->close();
            }
        }
    }
} catch (Exception $e) {
    error_log("Error processing private problems: " . $e->getMessage());
}

// Combine both histories
$all_history = [];

// Add private history first (most recent dates)
foreach ($private_history as $record) {
    $record['unique_id'] = 'private_' . $record['history_id'];
    $all_history[] = $record;
}

// Add regular history
foreach ($regular_history as $record) {
    $record['unique_id'] = 'regular_' . $record['history_id'];
    $all_history[] = $record;
}

// Remove duplicates
$unique_history = [];
$seen_ids = [];

foreach ($all_history as $record) {
    if (!isset($seen_ids[$record['unique_id']])) {
        $seen_ids[$record['unique_id']] = true;
        $unique_history[] = $record;
    }
}

// Sort by date_submitted descending
usort($unique_history, function($a, $b) {
    return strtotime($b['date_submitted']) - strtotime($a['date_submitted']);
});

// Create final history array with correct indexing
$final_history = [];
$total_records = count($unique_history);

for ($i = 0; $i < $total_records; $i++) {
    $record = $unique_history[$i];
    
    $new_record = [
        'history_id' => $record['history_id'],
        'unique_id' => $record['unique_id'],
        'problem_type' => $record['problem_type'],
        'problem' => $record['problem'],
        'doctor_name' => $record['doctor_name'],
        'display_status' => $record['display_status'],
        'hospital' => $record['hospital'],
        'date_submitted' => $record['date_submitted'],
        'date_completed' => $record['date_completed'],
        'treatment_type' => $record['treatment_type'],
        'appointment_date' => $record['appointment_date'],
        'doctor_solution' => $record['doctor_solution']
    ];
    
    $final_history[$i] = $new_record;
}

// Sanitize output data
for ($i = 0; $i < count($final_history); $i++) {
    $final_history[$i]['hospital'] = sanitizeInput($final_history[$i]['hospital']);
    $final_history[$i]['doctor_name'] = sanitizeInput($final_history[$i]['doctor_name']);
    if (isset($final_history[$i]['problem'])) {
        $final_history[$i]['problem'] = sanitizeInput($final_history[$i]['problem']);
    }
    if (isset($final_history[$i]['doctor_solution']) && $final_history[$i]['doctor_solution']) {
        $final_history[$i]['doctor_solution'] = sanitizeInput($final_history[$i]['doctor_solution']);
    }
    $final_history[$i]['display_status'] = sanitizeInput($final_history[$i]['display_status']);
    $final_history[$i]['problem_type'] = sanitizeInput($final_history[$i]['problem_type']);
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="csrf-token" content="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    <title>Patient Medical History</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4361ee;
            --secondary-color: #3f37c9;
            --accent-color: #4cc9f0;
            --success-color: #4ade80;
            --warning-color: #fbbf24;
            --danger-color: #f87171;
            --light-color: #f8fafc;
            --dark-color: #1e293b;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
            --card-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background-color: var(--gray-100);
            color: var(--gray-800);
            line-height: 1.6;
        }

        .container {
            max-width: 1280px;
            margin: 0 auto;
            padding: 20px;
        }

        .page-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .page-title {
            font-size: 1.8rem;
            font-weight: 600;
            color: var(--gray-800);
        }

        .filter-container {
            display: flex;
            align-items: center;
            gap: 15px;
            flex-wrap: wrap;
        }

        .filter-group {
            display: flex;
            align-items: center;
            gap: 10px;
            background-color: white;
            padding: 8px 15px;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }

        .filter-label {
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--gray-600);
        }

        .filter-option {
            background: none;
            border: none;
            font-family: inherit;
            font-size: 0.9rem;
            color: var(--gray-700);
            cursor: pointer;
            padding: 5px 10px;
            border-radius: 5px;
            transition: all 0.2s;
        }

        .filter-option:hover {
            background-color: var(--gray-100);
        }

        .filter-option.active {
            background-color: var(--primary-color);
            color: white;
        }

        .search-container {
            position: relative;
            flex-grow: 1;
            max-width: 400px;
        }

        .search-input {
            width: 100%;
            padding: 10px 15px 10px 40px;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            font-family: inherit;
            font-size: 0.95rem;
            background-color: white;
            transition: all 0.3s;
        }

        .search-input:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
        }

        .search-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--gray-400);
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(350px, 1fr));
            gap: 25px;
        }

        .card {
            background-color: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: var(--card-shadow);
            transition: transform 0.3s, box-shadow 0.3s;
            position: relative;
        }

        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
        }

        .card-header {
            padding: 20px;
            border-bottom: 1px solid var(--gray-200);
            position: relative;
        }

        .card-body {
            padding: 20px;
        }

        .card-footer {
            padding: 15px 20px;
            background-color: var(--gray-50);
            border-top: 1px solid var(--gray-200);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .hospital-name {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--gray-800);
            margin-bottom: 5px;
        }

        .problem-type {
            position: absolute;
            top: 20px;
            right: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
            padding: 4px 8px;
            border-radius: 4px;
        }

        .problem-type.regular {
            background-color: var(--accent-color);
            color: white;
        }

        .problem-type.private {
            background-color: var(--secondary-color);
            color: white;
        }

        .problem-text {
            font-size: 0.95rem;
            color: var(--gray-700);
            margin-bottom: 15px;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .detail-row {
            display: flex;
            margin-bottom: 10px;
            font-size: 0.9rem;
        }

        .detail-label {
            font-weight: 500;
            color: var(--gray-600);
            width: 120px;
            flex-shrink: 0;
        }

        .detail-value {
            color: var(--gray-800);
            flex-grow: 1;
        }

        .status-badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 50px;
            font-size: 0.8rem;
            font-weight: 600;
        }

        .status-pending {
            background-color: rgba(251, 191, 36, 0.15);
            color: #92400e;
        }

        .status-completed {
            background-color: rgba(74, 222, 128, 0.15);
            color: #166534;
        }

        .date-info {
            font-size: 0.85rem;
            color: var(--gray-500);
        }

        .view-details {
            display: inline-flex;
            align-items: center;
            gap: 5px;
            font-size: 0.9rem;
            font-weight: 500;
            color: var(--primary-color);
            text-decoration: none;
            padding: 5px 10px;
            border-radius: 5px;
            transition: all 0.2s;
        }

        .view-details:hover {
            background-color: rgba(67, 97, 238, 0.1);
        }

        .empty-state {
            text-align: center;
            padding: 50px 20px;
            background-color: white;
            border-radius: 12px;
            box-shadow: var(--card-shadow);
        }

        .empty-icon {
            font-size: 3rem;
            color: var(--gray-400);
            margin-bottom: 20px;
        }

        .empty-text {
            font-size: 1.1rem;
            color: var(--gray-600);
            margin-bottom: 20px;
        }

        .pagination {
            display: flex;
            justify-content: center;
            margin-top: 30px;
            gap: 5px;
        }

        .pagination-button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            border-radius: 8px;
            background-color: white;
            border: 1px solid var(--gray-300);
            color: var(--gray-700);
            font-weight: 500;
            transition: all 0.2s;
            cursor: pointer;
        }

        .pagination-button:hover {
            border-color: var(--primary-color);
            color: var(--primary-color);
        }

        .pagination-button.active {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            color: white;
        }

        .pagination-button.disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        @media (max-width: 768px) {
            .page-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .filter-container {
                width: 100%;
                justify-content: space-between;
            }
            
            .search-container {
                max-width: 100%;
                width: 100%;
            }
            
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <input type="hidden" id="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
    
    <div class="container">
        <div class="page-header">
            <h1 class="page-title">Medical History</h1>
            
            <div class="filter-container">
                <div class="filter-group">
                    <span class="filter-label">Type:</span>
                    <button class="filter-option active" data-filter="all">All</button>
                    <button class="filter-option" data-filter="regular">Regular</button>
                    <button class="filter-option" data-filter="private">Private</button>
                </div>
                
                <div class="filter-group">
                    <span class="filter-label">Status:</span>
                    <button class="filter-option active" data-status="all">All</button>
                    <button class="filter-option" data-status="Completed">Completed</button>
                    <button class="filter-option" data-status="Pending">Pending</button>
                </div>
                
                <div class="filter-group">
                    <span class="filter-label">Sort:</span>
                    <button class="filter-option active" data-sort="newest">Newest</button>
                    <button class="filter-option" data-sort="oldest">Oldest</button>
                </div>
            </div>
            
            <div class="search-container">
                <i class="fas fa-search search-icon"></i>
                <input type="text" class="search-input" placeholder="Search by problem, doctor, or hospital..." id="search-input">
            </div>
        </div>
        
        <div class="grid" id="history-grid">
            <?php if (empty($final_history)): ?>
                <div class="empty-state">
                    <i class="fas fa-file-medical-alt empty-icon"></i>
                    <p class="empty-text">No medical history records found</p>
                </div>
            <?php else: ?>
                <?php 
                $total_cards = count($final_history);
                for ($card_index = 0; $card_index < $total_cards; $card_index++): 
                    $current_record = $final_history[$card_index];
                ?>
                    <div class="card" 
                         data-type="<?= htmlspecialchars($current_record['problem_type']) ?>"
                         data-status="<?= htmlspecialchars($current_record['display_status']) ?>"
                         data-date-submitted="<?= htmlspecialchars($current_record['date_submitted']) ?>">
                        <div class="card-header">
                            <div class="hospital-name"><?= htmlspecialchars($current_record['hospital']) ?></div>
                            <span class="problem-type <?= htmlspecialchars($current_record['problem_type']) ?>">
                                <?= htmlspecialchars(ucfirst($current_record['problem_type'])) ?>
                            </span>
                        </div>
                        <div class="card-body">
                            <p class="problem-text"><?= htmlspecialchars($current_record['problem']) ?></p>
                            
                            <div class="detail-row">
                                <span class="detail-label">Doctor:</span>
                                <span class="detail-value"><?= htmlspecialchars($current_record['doctor_name']) ?></span>
                            </div>
                            
                            <div class="detail-row">
                                <span class="detail-label">Status:</span>
                                <span class="detail-value">
                                    <span class="status-badge status-<?= strtolower(htmlspecialchars($current_record['display_status'])) ?>">
                                        <?= htmlspecialchars($current_record['display_status']) ?>
                                    </span>
                                </span>
                            </div>
                            
                            <?php if (isset($current_record['treatment_type']) && $current_record['treatment_type'] === 'in_person' && isset($current_record['appointment_date']) && $current_record['appointment_date']): ?>
                                <div class="detail-row">
                                    <span class="detail-label">Appointment:</span>
                                    <span class="detail-value"><?= htmlspecialchars($current_record['appointment_date']) ?></span>
                                </div>
                            <?php endif; ?>
                        </div>
                        <div class="card-footer">
                            <span class="date-info">
                                <?php if ($current_record['display_status'] === 'Completed' && !empty($current_record['date_completed'])): ?>
                                    Completed on: <?= htmlspecialchars(date('M d, Y', strtotime($current_record['date_completed']))) ?>
                                <?php else: ?>
                                    Submitted on: <?= htmlspecialchars(date('M d, Y', strtotime($current_record['date_submitted']))) ?>
                                <?php endif; ?>
                            </span>
                            
                            <a href="<?= $current_record['problem_type'] === 'private' ? 'PrivatePatientProblems/private_history.php?history_id=' : 'history_detail.php?history_id=' ?><?= intval($current_record['history_id']) ?>" class="view-details">
                                View Details <i class="fas fa-chevron-right"></i>
                            </a>
                        </div>
                    </div>
                <?php endfor; ?>
            <?php endif; ?>
        </div>
        
        <div class="pagination" id="pagination">
            <!-- Pagination will be generated by JavaScript -->
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const csrfToken = document.getElementById('csrf_token').value;
            
            let currentFilter = 'all';
            let currentStatus = 'all';
            let currentSort = 'newest';
            let currentSearch = '';
            let currentPage = 1;
            const itemsPerPage = 6;
            
            const historyCards = document.querySelectorAll('.card');
            const historyGrid = document.getElementById('history-grid');
            const pagination = document.getElementById('pagination');
            
            const filterButtons = document.querySelectorAll('[data-filter]');
            const statusButtons = document.querySelectorAll('[data-status]');
            const sortButtons = document.querySelectorAll('[data-sort]');
            const searchInput = document.getElementById('search-input');
            
            function sanitizeInput(input) {
                const div = document.createElement('div');
                div.textContent = input;
                return div.innerHTML;
            }
            
            function filterAndSortCards() {
                let visibleCards = Array.from(historyCards).filter(card => {
                    const cardType = card.getAttribute('data-type');
                    const cardStatus = card.getAttribute('data-status');
                    const cardText = card.textContent.toLowerCase();
                    
                    const typeMatch = currentFilter === 'all' || cardType === currentFilter;
                    const statusMatch = currentStatus === 'all' || cardStatus === currentStatus;
                    const searchMatch = currentSearch === '' || cardText.includes(sanitizeInput(currentSearch.toLowerCase()));
                    
                    return typeMatch && statusMatch && searchMatch;
                });
                
                visibleCards.sort((a, b) => {
                    const dateA = new Date(a.getAttribute('data-date-submitted'));
                    const dateB = new Date(b.getAttribute('data-date-submitted'));
                    
                    if (currentSort === 'newest') {
                        return dateB - dateA;
                    } else {
                        return dateA - dateB;
                    }
                });
                
                historyCards.forEach(card => {
                    card.style.display = 'none';
                });
                
                const totalPages = Math.ceil(visibleCards.length / itemsPerPage);
                const startIndex = (currentPage - 1) * itemsPerPage;
                const endIndex = Math.min(startIndex + itemsPerPage, visibleCards.length);
                
                for (let i = startIndex; i < endIndex; i++) {
                    visibleCards[i].style.display = 'block';
                }
                
                updatePagination(totalPages);
                
                const existingEmptyState = document.querySelector('.empty-state');
                if (visibleCards.length === 0) {
                    if (!existingEmptyState) {
                        const emptyState = document.createElement('div');
                        emptyState.className = 'empty-state';
                        emptyState.innerHTML = `
                            <i class="fas fa-search empty-icon"></i>
                            <p class="empty-text">No records match your filters</p>
                        `;
                        historyGrid.appendChild(emptyState);
                    }
                } else {
                    if (existingEmptyState && !existingEmptyState.innerHTML.includes('No medical history records found')) {
                        existingEmptyState.remove();
                    }
                }
            }
            
            function updatePagination(totalPages) {
                pagination.innerHTML = '';
                
                if (totalPages <= 1) {
                    pagination.style.display = 'none';
                    return;
                }
                
                pagination.style.display = 'flex';
                
                const prevButton = document.createElement('button');
                prevButton.className = `pagination-button ${currentPage === 1 ? 'disabled' : ''}`;
                prevButton.innerHTML = '<i class="fas fa-chevron-left"></i>';
                prevButton.disabled = currentPage === 1;
                prevButton.addEventListener('click', () => {
                    if (currentPage > 1) {
                        currentPage--;
                        filterAndSortCards();
                    }
                });
                pagination.appendChild(prevButton);
                
                const maxVisiblePages = 5;
                let startPage = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
                let endPage = Math.min(totalPages, startPage + maxVisiblePages - 1);
                
                if (endPage - startPage + 1 < maxVisiblePages) {
                    startPage = Math.max(1, endPage - maxVisiblePages + 1);
                }
                
                for (let i = startPage; i <= endPage; i++) {
                    const pageButton = document.createElement('button');
                    pageButton.className = `pagination-button ${i === currentPage ? 'active' : ''}`;
                    pageButton.textContent = i;
                    pageButton.addEventListener('click', () => {
                        currentPage = i;
                        filterAndSortCards();
                    });
                    pagination.appendChild(pageButton);
                }
                
                const nextButton = document.createElement('button');
                nextButton.className = `pagination-button ${currentPage === totalPages ? 'disabled' : ''}`;
                nextButton.innerHTML = '<i class="fas fa-chevron-right"></i>';
                nextButton.disabled = currentPage === totalPages;
                nextButton.addEventListener('click', () => {
                    if (currentPage < totalPages) {
                        currentPage++;
                        filterAndSortCards();
                    }
                });
                pagination.appendChild(nextButton);
            }
            
            filterButtons.forEach(button => {
                button.addEventListener('click', () => {
                    filterButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    currentFilter = button.getAttribute('data-filter');
                    currentPage = 1;
                    filterAndSortCards();
                });
            });
            
            statusButtons.forEach(button => {
                button.addEventListener('click', () => {
                    statusButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    currentStatus = button.getAttribute('data-status');
                    currentPage = 1;
                    filterAndSortCards();
                });
            });
            
            sortButtons.forEach(button => {
                button.addEventListener('click', () => {
                    sortButtons.forEach(btn => btn.classList.remove('active'));
                    button.classList.add('active');
                    currentSort = button.getAttribute('data-sort');
                    currentPage = 1;
                    filterAndSortCards();
                });
            });
            
            let searchTimeout;
            searchInput.addEventListener('input', () => {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    currentSearch = searchInput.value.trim();
                    currentPage = 1;
                    filterAndSortCards();
                }, 300);
            });
            
            searchInput.addEventListener('paste', (e) => {
                setTimeout(() => {
                    searchInput.value = sanitizeInput(searchInput.value);
                }, 0);
            });
            
            filterAndSortCards();
        });
    </script>
</body>
</html>
