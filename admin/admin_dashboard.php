<?php
// --- SECURITY HEADERS AND CSRF PROTECTION ---

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

// Enhanced session security
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800);
ini_set('session.cookie_lifetime', 0);

// Enable mysqli error reporting
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

session_start();
include '../connection.php';

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

// Check if hospital_id is set in the session
if (!isset($_SESSION['hospital_id'])) {
    // Redirect to login page if not set
    header("Location: ../login.php");
    exit();
}

// Retrieve hospital_id from session
$hospital_id = $_SESSION['hospital_id'];

// --- Hospital Status Check ---
try {
    $hospital_query = "SELECT status FROM hospitals WHERE id = ?";
    $stmt_hospital = $conn->prepare($hospital_query);
    $stmt_hospital->bind_param("i", $hospital_id);
    $stmt_hospital->execute();
    $hospital_result = $stmt_hospital->get_result();
    $hospital = $hospital_result->fetch_assoc();
    $stmt_hospital->close();
    
    if (!$hospital) {
        die("Hospital not found");
    }
} catch (mysqli_sql_exception $e) {
    die("Database error while fetching hospital information");
}

// Check if hospital status is rejected
if ($hospital['status'] === 'rejected') {
    $conn->close();
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Blocked - Healthcare Portal</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Inter', sans-serif;
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
        </style>
    </head>
    <body>
        <div class="blocked-container">
            <div class="blocked-icon">
                <i class="fas fa-ban"></i>
            </div>
            <h1 class="blocked-title">Access Blocked</h1>
            <p class="blocked-message">
                Your hospital has been rejected by the admin for some reason. If you want to access your dashboard, please request access from the admin, or try to log in with a different hospital account.
            </p>
            <div class="blocked-actions">
                <a href="../send_report" class="blocked-btn primary">
                    <i class="fas fa-paper-plane"></i>
                    Request Access from Admin
                </a>
                <a href="../logout.php" class="blocked-btn">
                    <i class="fas fa-sign-out-alt"></i>
                    Try Different Account
                </a>
            </div>
        </div>
    </body>
    </html>
    <?php
    exit;
}

// Initialize variables with default values
$doctor_count_display = 0;
$patient_count_display = 0;
$pending_count = 0;
$completed_count = 0;
$total_status_count = 0;
$pending_percentage = 0;

// Fetch the total number of doctors for the hospital
try {
    $doctor_query = "SELECT COUNT(d.id) AS doctor_count FROM doctors d INNER JOIN hospitals h ON d.hospital_id = h.id WHERE h.id = ?";
    $stmt_doctor = $conn->prepare($doctor_query);
    $stmt_doctor->bind_param("i", $hospital_id);
    $stmt_doctor->execute();
    $doctor_result = $stmt_doctor->get_result();
    $doctor_count_display = $doctor_result->fetch_assoc()['doctor_count'];
    $stmt_doctor->close();
} catch (mysqli_sql_exception $e) {
    $doctor_count_display = 0;
}

// Fetch the total number of patients for the hospital
try {
    $patient_query = "SELECT COUNT(p.id) AS patient_count FROM patients p INNER JOIN patient_hospital ph ON p.id = ph.patient_id INNER JOIN hospitals h ON ph.hospital_id = h.id WHERE h.id = ?";
    $stmt_patient = $conn->prepare($patient_query);
    $stmt_patient->bind_param("i", $hospital_id);
    $stmt_patient->execute();
    $patient_result = $stmt_patient->get_result();
    $patient_count_display = $patient_result->fetch_assoc()['patient_count'];
    $stmt_patient->close();
} catch (mysqli_sql_exception $e) {
    $patient_count_display = 0;
}

// Fetch patient status data for the hospital
try {
    $status_query = "
        SELECT 
            (SELECT COUNT(ph.id) 
             FROM patient_history ph
             INNER JOIN patient_hospital phosp ON ph.patient_id = phosp.patient_id
             WHERE phosp.hospital_id = ? AND ph.status = 'pending') AS pending_count,
            (SELECT COUNT(ph.id) 
             FROM patient_history ph
             INNER JOIN patient_hospital phosp ON ph.patient_id = phosp.patient_id
             WHERE phosp.hospital_id = ? AND ph.status = 'completed') AS completed_count";
    $stmt_status = $conn->prepare($status_query);
    $stmt_status->bind_param("ii", $hospital_id, $hospital_id);
    $stmt_status->execute();
    $status_result = $stmt_status->get_result();
    $status_data = $status_result->fetch_assoc();
    $stmt_status->close();
    
    $pending_count = $status_data['pending_count'];
    $completed_count = $status_data['completed_count'];
    $total_status_count = $pending_count + $completed_count;
    $pending_percentage = $total_status_count > 0 ? round(($pending_count / $total_status_count) * 100) : 0;
} catch (mysqli_sql_exception $e) {
    $pending_count = 0;
    $completed_count = 0;
    $total_status_count = 0;
    $pending_percentage = 0;
}

$pending_count_display = htmlspecialchars($pending_count);
$completed_count_display = htmlspecialchars($completed_count);
$total_status_count_display = htmlspecialchars($total_status_count);
$pending_percentage_display = htmlspecialchars($pending_percentage);

$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hospital Admin Dashboard</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <!-- Font Awesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- Chart.js for better charts -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/3.9.1/chart.min.js"></script>
    <style>
        :root {
            --primary: #4361ee;
            --primary-light: #4895ef;
            --secondary: #3f37c9;
            --success: #4cc9f0;
            --danger: #f72585;
            --warning: #f8961e;
            --dark: #1d3557;
            --light: #f8f9fa;
            --sidebar-width: 280px;
            --header-height: 70px;
            --card-shadow: 0 8px 26px -4px rgba(20, 20, 20, 0.15),
                          0 8px 9px -5px rgba(20, 20, 20, 0.06);
            --transition-speed: 0.3s;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f5f8fe;
            color: #333;
            display: flex;
            min-height: 100vh;
            overflow-x: hidden;
        }

        /* Sidebar styles */
        .sidebar {
            position: fixed;
            width: var(--sidebar-width);
            height: 100vh;
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            padding: 2rem 1.5rem;
            color: white;
            transition: all var(--transition-speed) ease;
            overflow-y: auto;
            z-index: 999;
        }

        .sidebar-header {
            margin-bottom: 2.5rem;
            text-align: center;
            position: relative;
        }

        .logo {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 1rem;
            letter-spacing: 1px;
            text-transform: uppercase;
            background: rgba(255, 255, 255, 0.1);
            padding: 10px;
            border-radius: 10px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .sidebar-menu {
            list-style: none;
            padding: 0;
            margin: 0;
        }

        .sidebar-menu li {
            margin-bottom: 0.8rem;
            position: relative;
            transition: all 0.3s ease;
        }

        .sidebar-menu li a {
            display: flex;
            align-items: center;
            padding: 1rem 1.2rem;
            color: rgba(255, 255, 255, 0.85);
            text-decoration: none;
            border-radius: 10px;
            transition: all 0.3s ease;
            font-weight: 500;
        }

        .sidebar-menu li a:hover {
            background: rgba(255, 255, 255, 0.15);
            color: white;
            transform: translateX(5px);
        }

        .sidebar-menu li a i {
            margin-right: 12px;
            font-size: 1.2rem;
            width: 24px;
            text-align: center;
        }

        /* Main Content */
        .main-content {
            flex: 1;
            margin-left: var(--sidebar-width);
            transition: all var(--transition-speed) ease;
        }

        .header {
            height: var(--header-height);
            background-color: white;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
            padding: 0 2rem;
            display: flex;
            align-items: center;
            justify-content: space-between;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--dark);
        }

        .header-controls {
            display: flex;
            align-items: center;
            gap: 1.5rem;
        }

        .header-controls .btn {
            background: transparent;
            border: none;
            font-size: 1.5rem;
            color: #555;
            cursor: pointer;
            transition: color 0.2s ease;
        }

        .header-controls .btn:hover {
            color: var(--primary);
        }

        .profile-button {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: var(--light);
            border: none;
            padding: 0.5rem 1rem;
            border-radius: 50px;
            cursor: pointer;
        }

        .profile-avatar {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: var(--primary-light);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
        }

        .dashboard-container {
            padding: 2rem;
        }

        .section-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--dark);
            position: relative;
            display: inline-block;
        }

        .section-title::after {
            content: "";
            position: absolute;
            left: 0;
            bottom: -5px;
            width: 50px;
            height: 4px;
            background: var(--primary);
            border-radius: 10px;
        }

        /* Stats Cards */
        .stats-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }

        .stat-card {
            background: white;
            border-radius: 20px;
            padding: 1.5rem;
            box-shadow: var(--card-shadow);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            position: relative;
            overflow: hidden;
            display: flex;
            flex-direction: column;
        }

        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 30px -5px rgba(20, 20, 20, 0.15);
        }

        .stat-card::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(90deg, var(--primary), var(--primary-light));
        }

        .stat-card-icon {
            position: absolute;
            top: 30px;
            right: 30px;
            font-size: 3.5rem;
            color: rgba(67, 97, 238, 0.15);
        }

        .stat-card-title {
            font-size: 1rem;
            color: #718096;
            margin-bottom: 0.5rem;
            font-weight: 500;
        }

        .stat-card-value {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--dark);
            margin-bottom: 1rem;
        }

        .stat-card-change {
            display: flex;
            align-items: center;
            font-size: 0.875rem;
            color: var(--success);
        }

        .stat-card-change i {
            margin-right: 5px;
        }

        /* Patient Status Card */
        .patient-status-card {
            background: white;
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--card-shadow);
            margin-bottom: 2rem;
        }

        .patient-status-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 2rem;
        }

        .patient-status-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--dark);
        }

        .patient-status-chart-container {
            display: flex;
            justify-content: center;
            align-items: center;
            margin-bottom: 2rem;
            height: 280px;
        }

        .doughnut-container {
            position: relative;
            width: 250px;
            height: 250px;
        }

        .doughnut-center-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .doughnut-percentage {
            font-size: 2.5rem;
            font-weight: 700;
            color: var(--dark);
            line-height: 1;
        }

        .doughnut-label {
            font-size: 0.875rem;
            color: #718096;
        }

        .status-stats {
            display: flex;
            justify-content: space-around;
            text-align: center;
        }

        .status-stat-item {
            display: flex;
            flex-direction: column;
            align-items: center;
        }

        .status-stat-value {
            font-size: 1.75rem;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .pending-value {
            color: var(--danger);
        }

        .completed-value {
            color: var(--success);
        }

        .status-stat-label {
            font-size: 0.875rem;
            color: #718096;
            display: flex;
            align-items: center;
        }

        .status-stat-label::before {
            content: "";
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            margin-right: 5px;
        }

        .pending-label::before {
            background-color: var(--danger);
        }

        .completed-label::before {
            background-color: var(--success);
        }

        /* Quick Actions Section */
        .quick-actions {
            background: white;
            border-radius: 20px;
            padding: 2rem;
            box-shadow: var(--card-shadow);
            margin-bottom: 2rem;
        }

        .quick-actions-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--dark);
            margin-bottom: 1.5rem;
        }

        .action-buttons {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }

        .action-btn {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            padding: 1rem 1.5rem;
            background: linear-gradient(135deg, var(--primary), var(--primary-light));
            color: white;
            text-decoration: none;
            border-radius: 15px;
            font-weight: 600;
            transition: all 0.3s ease;
            border: none;
            cursor: pointer;
        }

        .action-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(67, 97, 238, 0.3);
            background: linear-gradient(135deg, var(--primary-light), var(--primary));
        }

        .action-btn i {
            font-size: 1.2rem;
        }

        /* Media Queries for Responsiveness */
        @media (max-width: 1200px) {
            .stats-row {
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            }
        }

        @media (max-width: 992px) {
            .sidebar {
                width: 80px;
                padding: 1.5rem 0.5rem;
            }

            .sidebar .logo {
                font-size: 1.2rem;
                padding: 5px;
            }

            .sidebar-menu li a span {
                display: none;
            }

            .sidebar-menu li a {
                justify-content: center;
                padding: 1rem;
            }

            .sidebar-menu li a i {
                margin-right: 0;
                font-size: 1.5rem;
            }

            .main-content {
                margin-left: 80px;
            }
        }

        @media (max-width: 768px) {
            .header {
                padding: 0 1rem;
            }

            .header-title {
                font-size: 1.2rem;
            }

            .dashboard-container {
                padding: 1rem;
            }

            .stats-row {
                grid-template-columns: 1fr;
            }

            .patient-status-chart-container {
                height: 240px;
            }

            .doughnut-container {
                width: 200px;
                height: 200px;
            }

            .action-buttons {
                grid-template-columns: 1fr;
            }
        }

        @media (max-width: 576px) {
            .sidebar {
                width: 0;
                padding: 0;
                transform: translateX(-100%);
            }

            .sidebar.active {
                width: 250px;
                padding: 2rem 1.5rem;
                transform: translateX(0);
            }

            .main-content {
                margin-left: 0;
            }

            .profile-button span {
                display: none;
            }

            .patient-status-chart-container {
                height: 220px;
            }

            .doughnut-container {
                width: 180px;
                height: 180px;
            }
        }

        /* Mobile menu toggle button */
        .menu-toggle {
            display: none;
            background: transparent;
            border: none;
            color: #555;
            font-size: 1.5rem;
            cursor: pointer;
            transition: color 0.2s ease;
        }

        .menu-toggle:hover {
            color: var(--primary);
        }

        @media (max-width: 576px) {
            .menu-toggle {
                display: block;
            }
        }

        /* Animations and Effects */
        .animate-fadeIn {
            animation: fadeIn 0.5s ease-in-out;
        }

        .animate-slideInUp {
            animation: slideInUp 0.5s ease-in-out;
        }

        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideInUp {
            from { 
                opacity: 0;
                transform: translateY(20px);
            }
            to { 
                opacity: 1;
                transform: translateY(0);
            }
        }

        /* Hover effects */
        .hover-lift {
            transition: transform 0.3s ease;
        }

        .hover-lift:hover {
            transform: translateY(-5px);
        }

        /* Loading overlay (optional) */
        .loading-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background-color: var(--light);
            display: flex;
            justify-content: center;
            align-items: center;
            z-index: 9999;
            transition: opacity 0.5s ease, visibility 0.5s ease;
        }

        .loading-spinner {
            width: 50px;
            height: 50px;
            border: 5px solid rgba(75, 85, 99, 0.1);
            border-radius: 50%;
            border-top-color: var(--primary);
            animation: spin 1s linear infinite;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .loaded {
            opacity: 0;
            visibility: hidden;
        }

        /* Custom Pulse Animation for Attention */
        .pulse {
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0% {
                box-shadow: 0 0 0 0 rgba(67, 97, 238, 0.4);
            }
            70% {
                box-shadow: 0 0 0 10px rgba(67, 97, 238, 0);
            }
            100% {
                box-shadow: 0 0 0 0 rgba(67, 97, 238, 0);
            }
        }
    </style>
</head>
<body>
    <!-- Loading Overlay -->
    <div class="loading-overlay">
        <div class="loading-spinner"></div>
    </div>

    <!-- Sidebar Navigation -->
    <aside class="sidebar">
        <div class="sidebar-header">
            <div class="logo">MediCare</div>
        </div>
        <ul class="sidebar-menu">
            <li>
                <a href="#" class="active">
                    <i class="fas fa-th-large"></i>
                    <span>Dashboard</span>
                </a>
            </li>
            <li>
                <a href="patient_list.php">
                    <i class="fas fa-user-injured"></i>
                    <span>Patient History</span>
                </a>
            </li>
            <li>
                <a href="doctor_list.php">
                    <i class="fas fa-user-md"></i>
                    <span>Doctor Applications</span>
                </a>
            </li>
            <li>
                <a href="receptionist_list.php">
                    <i class="fas fa-user-tie"></i>
                    <span>Receptionist Applications</span>
                </a>
            </li>
            <li>
                <a href="feed_back_doctor.php">
                    <i class="fas fa-comment-medical"></i>
                    <span>Doctor Feedback</span>
                </a>
            </li>
            <li>
                <a href="admin_events.php">
                    <i class="fas fa-newspaper"></i>
                    <span>Events & News</span>
                </a>
            </li>
            <li>
                <a href="contact_requests.php">
                    <i class="fas fa-chart-bar"></i>
                    <span>Contact Requests</span>
                </a>
            </li>
            <li>
                <a href="../send_report.php">
                    <i class="fas fa-chart-bar"></i>
                    <span>Report Issue</span>
                </a>
            </li>
            <li>
                <a href="#">
                    <i class="fas fa-cog"></i>
                    <span>Settings</span>
                </a>
            </li>
            <li>
                <a href="../logout.php">
                    <i class="fas fa-sign-out-alt"></i>
                    <span>Log Out</span>
                </a>
            </li>
        </ul>
    </aside>

    <!-- Main Content Area -->
    <main class="main-content">
        <!-- Header -->
        <header class="header">
            <button class="menu-toggle" id="menu-toggle">
                <i class="fas fa-bars"></i>
            </button>
            <div class="header-title">Hospital Admin Dashboard</div>
            <div class="header-controls">
                <button class="btn">
                    <i class="fas fa-bell"></i>
                </button>
                <button class="btn">
                    <i class="fas fa-envelope"></i>
                </button>
                <button class="profile-button">
                    <div class="profile-avatar">A</div>
                    <span>Admin</span>
                </button>
            </div>
        </header>

        <!-- Dashboard Content -->
        <div class="dashboard-container">
            <h2 class="section-title animate-fadeIn">Dashboard Overview</h2>

            <!-- Statistics Cards -->
            <div class="stats-row animate-slideInUp">
                <div class="stat-card hover-lift">
                    <div class="stat-card-icon">
                        <i class="fas fa-user-md"></i>
                    </div>
                    <div class="stat-card-title">Total Doctors</div>
                    <div class="stat-card-value"><?php echo $doctor_count_display; ?></div>
                    <div class="stat-card-change">
                        <i class="fas fa-arrow-up"></i>
                        <span>12% this month</span>
                    </div>
                </div>

                <div class="stat-card hover-lift">
                    <div class="stat-card-icon">
                        <i class="fas fa-users"></i>
                    </div>
                    <div class="stat-card-title">Total Patients</div>
                    <div class="stat-card-value"><?php echo $patient_count_display; ?></div>
                    <div class="stat-card-change">
                        <i class="fas fa-arrow-up"></i>
                        <span>8% this month</span>
                    </div>
                </div>

                <div class="stat-card hover-lift">
                    <div class="stat-card-icon">
                        <i class="fas fa-stethoscope"></i>
                    </div>
                    <div class="stat-card-title">Active Treatments</div>
                    <div class="stat-card-value"><?php echo $pending_count_display; ?></div>
                    <div class="stat-card-change">
                        <i class="fas fa-arrow-up"></i>
                        <span>5% this week</span>
                    </div>
                </div>
            </div>

            <!-- Quick Actions Section -->
            <div class="quick-actions animate-slideInUp" style="animation-delay: 0.1s;">
                <div class="quick-actions-title">Quick Actions</div>
                <div class="action-buttons">
                    <a href="admin_events.php" class="action-btn">
                        <i class="fas fa-newspaper"></i>
                        <span>Manage Events & News</span>
                    </a>
                    <a href="patient_list.php" class="action-btn">
                        <i class="fas fa-user-injured"></i>
                        <span>View Patients</span>
                    </a>
                    <a href="doctor_list.php" class="action-btn">
                        <i class="fas fa-user-md"></i>
                        <span>Manage Doctors</span>
                    </a>
                    <a href="feed_back_doctor.php" class="action-btn">
                        <i class="fas fa-comment-medical"></i>
                        <span>View Feedback</span>
                    </a>
                </div>
            </div>

            <!-- Patient Status Card with Doughnut Chart -->
            <div class="patient-status-card animate-slideInUp" style="animation-delay: 0.2s;">
                <div class="patient-status-header">
                    <div class="patient-status-title">Patient Treatment Status</div>
                    <div class="dropdown">
                        <button class="btn">
                            <i class="fas fa-ellipsis-v"></i>
                        </button>
                    </div>
                </div>

                <div class="patient-status-chart-container">
                    <div class="doughnut-container">
                        <canvas id="statusChart"></canvas>
                        <div class="doughnut-center-text">
                            <div class="doughnut-percentage"><?php echo $pending_percentage_display; ?>%</div>
                            <div class="doughnut-label">Pending</div>
                        </div>
                    </div>
                </div>

                <div class="status-stats">
                    <div class="status-stat-item">
                        <div class="status-stat-value pending-value"><?php echo $pending_count_display; ?></div>
                        <div class="status-stat-label pending-label">Pending Cases</div>
                    </div>
                    <div class="status-stat-item">
                        <div class="status-stat-value completed-value"><?php echo $completed_count_display; ?></div>
                        <div class="status-stat-label completed-label">Completed Cases</div>
                    </div>
                    <div class="status-stat-item">
                        <div class="status-stat-value"><?php echo $total_status_count_display; ?></div>
                        <div class="status-stat-label">Total Cases</div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <script>
        // Initialize and render doughnut chart
        document.addEventListener('DOMContentLoaded', function() {
            // Chart.js initialization for status doughnut chart
            const statusChart = document.getElementById('statusChart').getContext('2d');
            
            const pendingPercentage = <?php echo $pending_percentage; ?>;
            const completedPercentage = 100 - pendingPercentage;
            
            new Chart(statusChart, {
                type: 'doughnut',
                data: {
                    labels: ['Pending', 'Completed'],
                    datasets: [{
                        data: [pendingPercentage, completedPercentage],
                        backgroundColor: [
                            '#f72585', // var(--danger)
                            '#4cc9f0'  // var(--success)
                        ],
                        borderWidth: 0,
                        cutout: '75%'
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        },
                        tooltip: {
                            enabled: true,
                            callbacks: {
                                label: function(context) {
                                    return context.label + ': ' + context.raw + '%';
                                }
                            }
                        }
                    },
                    animation: {
                        animateRotate: true,
                        animateScale: true
                    }
                }
            });

            // Handle loading overlay
            setTimeout(function() {
                document.querySelector('.loading-overlay').classList.add('loaded');
            }, 800);

            // Mobile menu toggle
            const menuToggle = document.getElementById('menu-toggle');
            const sidebar = document.querySelector('.sidebar');
            
            if(menuToggle) {
                menuToggle.addEventListener('click', function() {
                    sidebar.classList.toggle('active');
                });
            }

            // Close sidebar when clicking outside on mobile
            document.addEventListener('click', function(event) {
                if (window.innerWidth <= 576 && 
                    !sidebar.contains(event.target) && 
                    !menuToggle.contains(event.target) &&
                    sidebar.classList.contains('active')) {
                    sidebar.classList.remove('active');
                }
            });
        });
    </script>
</body>
</html>
