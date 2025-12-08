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

include '../connection.php';
session_start();

// Enable mysqli error reporting
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

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

if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'doctor') {
    header("Location: ../login.php");
    exit;
}

$doctor_id = $_SESSION['user_id'];
$_SESSION['doctor_id'] = $doctor_id;

// Initialize variables with default values
$doctor = [];
$pending_count = 0;
$completed_count = 0;
$pending_cases = [];
$completed_cases = [];
$private_pending_cases = [];
$private_completed_cases = [];
$consult_cases = [];
$patient_reports = [];
$status_message = '';

// --- Doctor Info Query (including profile_picture blob) ---
try {
    $doctor_query = "SELECT d.*, h.hospital_name FROM doctors d JOIN hospitals h ON d.hospital_id = h.id WHERE d.id = ?";
    $stmt_doctor = $conn->prepare($doctor_query);
    $stmt_doctor->bind_param("i", $doctor_id);
    $stmt_doctor->execute();
    $doctor_result = $stmt_doctor->get_result();
    $doctor = $doctor_result->fetch_assoc();
    $stmt_doctor->close();
    
    if (!$doctor) {
        die("Doctor not found");
    }
} catch (mysqli_sql_exception $e) {
    die("Database error while fetching doctor information");
}

// Function to convert blob to base64 data URL for doctor profile picture
function getDoctorProfilePicture($profileBlob) {
    if (!empty($profileBlob)) {
        // Detect image type (you might want to store this in DB)
        $imageInfo = getimagesizefromstring($profileBlob);
        if ($imageInfo !== false) {
            $mimeType = $imageInfo['mime'];
            return 'data:' . $mimeType . ';base64,' . base64_encode($profileBlob);
        }
    }
    return 'https://via.placeholder.com/120/3a86ff/ffffff?text=Dr';
}

// Function to get patient profile picture path
function getPatientProfilePicture($profilePath) {
    if (!empty($profilePath)) {
        return '../patient/' . $profilePath;
    }
    return 'https://via.placeholder.com/40/43e97b/ffffff?text=P';
}

// Get doctor profile picture
$doctor_profile_pic = getDoctorProfilePicture($doctor['profile_picture'] ?? null);

// Authorization check
$authorized = (int)($doctor['authorized'] ?? 1);

if ($authorized === 0) {
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
                You have been blocked by the admin for some reason. If you want to access your dashboard, please request access from the admin, or try to log in with a different email.
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

if (!isset($doctor['hospital_id']) || !$doctor['hospital_id']) {
    die("Error: Hospital ID not found for doctor");
}
$doctor_hospital_id = $doctor['hospital_id'];

// --- Status Update ---
try {
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['status'])) {
        $status = $_POST['status'];
        $sql_update = "UPDATE doctors SET status = ? WHERE id = ?";
        $stmt_update = $conn->prepare($sql_update);
        $stmt_update->bind_param("si", $status, $doctor_id);
        
        if ($stmt_update->execute()) {
            $status_message = "Status updated successfully!";
            $doctor['status'] = $status;
        } else {
            $status_message = "Error updating status";
        }
        $stmt_update->close();
    }
} catch (mysqli_sql_exception $e) {
    $status_message = "Database error: " . $e->getMessage();
}

// --- Stats Queries ---
try {
    $count_pending_query = "SELECT COUNT(*) as pending_count FROM patient_history WHERE status = 'pending' AND hospital_id = ?";
    $stmt_count = $conn->prepare($count_pending_query);
    $stmt_count->bind_param("i", $doctor_hospital_id);
    $stmt_count->execute();
    $count_result = $stmt_count->get_result();
    $pending_count = $count_result->fetch_assoc()['pending_count'];
    $stmt_count->close();
} catch (mysqli_sql_exception $e) {
    $pending_count = 0;
}

try {
    $count_completed_query = "SELECT COUNT(*) as completed_count FROM patient_history WHERE status = 'completed' AND hospital_id = ?";
    $stmt_count = $conn->prepare($count_completed_query);
    $stmt_count->bind_param("i", $doctor_hospital_id);
    $stmt_count->execute();
    $count_result = $stmt_count->get_result();
    $completed_count = $count_result->fetch_assoc()['completed_count'];
    $stmt_count->close();
} catch (mysqli_sql_exception $e) {
    $completed_count = 0;
}

// --- Pending Patient Issues ---
try {
    $pending_query = "SELECT ph.id, p.first_name, p.last_name, p.blood_group, p.date_of_birth, ph.problem, ph.date_submitted, h.hospital_name, p.profile_picture
                      FROM patient_history ph
                      JOIN patients p ON ph.patient_id = p.id
                      JOIN hospitals h ON ph.hospital_id = h.id
                      WHERE ph.status = 'pending' AND ph.hospital_id = ?
                      ORDER BY ph.date_submitted DESC";
    $stmt_pending = $conn->prepare($pending_query);
    $stmt_pending->bind_param("i", $doctor_hospital_id);
    $stmt_pending->execute();
    $pending_result = $stmt_pending->get_result();
    $pending_cases = $pending_result->fetch_all(MYSQLI_ASSOC);
    $stmt_pending->close();
} catch (mysqli_sql_exception $e) {
    $pending_cases = [];
}

// --- Completed Patient Issues ---
try {
    $completed_query = "SELECT ph.id, p.first_name, p.last_name, p.blood_group, p.date_of_birth, ph.problem, ph.date_submitted, h.hospital_name, p.profile_picture
                        FROM patient_history ph
                        JOIN patients p ON ph.patient_id = p.id
                        JOIN hospitals h ON ph.hospital_id = h.id
                        WHERE ph.status = 'completed' AND ph.hospital_id = ?
                        ORDER BY ph.date_submitted DESC LIMIT 5";
    $stmt_completed = $conn->prepare($completed_query);
    $stmt_completed->bind_param("i", $doctor_hospital_id);
    $stmt_completed->execute();
    $completed_result = $stmt_completed->get_result();
    $completed_cases = $completed_result->fetch_all(MYSQLI_ASSOC);
    $stmt_completed->close();
} catch (mysqli_sql_exception $e) {
    $completed_cases = [];
}

// --- Private Problems ---
try {
    $private_pending_query = "SELECT pp.id, pp.problem_description, pp.created_at, p.first_name, p.last_name, p.blood_group, TIMESTAMPDIFF(YEAR, p.date_of_birth, CURDATE()) AS age, h.hospital_name
                      FROM private_problems pp
                      JOIN patients p ON pp.patient_id = p.id
                      JOIN patient_hospital ph ON p.id = ph.patient_id
                      JOIN hospitals h ON ph.hospital_id = h.id
                      WHERE pp.status = 'pending' AND pp.doctor_id = ? AND h.id = ?";
    $stmt_private_pending = $conn->prepare($private_pending_query);
    $stmt_private_pending->bind_param("ii", $doctor_id, $doctor_hospital_id);
    $stmt_private_pending->execute();
    $private_pending_result = $stmt_private_pending->get_result();
    $private_pending_cases = $private_pending_result->fetch_all(MYSQLI_ASSOC);
    $stmt_private_pending->close();
} catch (mysqli_sql_exception $e) {
    $private_pending_cases = [];
}

try {
    $private_completed_query = "SELECT pp.id, pp.problem_description, pp.created_at, p.first_name, p.last_name, p.blood_group, TIMESTAMPDIFF(YEAR, p.date_of_birth, CURDATE()) AS age, h.hospital_name
                            FROM private_problems pp
                            JOIN patients p ON pp.patient_id = p.id
                            JOIN patient_hospital ph ON p.id = ph.patient_id
                            JOIN hospitals h ON ph.hospital_id = h.id
                            WHERE pp.status = 'completed' AND pp.doctor_id = ? AND h.id = ?";
    $stmt_private_completed = $conn->prepare($private_completed_query);
    $stmt_private_completed->bind_param("ii", $doctor_id, $doctor_hospital_id);
    $stmt_private_completed->execute();
    $private_completed_result = $stmt_private_completed->get_result();
    $private_completed_cases = $private_completed_result->fetch_all(MYSQLI_ASSOC);
    $stmt_private_completed->close();
} catch (mysqli_sql_exception $e) {
    $private_completed_cases = [];
}

// --- Consultations ---
try {
    $consult_query = "SELECT pp.patient_id, p.first_name, p.last_name, pp.problem_description, pp.status, pp.created_at
                      FROM private_problems pp
                      INNER JOIN patients p ON pp.patient_id = p.id
                      WHERE pp.doctor_id = ? AND (pp.status = 'completed' OR pp.status = 'pending')
                      ORDER BY pp.created_at DESC";
    $stmt_consult = $conn->prepare($consult_query);
    $stmt_consult->bind_param("i", $doctor_id);
    $stmt_consult->execute();
    $consult_result = $stmt_consult->get_result();
    $consult_cases = $consult_result->fetch_all(MYSQLI_ASSOC);
    $stmt_consult->close();
} catch (mysqli_sql_exception $e) {
    $consult_cases = [];
}

// --- Patient Reports (Updated Logic with Scheduled OR Completed status and null allergen/test_name check) ---
try {
    $patient_reports = [];
    $immunizations_query = "
    SELECT 
        i.id AS immunization_id,
        i.patient_id,
        i.vaccine_name,
        i.vaccine_type,
        i.schedule,
        i.appointment_time,
        i.immunization_date,
        i.status,
        p.first_name,
        p.last_name,
        CONCAT(p.first_name, ' ', p.last_name) AS patient_name
    FROM 
        immunizations i
    JOIN 
        patients p ON i.patient_id = p.id
    WHERE 
        i.doctor_id = ? 
        AND ((i.status = 'Scheduled' AND i.attended = 1) OR (i.status = 'Completed' AND i.attended = 1))
    ORDER BY 
        i.schedule, i.appointment_time";

    $stmt_immunizations = $conn->prepare($immunizations_query);
    if (!$stmt_immunizations) {
        throw new Exception("Failed to prepare immunizations query: " . $conn->error);
    }
    
    $stmt_immunizations->bind_param("i", $doctor_id);
    $stmt_immunizations->execute();
    $immunizations_result = $stmt_immunizations->get_result();
    $immunizations = $immunizations_result->fetch_all(MYSQLI_ASSOC);
    $stmt_immunizations->close();

    foreach ($immunizations as $immunization) {
        try {
            // Check immunization status
            $immunization_status = (!empty($immunization['immunization_date'])) ? 'Completed' : 'Pending';

            // Check allergies status - if allergen is null or empty, it's Pending
            $allergy_query = "SELECT COUNT(*) as count FROM allergies WHERE doctor_id = ? AND patient_id = ? AND immunization_id = ? AND (allergen IS NULL OR allergen = '')";
            $stmt_allergy = $conn->prepare($allergy_query);
            if (!$stmt_allergy) {
                throw new Exception("Failed to prepare allergy query: " . $conn->error);
            }
            
            $stmt_allergy->bind_param("iii", $doctor_id, $immunization['patient_id'], $immunization['immunization_id']);
            $stmt_allergy->execute();
            $allergy_result = $stmt_allergy->get_result();
            $allergy_count = $allergy_result->fetch_assoc()['count'];
            $allergy_status = ($allergy_count > 0) ? 'Pending' : 'Completed';
            $stmt_allergy->close();

            // Check lab results status - if test_name is null or empty, it's Pending
            $lab_query = "SELECT COUNT(*) as count FROM labresults WHERE doctor_id = ? AND patient_id = ? AND immunization_id = ? AND (test_name IS NULL OR test_name = '')";
            $stmt_lab = $conn->prepare($lab_query);
            if (!$stmt_lab) {
                throw new Exception("Failed to prepare lab results query: " . $conn->error);
            }
            
            $stmt_lab->bind_param("iii", $doctor_id, $immunization['patient_id'], $immunization['immunization_id']);
            $stmt_lab->execute();
            $lab_result = $stmt_lab->get_result();
            $lab_count = $lab_result->fetch_assoc()['count'];
            $lab_status = ($lab_count > 0) ? 'Pending' : 'Completed';
            $stmt_lab->close();

            // Show record only if any one of the three statuses is Pending
            if ($immunization_status === 'Pending' || $allergy_status === 'Pending' || $lab_status === 'Pending') {
                $patient_reports[] = [
                    'patient_id' => $immunization['patient_id'],
                    'patient_name' => $immunization['patient_name'],
                    'immunization_status' => $immunization_status,
                    'allergy_status' => $allergy_status,
                    'lab_status' => $lab_status,
                    'vaccine_type' => $immunization['vaccine_type'],
                    'schedule_date' => $immunization['schedule'],
                    'appointment_time' => $immunization['appointment_time'],
                    'immunization_id' => $immunization['immunization_id']
                ];
            }
        } catch (Exception $e) {
            error_log('Error processing immunization ID ' . ($immunization['immunization_id'] ?? 'unknown') . ': ' . $e->getMessage());
            continue;
        }
    }
} catch (mysqli_sql_exception $e) {
    error_log('Database error in patient report: ' . $e->getMessage());
    $patient_reports = [];
} catch (Exception $e) {
    error_log('General error in patient report: ' . $e->getMessage());
    $patient_reports = [];
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Doctor Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
:root {
    --primary: #3a86ff;
    --primary-light: #e0eaff;
    --primary-dark: #2667cc;
    --secondary: #43e97b;
    --secondary-light: #e3fceb;
    --accent: #ff6b6b;
    --accent-light: #ffe0e0;
    --warning: #ffbe0b;
    --warning-light: #fff8e0;
    --text-dark: #2d3748;
    --text-medium: #4a5568;
    --text-light: #718096;
    --bg-white: #ffffff;
    --bg-light: #f7fafc;
    --bg-gray: #edf2f7;
    --shadow-sm: 0 1px 3px rgba(0,0,0,0.12);
    --shadow-md: 0 4px 6px rgba(0,0,0,0.10);
    --shadow-lg: 0 10px 15px rgba(0,0,0,0.10);
    --radius-sm: 6px;
    --radius-md: 12px;
    --radius-lg: 20px;
    --transition: all 0.3s cubic-bezier(.4,0,.2,1);
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: 'Inter', Arial, sans-serif;
    background: var(--bg-light);
    color: var(--text-dark);
    min-height: 100vh;
}
.dashboard-container {
    display: grid;
    grid-template-columns: 260px 1fr;
    min-height: 100vh;
}
.sidebar {
    background: var(--bg-white);
    box-shadow: var(--shadow-md);
    padding: 2rem 1.5rem;
    height: 100vh;
    position: sticky;
    top: 0;
}
.sidebar-logo {
    display: flex;
    align-items: center;
    margin-bottom: 2.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid var(--bg-gray);
}
.sidebar-logo img {
    width: 40px; height: 40px; margin-right: 0.75rem;
}
.sidebar-logo h2 {
    font-size: 1.25rem; font-weight: 600; color: var(--primary);
}
.doctor-profile {
    display: flex; flex-direction: column; align-items: center;
    padding: 1.5rem 0; margin-bottom: 2rem; border-bottom: 1px solid var(--bg-gray);
}
.doctor-avatar {
    width: 80px; height: 80px; border-radius: 50%; object-fit: cover;
    margin-bottom: 1rem; border: 3px solid var(--primary-light);
}
.doctor-name {
    font-size: 1.1rem; font-weight: 600; margin-bottom: 0.25rem;
}
.doctor-specialty {
    font-size: 0.875rem; color: var(--text-light); margin-bottom: 0.75rem;
}
.doctor-hospital {
    font-size: 0.875rem; color: var(--primary); font-weight: 500;
}
.sidebar-menu {
    list-style: none; margin-top: 1.5rem;
}
.sidebar-menu li { margin-bottom: 0.5rem; }
.sidebar-menu a {
    display: flex; align-items: center;
    padding: 0.75rem 1rem;
    border-radius: var(--radius-sm);
    color: var(--text-medium);
    text-decoration: none;
    transition: var(--transition);
    font-weight: 500;
}
.sidebar-menu a:hover {
    background: var(--primary-light); color: var(--primary);
}
.sidebar-menu a.active {
    background: var(--primary); color: #fff;
}
.sidebar-menu i {
    margin-right: 0.75rem; font-size: 1.1rem;
}
.main-content {
    padding: 2rem 2.5rem;
    width: 100%;
    min-width: 0;
}
.dashboard-header {
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 2rem;
}
.greeting h1 {
    font-size: 1.75rem; font-weight: 600; margin-bottom: 0.5rem;
}
.greeting p { color: var(--text-light); }
.stats-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}
.stat-card {
    background: var(--bg-white);
    border-radius: var(--radius-md);
    padding: 1.5rem;
    box-shadow: var(--shadow-sm);
    transition: var(--transition);
    text-align: center;
}
.stat-card:hover {
    transform: translateY(-5px) scale(1.02);
    box-shadow: var(--shadow-md);
}
.stat-icon {
    display: inline-flex; align-items: center; justify-content: center;
    width: 48px; height: 48px; border-radius: var(--radius-sm);
    margin-bottom: 1rem; font-size: 1.5rem;
}
.stat-icon.pending {
    background: var(--warning-light); color: var(--warning);
}
.stat-icon.completed {
    background: var(--secondary-light); color: var(--secondary);
}
.stat-icon.hospital {
    background: var(--primary-light); color: var(--primary);
}
.stat-value {
    font-size: 1.75rem; font-weight: 700; margin-bottom: 0.5rem;
}
.stat-label {
    color: var(--text-light); font-size: 0.875rem;
}
.tabs {
    display: flex; margin-bottom: 1.5rem; border-bottom: 1px solid var(--bg-gray);
}
.tab {
    padding: 1rem 1.5rem; cursor: pointer;
    border-bottom: 3px solid transparent;
    color: var(--text-light); font-weight: 500;
    transition: var(--transition); margin-right: 1rem;
}
.tab:hover { color: var(--primary); }
.tab.active {
    color: var(--primary); border-bottom-color: var(--primary);
}
.table-container {
    background: var(--bg-white);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    overflow: hidden;
    margin-bottom: 2rem;
}
.table-header {
    display: flex; justify-content: space-between; align-items: center;
    padding: 1.5rem 1.5rem 1rem 1.5rem; border-bottom: 1px solid var(--bg-gray);
}
.table-title {
    font-size: 1.25rem; font-weight: 600;
}
.table-actions { display: flex; gap: 1rem; }
.search-input {
    display: flex; align-items: center;
    background: var(--bg-light);
    border-radius: var(--radius-sm);
    padding: 0.5rem 1rem;
}
.search-input input {
    border: none; background: transparent; padding: 0.25rem;
    outline: none; color: var(--text-dark); font-size: 1rem;
}
.search-input i {
    color: var(--text-light); margin-right: 0.5rem;
}
.table-responsive {
    width: 100%; overflow-x: auto;
}
table {
    width: 100%; border-collapse: collapse; min-width: 700px; background: var(--bg-white);
}
table th, table td {
    padding: 1rem 1.5rem;
    border-bottom: 1px solid var(--bg-gray);
    text-align: left;
}
.patient-info {
    display: flex; align-items: center; gap: 1rem;
}
.patient-avatar {
    width: 40px; height: 40px; border-radius: 50%; object-fit: cover;
}
.patient-name {
    font-weight: 500; color: var(--text-dark);
}
.status {
    display: inline-flex; align-items: center;
    padding: 0.25rem 0.75rem;
    border-radius: 20px; font-size: 0.75rem; font-weight: 500;
}
.status.pending {
    background: var(--warning-light); color: var(--warning);
}
.status.completed {
    background: var(--secondary-light); color: var(--secondary);
}
.action-btn {
    display: inline-flex; align-items: center;
    padding: 0.5rem 1rem;
    border-radius: var(--radius-sm);
    font-size: 0.875rem; font-weight: 500;
    text-decoration: none; transition: var(--transition);
    border: none; cursor: pointer; margin-right: 0.5rem;
}
.action-btn.primary {
    background: var(--primary); color: #fff;
}
.action-btn.primary:hover { background: var(--primary-dark); }
.action-btn.secondary {
    background: var(--bg-light); color: var(--text-medium);
}
.action-btn.secondary:hover { background: var(--bg-gray); }
.action-btn i { margin-right: 0.5rem; }
.empty-state {
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    padding: 3rem; text-align: center;
}
.empty-state i {
    font-size: 3rem; color: var(--text-light); margin-bottom: 1rem;
}
.empty-state h3 {
    font-size: 1.25rem; margin-bottom: 0.5rem; color: var(--text-medium);
}
.empty-state p {
    color: var(--text-light); max-width: 400px; margin-bottom: 1.5rem;
}
.form-group { margin-bottom: 1.5rem; }
label {
    display: block; font-weight: 500; margin-bottom: 0.5rem; color: var(--text-medium);
}
select, input[type="text"], input[type="password"], input[type="email"], textarea {
    width: 100%; padding: 0.75rem 1rem;
    border: 1px solid var(--bg-gray);
    border-radius: var(--radius-sm);
    background: var(--bg-light);
    color: var(--text-dark);
    font-size: 1rem;
    transition: border-color 0.2s;
}
select:focus, input:focus, textarea:focus {
    border-color: var(--primary); outline: none;
}
.alert {
    padding: 1rem 1.5rem; border-radius: var(--radius-sm); margin-bottom: 1rem;
    background: var(--primary-light); color: var(--primary); font-weight: 500;
}
.section-container {
    background: var(--bg-white);
    border-radius: var(--radius-md);
    box-shadow: var(--shadow-sm);
    margin-bottom: 2rem;
    padding: 2rem;
}
.section-title {
    font-size: 1.5rem; font-weight: 600; color: var(--primary); margin-bottom: 1.5rem;
}
.profile-section {
    display: flex; flex-direction: column; gap: 1.5rem;
}

.profile-card {
    max-width: 420px;
    margin: 2rem auto 0 auto;
    background: var(--bg-white);
    border-radius: var(--radius-lg);
    box-shadow: 0 6px 32px rgba(58,134,255,0.10), 0 1.5px 6px rgba(44,62,80,0.05);
    overflow: hidden;
    padding: 2rem 2rem 1.5rem 2rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    transition: box-shadow 0.3s;
}
.profile-card-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-bottom: 1.5rem;
}
.profile-avatar-large {
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid var(--primary-light);
    box-shadow: 0 2px 8px rgba(58,134,255,0.08);
    margin-bottom: 1rem;
}
.profile-card-info {
    text-align: center;
}
.profile-card-name {
    font-size: 1.4rem;
    font-weight: 700;
    color: var(--primary);
    margin-bottom: 0.25rem;
}
.profile-card-specialty,
.profile-card-hospital,
.profile-card-status {
    color: var(--text-medium);
    font-size: 1rem;
    margin: 0.25rem 0;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}
.profile-card-status i {
    font-size: 0.8rem;
}
.profile-card-body {
    width: 100%;
    margin-top: 1rem;
}
.profile-status-form {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}
.profile-status-form .form-group label {
    font-weight: 500;
    color: var(--primary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.profile-status-form .form-control {
    width: 100%;
    padding: 0.6rem 1rem;
    border-radius: var(--radius-sm);
    border: 1px solid var(--bg-gray);
    background: var(--bg-light);
    font-size: 1rem;
    color: var(--text-dark);
    transition: border-color 0.2s;
}
.profile-status-form .form-control:focus {
    border-color: var(--primary);
    outline: none;
}
.profile-status-form .action-btn.primary {
    width: 100%;
    font-size: 1rem;
    font-weight: 600;
    padding: 0.75rem 0;
    border-radius: var(--radius-md);
}

.toggle-button-group {
    display: flex;
    background-color: var(--bg-light);
    border-radius: var(--radius-md);
    overflow: hidden;
    margin-bottom: 20px;
    box-shadow: var(--shadow-sm);
}
.toggle-button-group button {
    flex: 1;
    padding: 12px 15px;
    background: transparent;
    border: none;
    color: var(--text-medium);
    font-weight: 500;
    font-size: 0.9rem;
    cursor: pointer;
    transition: all 0.3s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
}
.toggle-button-group button.active {
    background-color: var(--primary);
    color: white;
}
.toggle-button-group button:hover:not(.active) {
    background-color: rgba(0,0,0,0.05);
}
.toggle-button-group button i {
    font-size: 1rem;
}

.status-green {
    color: green;
    font-weight: bold;
}
.status-red {
    color: red;
    font-weight: bold;
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

@media (max-width: 1200px) {
    .main-content { padding: 2rem 1rem; }
}
@media (max-width: 1024px) {
    .dashboard-container { grid-template-columns: 1fr; }
    .sidebar { display: none; }
    .main-content { padding: 2rem 1rem; }
}
@media (max-width: 768px) {
    .stats-container { grid-template-columns: 1fr; }
    .table-responsive { overflow-x: auto; }
    .main-content { padding: 1rem 0.5rem; }
    .toggle-button-group {
        flex-direction: column;
    }
    .toggle-button-group button {
        padding: 10px;
    }
}
@media (max-width: 600px) {
    .profile-card {
        padding: 1.2rem 0.5rem 1rem 0.5rem;
    }
    .profile-avatar-large {
        width: 90px;
        height: 90px;
    }
}
@media (max-width: 500px) {
    .table-header, .table-title, .table-actions {
        flex-direction: column; align-items: flex-start; gap: 0.5rem;
    }
    .sidebar {
        width: 100vw; position: relative; height: auto; padding: 1rem;
    }
    .main-content { padding: 0.5rem; }
}
    </style>
</head>
<body>
<div class="dashboard-container">
    <!-- Sidebar -->
    <aside class="sidebar">
        <div class="sidebar-logo">
            <img src="https://via.placeholder.com/40" alt="Logo">
            <h2>MediCare</h2>
        </div>
        <div class="doctor-profile">
            <img src="<?= $doctor_profile_pic ?>" alt="Doctor Avatar" class="doctor-avatar">
            <h3 class="doctor-name">Dr. <?= htmlspecialchars($doctor['first_name'] . ' ' . $doctor['last_name']) ?></h3>
            <p class="doctor-specialty"><?= htmlspecialchars($doctor['specialization'] ?? 'Pulmonologist') ?></p>
            <p class="doctor-hospital"><?= htmlspecialchars($doctor['hospital_name']) ?></p>
        </div>
        <ul class="sidebar-menu">
            <li><a href="#" class="active" onclick="showTab('dashboard')"><i class="fas fa-home"></i> Dashboard</a></li>
            <li><a href="#" onclick="showTab('private')"><i class="fas fa-user-secret"></i> Private Problems</a></li>
            <li><a href="#" onclick="showTab('consult')"><i class="fas fa-notes-medical"></i> Consult History</a></li>
            <li><a href="#" onclick="showTab('profile')"><i class="fas fa-user-md"></i> Profile</a></li>
            <li><a href="../logout.php"><i class="fas fa-sign-out-alt"></i> Logout</a></li>
        </ul>
    </aside>
    
    <!-- Main Content -->
    <main class="main-content">
        <!-- Dashboard Tab -->
        <div id="dashboard-tab" class="tab-content active">
            <div class="section-container">
                <div class="dashboard-header">
                    <div class="greeting">
                        <h1>Welcome, Dr. <?= htmlspecialchars($doctor['first_name']) ?>!</h1>
                        <p><?= date('l, F j, Y') ?></p>
                    </div>
                </div>
                
                <?php if ($status_message): ?>
                <div class="alert"><?= htmlspecialchars($status_message) ?></div>
                <?php endif; ?>
                
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-icon pending"><i class="fas fa-clipboard-list"></i></div>
                        <div class="stat-value"><?= $pending_count ?></div>
                        <div class="stat-label">Pending Cases</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon completed"><i class="fas fa-check-circle"></i></div>
                        <div class="stat-value"><?= $completed_count ?></div>
                        <div class="stat-label">Completed Cases</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon hospital"><i class="fas fa-hospital"></i></div>
                        <div class="stat-value">1</div>
                        <div class="stat-label">Hospital</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-icon pending"><i class="fas fa-file-medical-alt"></i></div>
                        <div class="stat-value"><?= count($patient_reports) ?></div>
                        <div class="stat-label">Patient Reports</div>
                    </div>
                </div>
                
                <!-- Toggle Button Group -->
                <div role="group" class="toggle-button-group">
                    <button id="pendingToggle" class="active" onclick="toggleView('pending')">
                        <i class="fas fa-clipboard-list"></i> Pending Cases
                    </button>
                    <button id="completedToggle" onclick="toggleView('completed')">
                        <i class="fas fa-check-circle"></i> Completed Cases
                    </button>
                    <button id="reportsToggle" onclick="toggleView('reports')">
                        <i class="fas fa-file-medical-alt"></i> Patient Reports
                    </button>
                </div>
                
                <!-- Pending Cases Table -->
                <div id="pending-view" class="view-content">
                    <div class="table-container">
                        <div class="table-header">
                            <h2 class="table-title">Pending Patient Cases</h2>
                            <div class="table-actions">
                                <div class="search-input">
                                    <i class="fas fa-search"></i>
                                    <input type="text" placeholder="Search patients..." id="search-pending">
                                </div>
                            </div>
                        </div>
                        <div class="table-responsive">
                            <?php if (count($pending_cases) > 0): ?>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Patient</th>
                                        <th>Blood Group</th>
                                        <th>Age</th>
                                        <th>Date Submitted</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($pending_cases as $row): 
                                        $age = date_diff(date_create($row['date_of_birth']), date_create('today'))->y;
                                        $patient_profile_pic = getPatientProfilePicture($row['profile_picture']);
                                    ?>
                                    <tr>
                                        <td>
                                            <div class="patient-info">
                                                <img src="<?= htmlspecialchars($patient_profile_pic) ?>" alt="Patient" class="patient-avatar">
                                                <span class="patient-name"><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></span>
                                            </div>
                                        </td>
                                        <td><?= htmlspecialchars($row['blood_group']) ?></td>
                                        <td><?= htmlspecialchars($age) ?> years</td>
                                        <td><?= htmlspecialchars(date('M d, Y', strtotime($row['date_submitted']))) ?></td>
                                        <td><span class="status pending">Pending</span></td>
                                        <td>
                                            <a href="edit_issue.php?id=<?= $row['id'] ?>" class="action-btn primary">
                                                <i class="fas fa-stethoscope"></i> Provide Solution
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-clipboard-check"></i>
                                <h3>No Pending Cases</h3>
                                <p>There are no pending patient cases that require your attention at this time.</p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Completed Cases Table -->
                <div id="completed-view" class="view-content" style="display:none;">
                    <div class="table-container">
                        <div class="table-header">
                            <h2 class="table-title">Completed Patient Cases</h2>
                            <div class="table-actions">
                                <div class="search-input">
                                    <i class="fas fa-search"></i>
                                    <input type="text" placeholder="Search patients..." id="search-completed">
                                </div>
                            </div>
                        </div>
                        <div class="table-responsive">
                            <?php if (count($completed_cases) > 0): ?>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Patient</th>
                                        <th>Blood Group</th>
                                        <th>Age</th>
                                        <th>Date Submitted</th>
                                        <th>Status</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($completed_cases as $row): 
                                        $age = date_diff(date_create($row['date_of_birth']), date_create('today'))->y;
                                        $patient_profile_pic = getPatientProfilePicture($row['profile_picture']);
                                    ?>
                                    <tr>
                                        <td>
                                            <div class="patient-info">
                                                <img src="<?= htmlspecialchars($patient_profile_pic) ?>" alt="Patient" class="patient-avatar">
                                                <span class="patient-name"><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></span>
                                            </div>
                                        </td>
                                        <td><?= htmlspecialchars($row['blood_group']) ?></td>
                                        <td><?= htmlspecialchars($age) ?> years</td>
                                        <td><?= htmlspecialchars(date('M d, Y', strtotime($row['date_submitted']))) ?></td>
                                        <td><span class="status completed">Completed</span></td>
                                        <td>
                                            <a href="edit_issue.php?id=<?= $row['id'] ?>" class="action-btn secondary">
                                                <i class="fas fa-eye"></i> View Solution
                                            </a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-clipboard"></i>
                                <h3>No Completed Cases</h3>
                                <p>You haven't completed any patient cases yet.</p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
                
                <!-- Patient Reports Table -->
                <div id="reports-view" class="view-content" style="display:none;">
                    <div class="table-container">
                        <div class="table-header">
                            <h2 class="table-title">Patient Reports</h2>
                        </div>
                        <div class="table-responsive">
                            <?php if (count($patient_reports) > 0): ?>
                            <table>
                                <thead>
                                    <tr>
                                        <th>Patient Name</th>
                                        <th>Immunization</th>
                                        <th>Allergy Status</th>
                                        <th>Lab Result</th>
                                        <th>Vaccine Type</th>
                                        <th>Schedule Date</th>
                                        <th>Appointment Time</th>
                                        <th>Action</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($patient_reports as $row): 
                                        $immunizationClass = ($row['immunization_status'] == 'Pending') ? 'status-red' : 'status-green';
                                        $allergyClass = ($row['allergy_status'] == 'Pending') ? 'status-red' : 'status-green';
                                        $labClass = ($row['lab_status'] == 'Pending') ? 'status-red' : 'status-green';
                                    ?>
                                    <tr>
                                        <td><?= htmlspecialchars($row['patient_name']) ?></td>
                                        <td class="<?= $immunizationClass ?>"><?= htmlspecialchars($row['immunization_status']) ?></td>
                                        <td class="<?= $allergyClass ?>"><?= htmlspecialchars($row['allergy_status']) ?></td>
                                        <td class="<?= $labClass ?>"><?= htmlspecialchars($row['lab_status']) ?></td>
                                        <td><?= htmlspecialchars($row['vaccine_type'] ?? 'Not specified') ?></td>
                                        <td><?= htmlspecialchars($row['schedule_date'] ?? 'Not scheduled') ?></td>
                                        <td><?= htmlspecialchars($row['appointment_time'] ?? 'Not set') ?></td>
                                        <td>
                                            <a href="patient_report_update.php?immunization_id=<?= urlencode($row['immunization_id']) ?>" class="action-btn primary">Update</a>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <?php else: ?>
                            <div class="empty-state">
                                <i class="fas fa-clipboard-check"></i>
                                <h3>No Patient Reports</h3>
                                <p>All scheduled and completed immunizations have complete immunization, allergy and lab result data.</p>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Private Problems Tab -->
        <div id="private-tab" class="tab-content">
            <div class="section-container">
                <h2 class="section-title">Private Problems Dashboard</h2>
                <div class="tabs">
                    <div class="tab active" onclick="switchPrivateTab('private-pending')">Pending</div>
                    <div class="tab" onclick="switchPrivateTab('private-completed')">Completed</div>
                </div>
                <div id="private-pending" class="subtab-content">
                    <?php if (count($private_pending_cases) > 0): ?>
                    <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Patient Name</th>
                                <th>Blood Group</th>
                                <th>Age</th>
                                <th>Date Submitted</th>
                                <th>Hospital</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($private_pending_cases as $row): ?>
                            <tr>
                                <td><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></td>
                                <td><?= htmlspecialchars($row['blood_group']) ?></td>
                                <td><?= htmlspecialchars($row['age']) ?></td>
                                <td><?= htmlspecialchars($row['created_at']) ?></td>
                                <td><?= htmlspecialchars($row['hospital_name']) ?></td>
                                <td>
                                    <a href="edit_private_issue.php?id=<?= $row['id'] ?>" class="action-btn primary">Provide Solution</a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-clipboard-check"></i>
                        <h3>No Pending Private Problems</h3>
                    </div>
                    <?php endif; ?>
                </div>
                <div id="private-completed" class="subtab-content" style="display:none;">
                    <?php if (count($private_completed_cases) > 0): ?>
                    <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Patient Name</th>
                                <th>Blood Group</th>
                                <th>Age</th>
                                <th>Date Submitted</th>
                                <th>Hospital</th>
                                <th>Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($private_completed_cases as $row): ?>
                            <tr>
                                <td><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></td>
                                <td><?= htmlspecialchars($row['blood_group']) ?></td>
                                <td><?= htmlspecialchars($row['age']) ?></td>
                                <td><?= htmlspecialchars($row['created_at']) ?></td>
                                <td><?= htmlspecialchars($row['hospital_name']) ?></td>
                                <td>
                                    <a href="view_solution.php?id=<?= $row['id'] ?>" class="action-btn secondary">View Solution</a>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                    </div>
                    <?php else: ?>
                    <div class="empty-state">
                        <i class="fas fa-clipboard"></i>
                        <h3>No Completed Private Problems</h3>
                    </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
        
        <!-- Consult History Tab -->
        <div id="consult-tab" class="tab-content">
            <div class="section-container">
                <h2 class="section-title">Consultation History</h2>
                <div class="table-container">
                    <div class="table-header">
                        <h2 class="table-title">Patient Consultations</h2>
                        <div class="table-actions">
                            <div class="search-input">
                                <i class="fas fa-search"></i>
                                <input type="text" placeholder="Search consultations..." id="search-consult">
                            </div>
                        </div>
                    </div>
                    <div class="table-responsive">
                        <?php if (count($consult_cases) > 0): ?>
                        <table>
                            <thead>
                                <tr>
                                    <th>Patient Name</th>
                                    <th>Problem Description</th>
                                    <th>Status</th>
                                    <th>Date</th>
                                    <th>Action</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($consult_cases as $row): ?>
                                <tr>
                                    <td><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></td>
                                    <td><?= htmlspecialchars(substr($row['problem_description'], 0, 50)) ?>...</td>
                                    <td>
                                        <span class="status <?= $row['status'] === 'completed' ? 'completed' : 'pending' ?>">
                                            <?= ucfirst(htmlspecialchars($row['status'])) ?>
                                        </span>
                                    </td>
                                    <td><?= htmlspecialchars(date('M d, Y', strtotime($row['created_at']))) ?></td>
                                    <td>
                                        <a href="view_consultation.php?patient_id=<?= $row['patient_id'] ?>" class="action-btn secondary">
                                            <i class="fas fa-eye"></i> View Details
                                        </a>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                        <?php else: ?>
                        <div class="empty-state">
                            <i class="fas fa-notes-medical"></i>
                            <h3>No Consultation History</h3>
                            <p>You haven't conducted any consultations yet.</p>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Profile Tab -->
        <div id="profile-tab" class="tab-content">
            <div class="section-container">
                <h2 class="section-title">Doctor Profile</h2>
                <div class="profile-card">
                    <div class="profile-card-header">
                        <img src="<?= $doctor_profile_pic ?>" alt="Doctor Avatar" class="profile-avatar-large">
                        <div class="profile-card-info">
                            <h3 class="profile-card-name">Dr. <?= htmlspecialchars($doctor['first_name'] . ' ' . $doctor['last_name']) ?></h3>
                            <p class="profile-card-specialty">
                                <i class="fas fa-user-md"></i>
                                <?= htmlspecialchars($doctor['specialization'] ?? 'Pulmonologist') ?>
                            </p>
                            <p class="profile-card-hospital">
                                <i class="fas fa-hospital"></i>
                                <?= htmlspecialchars($doctor['hospital_name']) ?>
                            </p>
                            <p class="profile-card-status">
                                <i class="fas fa-circle <?= $doctor['status'] === 'available' ? 'status-green' : 'status-red' ?>"></i>
                                Status: <?= ucfirst(htmlspecialchars($doctor['status'] ?? 'available')) ?>
                            </p>
                        </div>
                    </div>
                    <div class="profile-card-body">
                        <form method="POST" class="profile-status-form">
                            <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                            <div class="form-group">
                                <label for="status">
                                    <i class="fas fa-toggle-on"></i>
                                    Update Status
                                </label>
                                <select name="status" id="status" class="form-control">
                                    <option value="available" <?= ($doctor['status'] ?? 'available') === 'available' ? 'selected' : '' ?>>Available</option>
                                    <option value="busy" <?= ($doctor['status'] ?? '') === 'busy' ? 'selected' : '' ?>>Busy</option>
                                    <option value="offline" <?= ($doctor['status'] ?? '') === 'offline' ? 'selected' : '' ?>>Offline</option>
                                </select>
                            </div>
                            <button type="submit" class="action-btn primary">
                                <i class="fas fa-save"></i>
                                Update Status
                            </button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </main>
</div>

<script>
// Tab switching functionality
function showTab(tabName) {
    // Hide all tab contents
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(tab => {
        tab.classList.remove('active');
        tab.style.display = 'none';
    });
    
    // Remove active class from all sidebar menu items
    const menuItems = document.querySelectorAll('.sidebar-menu a');
    menuItems.forEach(item => item.classList.remove('active'));
    
    // Show selected tab
    const selectedTab = document.getElementById(tabName + '-tab');
    if (selectedTab) {
        selectedTab.classList.add('active');
        selectedTab.style.display = 'block';
    }
    
    // Add active class to clicked menu item
    event.target.classList.add('active');
}

// Toggle view functionality for dashboard
function toggleView(viewName) {
    // Hide all views
    const views = ['pending-view', 'completed-view', 'reports-view'];
    views.forEach(view => {
        const element = document.getElementById(view);
        if (element) element.style.display = 'none';
    });
    
    // Remove active class from all toggle buttons
    const buttons = document.querySelectorAll('.toggle-button-group button');
    buttons.forEach(btn => btn.classList.remove('active'));
    
    // Show selected view
    const targetView = document.getElementById(viewName + '-view');
    if (targetView) targetView.style.display = 'block';
    
    // Add active class to clicked button
    const activeButton = document.getElementById(viewName === 'pending' ? 'pendingToggle' : 
                                               viewName === 'completed' ? 'completedToggle' : 'reportsToggle');
    if (activeButton) activeButton.classList.add('active');
}

// Private tab switching
function switchPrivateTab(tabName) {
    // Hide all private subtabs
    const privateTabs = document.querySelectorAll('.subtab-content');
    privateTabs.forEach(tab => tab.style.display = 'none');
    
    // Remove active class from all private tab buttons
    const privateTabButtons = document.querySelectorAll('#private-tab .tab');
    privateTabButtons.forEach(btn => btn.classList.remove('active'));
    
    // Show selected private tab
    const selectedTab = document.getElementById(tabName);
    if (selectedTab) selectedTab.style.display = 'block';
    
    // Add active class to clicked tab
    event.target.classList.add('active');
}

// Search functionality
document.addEventListener('DOMContentLoaded', function() {
    // Search for pending cases
    const searchPending = document.getElementById('search-pending');
    if (searchPending) {
        searchPending.addEventListener('input', function() {
            filterTable(this.value, 'pending-view');
        });
    }
    
    // Search for completed cases
    const searchCompleted = document.getElementById('search-completed');
    if (searchCompleted) {
        searchCompleted.addEventListener('input', function() {
            filterTable(this.value, 'completed-view');
        });
    }
    
    // Search for consultations
    const searchConsult = document.getElementById('search-consult');
    if (searchConsult) {
        searchConsult.addEventListener('input', function() {
            filterTable(this.value, 'consult-tab');
        });
    }
});

function filterTable(searchTerm, containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    
    const table = container.querySelector('table');
    if (!table) return;
    
    const rows = table.querySelectorAll('tbody tr');
    const lowerSearchTerm = searchTerm.toLowerCase();
    
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        if (text.includes(lowerSearchTerm)) {
            row.style.display = '';
        } else {
            row.style.display = 'none';
        }
    });
}

// Auto-refresh functionality (optional)
setInterval(function() {
    // You can add auto-refresh logic here if needed
    // For example, checking for new pending cases
}, 30000); // Refresh every 30 seconds

// Notification system (basic)
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    // Style the notification
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 1rem 1.5rem;
        background: var(--primary);
        color: white;
        border-radius: var(--radius-md);
        box-shadow: var(--shadow-lg);
        z-index: 1000;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    // Remove notification after 5 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(notification);
        }, 300);
    }, 5000);
}

// Add CSS animations for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Show dashboard tab by default
    showTab('dashboard');
    
    // Show pending view by default
    toggleView('pending');
    
    // Add any initialization code here
    console.log('Doctor Dashboard initialized successfully');
});
</script>

</body>
</html>
