<?php
// Enhanced session security - MUST be set BEFORE session_start()
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.gc_maxlifetime', 1800); // 30 minutes
ini_set('session.cookie_lifetime', 0); // Session cookie

// Start session AFTER setting session configuration
session_start();

// Enhanced security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdn.jsdelivr.net https://code.jquery.com https://cdnjs.cloudflare.com; style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src \'self\' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src \'self\' data:; connect-src \'self\'; frame-ancestors \'none\';');

include '../connection.php';

// CSRF token generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Optimized security logging function - Only log important events
function logSecurityEvent($conn, $email, $event_type, $ip_address, $user_agent, $additional_info = '') {
    // Only log critical security events to prevent database bloat
    $critical_events = [
        'UNAUTHORIZED_DASHBOARD_ACCESS',
        'SESSION_TIMEOUT',
        'SESSION_HIJACK_ATTEMPT',
        'CSRF_TOKEN_MISMATCH',
        'RATE_LIMIT_EXCEEDED',
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

// Function to sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Check for session messages at the beginning of the script
if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']);
} else {
    $success_message = "";
}

if (isset($_SESSION['error_message'])) {
    $error_message = $_SESSION['error_message'];
    unset($_SESSION['error_message']);
} else {
    $error_message = "";
}

// Enhanced authentication check with security logging
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'receptionist') {
    // Log unauthorized access attempt
    logSecurityEvent($conn, 'Unauthorized user detected - your information will be noticed', 'UNAUTHORIZED_DASHBOARD_ACCESS', $ip_address, $user_agent, 'Attempted to access receptionist dashboard without proper authentication');
    
    // Clear any existing session data
    session_destroy();
    
    // Redirect with security message
    header("Location: ../login.html");
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

$receptionist_id = $_SESSION['user_id'];

// Get receptionist information including hospital_id and authorization status
$sql_receptionist = "SELECT r.*, h.hospital_name FROM receptionist r JOIN hospitals h ON r.hospital_id = h.id
                     WHERE r.id = ?";
$stmt_receptionist = $conn->prepare($sql_receptionist);
$stmt_receptionist->bind_param("i", $receptionist_id);
$stmt_receptionist->execute();
$result_receptionist = $stmt_receptionist->get_result();
$receptionist = $result_receptionist->fetch_assoc();
$stmt_receptionist->close();

if (!$receptionist) {
    $error_message = "Receptionist information not found.";
    $receptionist_hospital_id = 0;
} else {
    // **AUTHORIZATION CHECK - NEW LOGIC ADDED HERE**
    $authorized = (int)($receptionist['authorized'] ?? 1); // Default to 1 if column doesn't exist
    
    if ($authorized === 0) {
        // User is not authorized - display blocking message
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
                    You have been blocked by the admin for some reason. If you want to access your dashboard, please request access from the admin, or try to log in with a different email. If you're unable to log in with a different email, your device may also be blocked – in that case, please submit a valid reason using the same request form.
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
    
    $receptionist_hospital_id = $receptionist['hospital_id'];
    $first_name = sanitizeInput($receptionist['first_name'] ?? "Unknown");
    $last_name = sanitizeInput($receptionist['last_name'] ?? "Receptionist");
    $profile_picture = $receptionist['profile_picture'] ?? "default-avatar.png";
    $hospital_name = sanitizeInput($receptionist['hospital_name']);
    $user_email = $receptionist['email'] ?? 'unknown';
    $_SESSION['user_email'] = $user_email;
}

// Count pending appointments (where schedule is NULL)
$sql_count_pending = "SELECT COUNT(*) as pending_count FROM immunizations WHERE hospital_id = ? AND schedule IS NULL";
$stmt_count = $conn->prepare($sql_count_pending);
$stmt_count->bind_param("i", $receptionist_hospital_id);
$stmt_count->execute();
$result_count = $stmt_count->get_result();
$pending_count = $result_count->fetch_assoc()['pending_count'];
$stmt_count->close();

// Count today's appointments
$today = date('Y-m-d');
$sql_count_today = "SELECT COUNT(*) as today_count FROM immunizations 
                    WHERE hospital_id = ? AND schedule = ? AND status = 'scheduled'";
$stmt_today = $conn->prepare($sql_count_today);
$stmt_today->bind_param("is", $receptionist_hospital_id, $today);
$stmt_today->execute();
$result_today = $stmt_today->get_result();
$today_count = $result_today->fetch_assoc()['today_count'];
$stmt_today->close();

// MODIFIED: Count total patients in the hospital regardless of status
$sql_count_patients = "SELECT COUNT(*) as patient_count FROM patients p 
                      JOIN patient_hospital ph ON p.id = ph.patient_id 
                      WHERE ph.hospital_id = ?";
$stmt_patients = $conn->prepare($sql_count_patients);
$stmt_patients->bind_param("i", $receptionist_hospital_id);
$stmt_patients->execute();
$result_patients = $stmt_patients->get_result();
$patient_count = $result_patients->fetch_assoc()['patient_count'];
$stmt_patients->close();

// Count overdue appointments
$sql_count_overdue = "SELECT COUNT(*) as overdue_count FROM immunizations 
                      WHERE hospital_id = ? AND schedule < CURDATE() AND status = 'Pending'";
$stmt_overdue = $conn->prepare($sql_count_overdue);
$stmt_overdue->bind_param("i", $receptionist_hospital_id);
$stmt_overdue->execute();
$result_overdue = $stmt_overdue->get_result();
$overdue_count = $result_overdue->fetch_assoc()['overdue_count'];
$stmt_overdue->close();

// Function to send email notification to patient using PHPMailer
function sendAppointmentEmail($patient_email, $patient_name, $schedule_date, $schedule_time, $doctor_name, $vaccine_type, $hospital_name, $comments) {
    $mail = new PHPMailer(true);
    
    try {
        // Server settings
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = ''; //replce your mail
        $mail->Password = ''; // replace your password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;
        
        // Recipients
        $mail->setFrom('youremail@gmail.com', $hospital_name);
        $mail->addAddress($patient_email, $patient_name);
        
        // Content
        $mail->isHTML(true);
        $mail->Subject = "Your Appointment Has Been Scheduled";
        
        // Create a beautiful HTML email
        $message = '
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Appointment Confirmation</title>
            <style>
                body {
                    font-family: Arial, sans-serif;
                    line-height: 1.6;
                    color: #333;
                    max-width: 600px;
                    margin: 0 auto;
                }
                .email-container {
                    border: 1px solid #e0e0e0;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.05);
                }
                .email-header {
                    background: linear-gradient(135deg, #2563eb, #1e40af);
                    color: white;
                    padding: 20px;
                    text-align: center;
                }
                .email-body {
                    padding: 20px;
                    background-color: #f9f9f9;
                }
                .appointment-details {
                    background-color: white;
                    border-radius: 8px;
                    padding: 20px;
                    margin-top: 20px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.05);
                }
                .detail-row {
                    margin-bottom: 10px;
                    display: flex;
                }
                .detail-label {
                    font-weight: bold;
                    width: 140px;
                    color: #555;
                }
                .detail-value {
                    flex: 1;
                }
                .comments-section {
                    margin-top: 20px;
                    padding: 15px;
                    background-color: #f0f7ff;
                    border-radius: 8px;
                    border-left: 4px solid #2563eb;
                }
                .email-footer {
                    text-align: center;
                    padding: 15px;
                    font-size: 12px;
                    color: #777;
                    background-color: #f1f1f1;
                }
                .button {
                    display: inline-block;
                    background-color: #2563eb;
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border-radius: 4px;
                    margin-top: 20px;
                }
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="email-header">
                    <h1>Appointment Confirmation</h1>
                    <p>Your health check-up has been scheduled</p>
                </div>
                <div class="email-body">
                    <p>Dear ' . $patient_name . ',</p>
                    <p>We\'re pleased to confirm that your appointment for a health check-up has been successfully scheduled at ' . $hospital_name . '.</p>
                    
                    <div class="appointment-details">
                        <h2>Appointment Details</h2>
                        
                        <div class="detail-row">
                            <div class="detail-label">Date:</div>
                            <div class="detail-value">' . date('l, F j, Y', strtotime($schedule_date)) . '</div>
                        </div>
                        
                        <div class="detail-row">
                            <div class="detail-label">Time:</div>
                            <div class="detail-value">' . date('h:i A', strtotime($schedule_time)) . '</div>
                        </div>
                        
                        <div class="detail-row">
                            <div class="detail-label">Doctor:</div>
                            <div class="detail-value">' . $doctor_name . '</div>
                        </div>
                        
                        <div class="detail-row">
                            <div class="detail-label">Vaccine Type:</div>
                            <div class="detail-value">' . $vaccine_type . '</div>
                        </div>
                        
                        <div class="detail-row">
                            <div class="detail-label">Location:</div>
                            <div class="detail-value">' . $hospital_name . '</div>
                        </div>
                    </div>';
                    
        if (!empty($comments)) {
            $message .= '
                    <div class="comments-section">
                        <h3>Special Instructions</h3>
                        <p>' . nl2br($comments) . '</p>
                    </div>';
        }
        
        $message .= '
                    <p>Please arrive 15 minutes before your scheduled appointment time. If you need to reschedule or cancel your appointment, please contact us at least 24 hours in advance.</p>
                    
                    <p>We look forward to seeing you!</p>
                    
                    <p>Best regards,<br>
                    The Healthcare Team at ' . $hospital_name . '</p>
                </div>
                <div class="email-footer">
                    <p>This is an automated message. Please do not reply to this email.</p>
                    <p>&copy; ' . date('Y') . ' ' . $hospital_name . '. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        ';
        
        $mail->Body = $message;
        $mail->AltBody = strip_tags(str_replace(['<br>', '</p>'], ["\n", "\n\n"], $message));
        
        return $mail->send();
    } catch (Exception $e) {
        error_log("Message could not be sent. Mailer Error: {$mail->ErrorInfo}");
        return false;
    }
}

// Initialize form token if not already set
if (!isset($_SESSION['form_token'])) {
    $_SESSION['form_token'] = bin2hex(random_bytes(32));
}
$form_token = $_SESSION['form_token'];

// Handle mark as attended action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mark_as_attended'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in mark as attended');
        $_SESSION['error_message'] = "Security token mismatch. Please try again.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    $immunization_id = $conn->real_escape_string($_POST['immunization_id']);
    
    // Validate the appointment belongs to the receptionist's hospital
    $validate_sql = "SELECT id FROM immunizations WHERE id = ? AND hospital_id = ?";
    $validate_stmt = $conn->prepare($validate_sql);
    $validate_stmt->bind_param("ii", $immunization_id, $receptionist_hospital_id);
    $validate_stmt->execute();
    $validate_result = $validate_stmt->get_result();
    
    if ($validate_result->num_rows > 0) {
        // Start transaction
        $conn->begin_transaction();
        
        try {
            // Update the immunization status to attended and set attended = 1
            $update_sql = "UPDATE immunizations SET attended = 1 WHERE id = ?";
            $update_stmt = $conn->prepare($update_sql);
            $update_stmt->bind_param("i", $immunization_id);
            
            if ($update_stmt->execute()) {
                // Commit the transaction
                $conn->commit();
                $_SESSION['success_message'] = "Appointment marked as attended successfully.";
            } else {
                // Rollback the transaction
                $conn->rollback();
                $_SESSION['error_message'] = "Error updating appointment status: " . $conn->error;
            }
            
            $update_stmt->close();
        } catch (Exception $e) {
            // Rollback the transaction
            $conn->rollback();
            $_SESSION['error_message'] = "Error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Invalid appointment or not associated with your hospital.";
    }
    
    // Redirect to the same page
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Handle appointment scheduling - FIXED VERSION
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['schedule_appointment'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in appointment scheduling');
        $_SESSION['error_message'] = "Security token mismatch. Please try again.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    // Check if this is a duplicate submission
    if (isset($_POST['form_token']) && isset($_SESSION['form_token']) && $_POST['form_token'] === $_SESSION['form_token']) {
        // This is a valid submission, process it
        $immunization_id = $conn->real_escape_string($_POST['immunization_id']);
        $schedule_date = $conn->real_escape_string($_POST['schedule_date']);
        $schedule_time = $conn->real_escape_string($_POST['schedule_time']);
        $doctor_id = $conn->real_escape_string($_POST['doctor_id']);
        $comments = $conn->real_escape_string($_POST['comments']);
        
        // Validate the appointment belongs to the receptionist's hospital
        $validate_sql = "SELECT i.*, i.patient_id, p.first_name, p.last_name, p.email, d.first_name as doctor_first_name, d.last_name as doctor_last_name 
                        FROM immunizations i 
                        JOIN patients p ON i.patient_id = p.id 
                        LEFT JOIN doctors d ON d.id = ? 
                        WHERE i.id = ? AND i.hospital_id = ?";
        $validate_stmt = $conn->prepare($validate_sql);
        $validate_stmt->bind_param("iii", $doctor_id, $immunization_id, $receptionist_hospital_id);
        $validate_stmt->execute();
        $validate_result = $validate_stmt->get_result();
        
        if ($validate_result->num_rows > 0) {
            $appointment_data = $validate_result->fetch_assoc();
            $patient_id = $appointment_data['patient_id']; // Get patient_id for allergies and labresults
            
            // Start transaction
            $conn->begin_transaction();
            try {
                // Update the immunization record with schedule and doctor
                $update_sql = "UPDATE immunizations 
                            SET schedule = ?, appointment_time = ?, doctor_id = ?, 
                                comments = ?, status = 'scheduled'
                            WHERE id = ?";
                $update_stmt = $conn->prepare($update_sql);
                $update_stmt->bind_param("ssssi", $schedule_date, $schedule_time, $doctor_id, $comments, $immunization_id);
                
                if ($update_stmt->execute()) {
                    // Set patient_id and doctor_id in allergies table if not already set
                    $check_allergies_sql = "SELECT id FROM allergies WHERE patient_id = ? AND doctor_id IS NULL";
                    $check_allergies_stmt = $conn->prepare($check_allergies_sql);
                    $check_allergies_stmt->bind_param("i", $patient_id);
                    $check_allergies_stmt->execute();
                    $allergies_result = $check_allergies_stmt->get_result();
                    
                    if ($allergies_result->num_rows > 0) {
                        // Update existing allergies records with doctor_id
                        $update_allergies_sql = "UPDATE allergies SET doctor_id = ? WHERE patient_id = ? AND doctor_id IS NULL";
                        $update_allergies_stmt = $conn->prepare($update_allergies_sql);
                        $update_allergies_stmt->bind_param("ii", $doctor_id, $patient_id);
                        $update_allergies_stmt->execute();
                        $update_allergies_stmt->close();
                    }
                    $check_allergies_stmt->close();
                    
                    // Set patient_id and doctor_id in labresults table if not already set
                    $check_labresults_sql = "SELECT id FROM labresults WHERE patient_id = ? AND doctor_id IS NULL";
                    $check_labresults_stmt = $conn->prepare($check_labresults_sql);
                    $check_labresults_stmt->bind_param("i", $patient_id);
                    $check_labresults_stmt->execute();
                    $labresults_result = $check_labresults_stmt->get_result();
                    
                    if ($labresults_result->num_rows > 0) {
                        // Update existing labresults records with doctor_id
                        $update_labresults_sql = "UPDATE labresults SET doctor_id = ? WHERE patient_id = ? AND doctor_id IS NULL";
                        $update_labresults_stmt = $conn->prepare($update_labresults_sql);
                        $update_labresults_stmt->bind_param("ii", $doctor_id, $patient_id);
                        $update_labresults_stmt->execute();
                        $update_labresults_stmt->close();
                    }
                    $check_labresults_stmt->close();
                    
                    // Send email notification to patient
                    $patient_email = $appointment_data['email'];
                    $patient_name = $appointment_data['first_name'] . ' ' . $appointment_data['last_name'];
                    $doctor_name = $appointment_data['doctor_first_name'] . ' ' . $appointment_data['doctor_last_name'];
                    $vaccine_type = $appointment_data['vaccine_type'];
                    
                    $email_sent = sendAppointmentEmail(
                        $patient_email, 
                        $patient_name, 
                        $schedule_date, 
                        $schedule_time, 
                        $doctor_name, 
                        $vaccine_type, 
                        $hospital_name, 
                        $comments
                    );
                    
                    // Commit the transaction
                    $conn->commit();
                    
                    if ($email_sent) {
                        $_SESSION['success_message'] = "Appointment scheduled successfully! Email notification sent to patient.";
                    } else {
                        $_SESSION['success_message'] = "Appointment scheduled successfully! However, there was an issue sending the email notification.";
                    }
                    
                    // Generate a new token for the next submission
                    $_SESSION['form_token'] = bin2hex(random_bytes(32));
                    
                    // Redirect to the same page to prevent form resubmission
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit;
                } else {
                    // Rollback the transaction
                    $conn->rollback();
                    $_SESSION['error_message'] = "Error scheduling appointment: " . $conn->error;
                    
                    // Redirect to the same page
                    header("Location: " . $_SERVER['PHP_SELF']);
                    exit;
                }
                $update_stmt->close();
            } catch (Exception $e) {
                // Rollback the transaction
                $conn->rollback();
                $_SESSION['error_message'] = "Error: " . $e->getMessage();
                
                // Redirect to the same page
                header("Location: " . $_SERVER['PHP_SELF']);
                exit;
            }
        } else {
            $_SESSION['error_message'] = "Invalid appointment or not associated with your hospital.";
            
            // Redirect to the same page
            header("Location: " . $_SERVER['PHP_SELF']);
            exit;
        }
        $validate_stmt->close();
    } else {
        // This is a duplicate submission, ignore it
        $_SESSION['error_message'] = "Form already submitted. Please refresh the page to submit a new form.";
        // Redirect to the same page
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
}

// Handle mark as overdue action
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['mark_as_overdue'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in mark as overdue');
        $_SESSION['error_message'] = "Security token mismatch. Please try again.";
        header("Location: " . $_SERVER['PHP_SELF']);
        exit;
    }
    
    $immunization_id = $conn->real_escape_string($_POST['immunization_id']);
    
    // Validate the appointment belongs to the receptionist's hospital
    $validate_sql = "SELECT id FROM immunizations WHERE id = ? AND hospital_id = ?";
    $validate_stmt = $conn->prepare($validate_sql);
    $validate_stmt->bind_param("ii", $immunization_id, $receptionist_hospital_id);
    $validate_stmt->execute();
    $validate_result = $validate_stmt->get_result();
    
    if ($validate_result->num_rows > 0) {
        // Start transaction
        $conn->begin_transaction();
        
        try {
            // Update the immunization status to overdue
            $update_sql = "UPDATE immunizations SET status = 'overdue' WHERE id = ?";
            $update_stmt = $conn->prepare($update_sql);
            $update_stmt->bind_param("i", $immunization_id);
            
            if ($update_stmt->execute()) {
                // Commit the transaction
                $conn->commit();
                $_SESSION['success_message'] = "Appointment marked as overdue successfully.";
            } else {
                // Rollback the transaction
                $conn->rollback();
                $_SESSION['error_message'] = "Error updating appointment status: " . $conn->error;
            }
            
            $update_stmt->close();
        } catch (Exception $e) {
            // Rollback the transaction
            $conn->rollback();
            $_SESSION['error_message'] = "Error: " . $e->getMessage();
        }
    } else {
        $_SESSION['error_message'] = "Invalid appointment or not associated with your hospital.";
    }
    
    // Redirect to the same page
    header("Location: " . $_SERVER['PHP_SELF']);
    exit;
}

// Build WHERE clause for filtering
$where_conditions = ["i.hospital_id = ?"];
$params = [$receptionist_hospital_id];
$param_types = "i";

// Handle filters
$name_filter = isset($_GET['name_filter']) ? trim($_GET['name_filter']) : '';
$status_filter = isset($_GET['status_filter']) ? trim($_GET['status_filter']) : '';
$vaccine_filter = isset($_GET['vaccine_filter']) ? trim($_GET['vaccine_filter']) : '';

if (!empty($name_filter)) {
    $where_conditions[] = "(p.first_name LIKE ? OR p.last_name LIKE ? OR CONCAT(p.first_name, ' ', p.last_name) LIKE ?)";
    $name_search = '%' . $name_filter . '%';
    $params[] = $name_search;
    $params[] = $name_search;
    $params[] = $name_search;
    $param_types .= "sss";
}

if (!empty($status_filter)) {
    $where_conditions[] = "i.status = ?";
    $params[] = $status_filter;
    $param_types .= "s";
}

if (!empty($vaccine_filter)) {
    $where_conditions[] = "i.vaccine_type = ?";
    $params[] = $vaccine_filter;
    $param_types .= "s";
}

$where_clause = implode(" AND ", $where_conditions);

// Fetch pending immunization requests for this hospital
$sql_pending = "SELECT i.*, p.first_name as patient_first_name, p.last_name as patient_last_name 
                FROM immunizations i 
                JOIN patients p ON i.patient_id = p.id 
                WHERE $where_clause AND i.schedule IS NULL 
                ORDER BY i.request_date DESC";
$stmt_pending = $conn->prepare($sql_pending);
$stmt_pending->bind_param($param_types, ...$params);
$stmt_pending->execute();
$result_pending = $stmt_pending->get_result();
$pending_immunizations = [];
while ($row = $result_pending->fetch_assoc()) {
    $pending_immunizations[] = $row;
}
$stmt_pending->close();

// Fetch scheduled immunization requests for this hospital
$sql_scheduled = "SELECT i.*, p.first_name as patient_first_name, p.last_name as patient_last_name,
                  d.first_name as doctor_first_name, d.last_name as doctor_last_name, d.specialization,
                  DATEDIFF(CURDATE(), i.schedule) as days_overdue
                  FROM immunizations i 
                  JOIN patients p ON i.patient_id = p.id 
                  LEFT JOIN doctors d ON i.doctor_id = d.id
                  WHERE $where_clause AND i.schedule IS NOT NULL 
                  ORDER BY i.schedule DESC, i.appointment_time ASC";
$stmt_scheduled = $conn->prepare($sql_scheduled);
$stmt_scheduled->bind_param($param_types, ...$params);
$stmt_scheduled->execute();
$result_scheduled = $stmt_scheduled->get_result();
$scheduled_immunizations = [];
while ($row = $result_scheduled->fetch_assoc()) {
    $scheduled_immunizations[] = $row;
}
$stmt_scheduled->close();

// Fetch overdue/scheduled appointments
$sql_overdue_scheduled = "SELECT i.*, p.first_name as patient_first_name, p.last_name as patient_last_name,
                         DATEDIFF(CURDATE(), i.schedule) as days_overdue
                         FROM immunizations i 
                         JOIN patients p ON i.patient_id = p.id 
                         WHERE $where_clause AND i.schedule IS NOT NULL AND i.status IN ('pending', 'scheduled')
                         ORDER BY i.schedule ASC";
$stmt_overdue_scheduled = $conn->prepare($sql_overdue_scheduled);
$stmt_overdue_scheduled->bind_param($param_types, ...$params);
$stmt_overdue_scheduled->execute();
$result_overdue_scheduled = $stmt_overdue_scheduled->get_result();
$overdue_scheduled_immunizations = [];
while ($row = $result_overdue_scheduled->fetch_assoc()) {
    $overdue_scheduled_immunizations[] = $row;
}
$stmt_overdue_scheduled->close();

// Get unique vaccine types for filter
$sql_vaccine_types = "SELECT DISTINCT vaccine_type FROM immunizations WHERE hospital_id = ? ORDER BY vaccine_type";
$stmt_vaccine_types = $conn->prepare($sql_vaccine_types);
$stmt_vaccine_types->bind_param("i", $receptionist_hospital_id);
$stmt_vaccine_types->execute();
$result_vaccine_types = $stmt_vaccine_types->get_result();
$vaccine_types = [];
while ($row = $result_vaccine_types->fetch_assoc()) {
    $vaccine_types[] = $row['vaccine_type'];
}
$stmt_vaccine_types->close();

// AJAX endpoint for doctor search
if (isset($_GET['search_doctor'])) {
    $search = '%' . $conn->real_escape_string($_GET['search_doctor']) . '%';
    $hospital_id = $conn->real_escape_string($_GET['hospital_id']);
    
    $sql = "SELECT d.id, d.first_name, d.last_name, d.specialization 
            FROM doctors d
            WHERE d.hospital_id = ? AND (d.first_name LIKE ? OR d.last_name LIKE ? OR d.specialization LIKE ?)
            ORDER BY d.last_name ASC LIMIT 10";
    
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("isss", $hospital_id, $search, $search, $search);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $doctors = [];
    while ($row = $result->fetch_assoc()) {
        $doctors[] = $row;
    }
    
    header('Content-Type: application/json');
    echo json_encode($doctors);
    exit;
}

// Handle patient search by email
if ($_SERVER["REQUEST_METHOD"] === "POST" && isset($_POST['email'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logSecurityEvent($conn, $user_email, 'CSRF_TOKEN_MISMATCH', $ip_address, $user_agent, 'CSRF token mismatch in patient search');
        echo json_encode(['error' => 'Security token mismatch.']);
        exit;
    }
    
    $email = trim($_POST['email']);
    error_log("Searching for email: " . $email);

    // MODIFIED: Removed registration_status filter from the query
    $query = "
        SELECT 
            p.first_name, 
            p.last_name, 
            p.email, 
            p.gender, 
            p.age,
            ph.registration_status
        FROM patients p
        JOIN patient_hospital ph ON p.id = ph.patient_id
        WHERE LOWER(p.email) = LOWER(?) AND ph.hospital_id = ?
    ";

    $stmt = $conn->prepare($query);
    if (!$stmt) {
        error_log("Patient search query preparation failed: " . $conn->error);
        echo json_encode(['error' => 'Database error occurred.']);
        exit;
    }
    $stmt->bind_param("si", $email, $receptionist_hospital_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        $patient_data = $result->fetch_assoc();
        error_log("Patient found: " . json_encode($patient_data));

        // MODIFIED: All patients are considered "active" for display purposes
        $statusColor = 'green';

        echo json_encode([
            'first_name' => $patient_data['first_name'],
            'last_name' => $patient_data['last_name'],
            'email' => $patient_data['email'],
            'gender' => $patient_data['gender'],
            'age' => $patient_data['age'],
            'registration_status' => $patient_data['registration_status'],
            'statusColor' => $statusColor
        ]);
    } else {
        error_log("No patient found for email: $email and hospital ID: $receptionist_hospital_id");
        echo json_encode(['error' => 'Patient not found in this hospital.']);
    }

    exit;
}

// Handle POST request for enhanced security
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Handle session refresh
    if (isset($_POST['action']) && $_POST['action'] === 'heartbeat') {
        // CSRF token validation
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
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
        if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
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
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Receptionist Dashboard - Healthcare Portal</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- FontAwesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <!-- Flatpickr for date/time picker -->
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/flatpickr/dist/flatpickr.min.css">
    <script src="https://cdn.jsdelivr.net/npm/flatpickr"></script>
    <!-- Alpine.js for reactivity -->
    <script src="https://cdn.jsdelivr.net/npm/alpinejs@3.14.8/dist/cdn.min.js" defer></script>
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
    --purple: #8b5cf6;
    
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
}

/* Video Background */
.video-background {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    z-index: -1;
    overflow: hidden;
}

.video-background video {
    position: absolute;
    top: 50%;
    left: 50%;
    min-width: 100%;
    min-height: 100%;
    width: auto;
    height: auto;
    transform: translateX(-50%) translateY(-50%);
    object-fit: cover;
}

.video-overlay {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: linear-gradient(135deg, rgba(15, 23, 42, 0.85), rgba(15, 23, 42, 0.75));
    z-index: 1;
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

/* Main Content Styles */
.main-content {
    flex: 1;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
}

/* Header Styles - Updated for 2025 */
.header {
    background: rgba(15, 23, 42, 0.75);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    padding: 1.25rem 2rem;
    position: sticky;
    top: 0;
    z-index: 50;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
    transition: padding 0.3s ease;
}

.header-title {
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--light);
    background: linear-gradient(to right, #fff, #60a5fa);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
    position: relative;
}

.header-title::after {
    content: '';
    position: absolute;
    bottom: -5px;
    left: 0;
    width: 40px;
    height: 3px;
    background: linear-gradient(to right, var(--primary), var(--accent));
    border-radius: 2px;
}

.header-actions {
    display: flex;
    align-items: center;
    gap: 1.25rem;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    padding: 0.5rem 1rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: var(--radius-full);
    border: 1px solid rgba(255, 255, 255, 0.1);
    transition: var(--transition);
}

.user-info:hover {
    background: rgba(255, 255, 255, 0.1);
}

.user-name {
    color: var(--light);
    font-weight: 600;
}

.logout-btn {
    padding: 0.5rem 1rem;
    background: rgba(239, 68, 68, 0.15);
    color: var(--danger);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-weight: 600;
    transition: var(--transition);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.logout-btn:hover {
    background: rgba(239, 68, 68, 0.25);
    transform: translateY(-2px);
}

/* FAQ Button */
.faq-btn {
    padding: 0.5rem 1rem;
    background: rgba(16, 185, 129, 0.15);
    color: var(--secondary);
    border: none;
    border-radius: var(--radius-md);
    cursor: pointer;
    font-weight: 600;
    transition: var(--transition);
    display: flex;
    align-items: center;
    gap: 0.5rem;
    text-decoration: none;
}

.faq-btn:hover {
    background: rgba(16, 185, 129, 0.25);
    transform: translateY(-2px);
}

/* Notification Icon - Enhanced for 2025 */
.notification-container {
    position: relative;
    margin-right: 0.5rem;
}

.notification-icon {
    color: var(--light);
    font-size: 1.5rem;
    cursor: pointer;
    transition: var(--transition);
    padding: 0.5rem;
    border-radius: var(--radius-full);
    background: rgba(255, 255, 255, 0.05);
}

.notification-icon:hover {
    color: var(--primary-light);
    background: rgba(255, 255, 255, 0.1);
    transform: translateY(-2px);
}

.notification-badge {
    position: absolute;
    top: -5px;
    right: -5px;
    background: var(--danger);
    color: white;
    border-radius: 50%;
    width: 22px;
    height: 22px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.75rem;
    font-weight: 600;
    box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
    animation: pulse 2s infinite;
}

@keyframes pulse {
    0% {
        box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7);
    }
    70% {
        box-shadow: 0 0 0 10px rgba(239, 68, 68, 0);
    }
    100% {
        box-shadow: 0 0 0 0 rgba(239, 68, 68, 0);
    }
}

/* Dashboard Content - Modern 2025 Style */
.dashboard {
    padding: 2rem;
    flex: 1;
    background: transparent;
    color: var(--light);
}

.dashboard-title {
    margin-bottom: 2rem;
    position: relative;
    padding-left: 1.25rem;
}

.dashboard-title::before {
    content: '';
    position: absolute;
    left: 0;
    top: 0.5rem;
    height: 80%;
    width: 4px;
    background: linear-gradient(to bottom, var(--primary), var(--secondary));
    border-radius: 4px;
}

.dashboard-heading {
    font-size: 2.25rem;
    font-weight: 700;
    margin-bottom: 0.75rem;
    background: linear-gradient(to right, #fff, #60a5fa);
    -webkit-background-clip: text;
    background-clip: text;
    color: transparent;
}

.dashboard-subheading {
    font-size: 1.1rem;
    color: rgba(255, 255, 255, 0.8);
}

/* Stats Cards - New for 2025 */
.stats-container {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1.5rem;
    margin-bottom: 2rem;
}

.stat-card {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
    transition: var(--transition);
    position: relative;
    overflow: hidden;
}

.stat-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 3px;
    background: linear-gradient(to right, var(--primary), var(--secondary));
}

.stat-card:hover {
    transform: translateY(-5px);
    box-shadow: var(--shadow-xl);
    border-color: rgba(255, 255, 255, 0.2);
}

.stat-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.stat-icon {
    width: 3rem;
    height: 3rem;
    border-radius: var(--radius-lg);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.5rem;
    color: white;
}

.stat-icon.pending {
    background: linear-gradient(135deg, var(--warning), #fbbf24);
}

.stat-icon.today {
    background: linear-gradient(135deg, var(--primary), var(--primary-light));
}

.stat-icon.patients {
    background: linear-gradient(135deg, var(--secondary), var(--secondary-light));
}

.stat-icon.overdue {
    background: linear-gradient(135deg, var(--danger), #f87171);
}

.stat-number {
    font-size: 2.5rem;
    font-weight: 800;
    color: var(--light);
    line-height: 1;
}

.stat-label {
    color: rgba(255, 255, 255, 0.8);
    font-weight: 500;
    margin-top: 0.5rem;
}

/* Filters Section - Enhanced for 2025 */
.filters-section {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    margin-bottom: 2rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.filters-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--light);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.filters-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
    gap: 1rem;
}

.filter-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.filter-label {
    color: rgba(255, 255, 255, 0.9);
    font-weight: 500;
    font-size: 0.875rem;
}

.filter-input, .filter-select {
    padding: 0.75rem 1rem;
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.05);
    color: var(--light);
    font-size: 0.875rem;
    transition: var(--transition);
}

.filter-input:focus, .filter-select:focus {
    outline: none;
    border-color: var(--primary);
    background: rgba(255, 255, 255, 0.1);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.filter-input::placeholder {
    color: rgba(255, 255, 255, 0.5);
}

.filter-select option {
    background: var(--dark);
    color: var(--light);
}

.filter-actions {
    display: flex;
    gap: 0.75rem;
    align-items: end;
}

.filter-btn {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: var(--radius-md);
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.filter-btn.primary {
    background: var(--primary);
    color: white;
}

.filter-btn.primary:hover {
    background: var(--primary-dark);
    transform: translateY(-2px);
}

.filter-btn.secondary {
    background: rgba(255, 255, 255, 0.1);
    color: var(--light);
    border: 1px solid rgba(255, 255, 255, 0.2);
}

.filter-btn.secondary:hover {
    background: rgba(255, 255, 255, 0.2);
}

/* Tabs - Modern 2025 Design */
.tabs-container {
    margin-bottom: 2rem;
}

.tabs-nav {
    display: flex;
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    border-radius: var(--radius-lg);
    padding: 0.5rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
    gap: 0.5rem;
}

.tab-btn {
    flex: 1;
    padding: 0.875rem 1.5rem;
    border: none;
    background: transparent;
    color: rgba(255, 255, 255, 0.7);
    border-radius: var(--radius-md);
    cursor: pointer;
    font-weight: 600;
    transition: var(--transition);
    position: relative;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.tab-btn.active {
    background: var(--primary);
    color: white;
    box-shadow: var(--shadow-md);
}

.tab-btn:hover:not(.active) {
    background: rgba(255, 255, 255, 0.1);
    color: var(--light);
}

.tab-content {
    display: none;
}

.tab-content.active {
    display: block;
}

/* Tables - Enhanced for 2025 */
.table-container {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    border-radius: var(--radius-lg);
    overflow: hidden;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: var(--shadow-lg);
}

.table-header {
    padding: 1.5rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.table-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--light);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.table-count {
    background: var(--primary);
    color: white;
    padding: 0.25rem 0.75rem;
    border-radius: var(--radius-full);
    font-size: 0.875rem;
    font-weight: 600;
}

.table-wrapper {
    overflow-x: auto;
}

.data-table {
    width: 100%;
    border-collapse: collapse;
}

.data-table th {
    background: rgba(255, 255, 255, 0.05);
    color: var(--light);
    font-weight: 600;
    padding: 1rem;
    text-align: left;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    font-size: 0.875rem;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}

.data-table td {
    padding: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.05);
    color: rgba(255, 255, 255, 0.9);
    vertical-align: middle;
}

.data-table tr:hover {
    background: rgba(255, 255, 255, 0.02);
}

/* Status Badges - Updated Colors */
.status-badge {
    padding: 0.375rem 0.875rem;
    border-radius: var(--radius-full);
    font-size: 0.75rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    display: inline-flex;
    align-items: center;
    gap: 0.375rem;
}

.status-badge::before {
    content: '';
    width: 6px;
    height: 6px;
    border-radius: 50%;
    background: currentColor;
}

.status-badge.completed {
    background: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border: 1px solid rgba(16, 185, 129, 0.3);
}

.status-badge.pending {
    background: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border: 1px solid rgba(245, 158, 11, 0.3);
}

.status-badge.overdue {
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.status-badge.scheduled {
    background: rgba(59, 130, 246, 0.15);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.3);
}

.status-badge.canceled {
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border: 1px solid rgba(239, 68, 68, 0.3);
}

.status-badge.attended {
    background: rgba(59, 130, 246, 0.15);
    color: #3b82f6;
    border: 1px solid rgba(59, 130, 246, 0.3);
}

/* Action Buttons */
.action-buttons {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.action-btn {
    padding: 0.5rem 1rem;
    border: none;
    border-radius: var(--radius-md);
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: var(--transition);
    display: flex;
    align-items: center;
    gap: 0.375rem;
    text-decoration: none;
}

.action-btn.schedule {
    background: var(--primary);
    color: white;
}

.action-btn.schedule:hover {
    background: var(--primary-dark);
    transform: translateY(-2px);
}

.action-btn.reschedule {
    background: var(--warning);
    color: white;
}

.action-btn.reschedule:hover {
    background: #d97706;
    transform: translateY(-2px);
}

.action-btn.overdue {
    background: var(--danger);
    color: white;
}

.action-btn.overdue:hover {
    background: #dc2626;
    transform: translateY(-2px);
}

.action-btn.attended {
    background: var(--secondary);
    color: white;
}

.action-btn.attended:hover {
    background: var(--secondary-dark);
    transform: translateY(-2px);
}

.action-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none !important;
}

/* Modal Styles - Enhanced for 2025 */
.modal {
    display: none;
    position: fixed;
    z-index: 1000;
    left: 0;
    top: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.7);
    backdrop-filter: blur(8px);
    animation: fadeIn 0.3s ease;
}

.modal.show {
    display: flex;
    align-items: center;
    justify-content: center;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.modal-content {
    background: rgba(15, 23, 42, 0.95);
    backdrop-filter: blur(20px);
    border-radius: var(--radius-lg);
    padding: 2rem;
    width: 90%;
    max-width: 600px;
    max-height: 90vh;
    overflow-y: auto;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: var(--shadow-xl);
    animation: slideUp 0.3s ease;
    position: relative;
}

@keyframes slideUp {
    from {
        opacity: 0;
        transform: translateY(50px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
    padding-bottom: 1rem;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.modal-title {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--light);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.close-btn {
    background: none;
    border: none;
    font-size: 1.5rem;
    color: rgba(255, 255, 255, 0.7);
    cursor: pointer;
    padding: 0.5rem;
    border-radius: var(--radius-md);
    transition: var(--transition);
}

.close-btn:hover {
    color: var(--light);
    background: rgba(255, 255, 255, 0.1);
}

/* Form Styles */
.form-group {
    margin-bottom: 1.5rem;
}

.form-label {
    display: block;
    margin-bottom: 0.5rem;
    color: var(--light);
    font-weight: 500;
}

.form-input, .form-select, .form-textarea {
    width: 100%;
    padding: 0.875rem 1rem;
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: var(--radius-md);
    background: rgba(255, 255, 255, 0.05);
    color: var(--light);
    font-size: 0.875rem;
    transition: var(--transition);
}

.form-input:focus, .form-select:focus, .form-textarea:focus {
    outline: none;
    border-color: var(--primary);
    background: rgba(255, 255, 255, 0.1);
    box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
}

.form-input::placeholder {
    color: rgba(255, 255, 255, 0.5);
}

.form-select option {
    background: var(--dark);
    color: var(--light);
}

.form-textarea {
    resize: vertical;
    min-height: 100px;
}

/* Doctor Search */
.doctor-search-container {
    position: relative;
}

.doctor-suggestions {
    position: absolute;
    top: 100%;
    left: 0;
    right: 0;
    background: rgba(15, 23, 42, 0.95);
    backdrop-filter: blur(12px);
    border: 1px solid rgba(255, 255, 255, 0.2);
    border-radius: var(--radius-md);
    max-height: 200px;
    overflow-y: auto;
    z-index: 1000;
    box-shadow: var(--shadow-lg);
}

.doctor-suggestion {
    padding: 0.875rem 1rem;
    cursor: pointer;
    border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    color: var(--light);
    transition: var(--transition);
}

.doctor-suggestion:hover {
    background: rgba(255, 255, 255, 0.1);
}

.doctor-suggestion:last-child {
    border-bottom: none;
}

.doctor-name {
    font-weight: 600;
    margin-bottom: 0.25rem;
}

.doctor-specialization {
    font-size: 0.875rem;
    color: rgba(255, 255, 255, 0.7);
}

/* Patient Search */
.patient-search-section {
    background: rgba(15, 23, 42, 0.6);
    backdrop-filter: blur(12px);
    border-radius: var(--radius-lg);
    padding: 1.5rem;
    margin-bottom: 2rem;
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.patient-search-title {
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--light);
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.search-form {
    display: flex;
    gap: 1rem;
    align-items: end;
}

.search-input-group {
    flex: 1;
}

.search-btn {
    padding: 0.875rem 1.5rem;
    background: var(--primary);
    color: white;
    border: none;
    border-radius: var(--radius-md);
    font-weight: 600;
    cursor: pointer;
    transition: var(--transition);
    display: flex;
    align-items: center;
    gap: 0.5rem;
}

.search-btn:hover {
    background: var(--primary-dark);
    transform: translateY(-2px);
}

.patient-info {
    margin-top: 1.5rem;
    padding: 1.5rem;
    background: rgba(255, 255, 255, 0.05);
    border-radius: var(--radius-md);
    border: 1px solid rgba(255, 255, 255, 0.1);
}

.patient-details {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
}

.patient-detail {
    display: flex;
    flex-direction: column;
    gap: 0.25rem;
}

.detail-label {
    font-size: 0.875rem;
    color: rgba(255, 255, 255, 0.7);
    font-weight: 500;
}

.detail-value {
    color: var(--light);
    font-weight: 600;
}

/* Alerts */
.alert {
    padding: 1rem 1.5rem;
    border-radius: var(--radius-md);
    margin-bottom: 1.5rem;
    display: flex;
    align-items: center;
    gap: 0.75rem;
    font-weight: 500;
    border: 1px solid;
    backdrop-filter: blur(8px);
}

.alert.success {
    background: rgba(16, 185, 129, 0.15);
    color: #10b981;
    border-color: rgba(16, 185, 129, 0.3);
}

.alert.error {
    background: rgba(239, 68, 68, 0.15);
    color: #ef4444;
    border-color: rgba(239, 68, 68, 0.3);
}

.alert.info {
    background: rgba(59, 130, 246, 0.15);
    color: #3b82f6;
    border-color: rgba(59, 130, 246, 0.3);
}

.alert.warning {
    background: rgba(245, 158, 11, 0.15);
    color: #f59e0b;
    border-color: rgba(245, 158, 11, 0.3);
}

/* Loading States */
.loading {
    display: inline-flex;
    align-items: center;
    gap: 0.5rem;
    color: rgba(255, 255, 255, 0.7);
}

.spinner {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top: 2px solid var(--primary);
    border-radius: 50%;
    animation: spin 1s linear infinite;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Empty States */
.empty-state {
    text-align: center;
    padding: 3rem 2rem;
    color: rgba(255, 255, 255, 0.7);
}

.empty-icon {
    font-size: 3rem;
    margin-bottom: 1rem;
    opacity: 0.5;
}

.empty-title {
    font-size: 1.25rem;
    font-weight: 600;
    margin-bottom: 0.5rem;
    color: var(--light);
}

.empty-message {
    margin-bottom: 1.5rem;
}

/* Responsive Design */
@media (max-width: 1024px) {
    .dashboard {
        padding: 1.5rem;
    }
    
    .stats-container {
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
    }
    
    .filters-grid {
        grid-template-columns: 1fr;
    }
    
    .tabs-nav {
        flex-direction: column;
        gap: 0.25rem;
    }
}

@media (max-width: 768px) {
    .header {
        padding: 1rem;
        flex-direction: column;
        gap: 1rem;
    }
    
    .header-actions {
        width: 100%;
        justify-content: space-between;
    }
    
    .dashboard {
        padding: 1rem;
    }
    
    .dashboard-heading {
        font-size: 1.75rem;
    }
    
    .stats-container {
        grid-template-columns: 1fr;
    }
    
    .search-form {
        flex-direction: column;
        align-items: stretch;
    }
    
    .patient-details {
        grid-template-columns: 1fr;
    }
    
    .modal-content {
        width: 95%;
        padding: 1.5rem;
        margin: 1rem;
    }
    
    .action-buttons {
        flex-direction: column;
    }
    
    .action-btn {
        width: 100%;
        justify-content: center;
    }
    
    .data-table {
        font-size: 0.875rem;
    }
    
    .data-table th,
    .data-table td {
        padding: 0.75rem 0.5rem;
    }
}

@media (max-width: 480px) {
    .header-title {
        font-size: 1.5rem;
    }
    
    .dashboard-heading {
        font-size: 1.5rem;
    }
    
    .stat-number {
        font-size: 2rem;
    }
    
    .modal-content {
        padding: 1rem;
    }
    
    .table-wrapper {
        overflow-x: scroll;
    }
    
    .data-table {
        min-width: 600px;
    }
}

/* Print Styles */
@media print {
    .header,
    .filters-section,
    .patient-search-section,
    .action-buttons {
        display: none !important;
    }
    
    .dashboard {
        background: white !important;
        color: black !important;
    }
    
    .table-container {
        background: white !important;
        box-shadow: none !important;
        border: 1px solid #ccc !important;
    }
    
    .data-table th,
    .data-table td {
        color: black !important;
        border: 1px solid #ccc !important;
    }
}

/* Accessibility Improvements */
.sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
}

/* Focus styles for better accessibility */
button:focus,
input:focus,
select:focus,
textarea:focus,
a:focus {
    outline: 2px solid var(--primary);
    outline-offset: 2px;
}

/* High contrast mode support */
@media (prefers-contrast: high) {
    :root {
        --primary: #0066cc;
        --secondary: #009900;
        --danger: #cc0000;
        --warning: #cc6600;
    }
}

/* Reduced motion support */
@media (prefers-reduced-motion: reduce) {
    *,
    *::before,
    *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
    }
}
    </style>
</head>
<body>
    <!-- Video Background -->
    <div class="video-background">
        <video autoplay muted loop>
            <source src="../uploads/videos/bgv.mp4" type="video/mp4">
        </video>
        <div class="video-overlay"></div>
    </div>

    <div class="app-container">
        <main class="main-content">
            <!-- Header -->
            <header class="header">
                <div class="header-title">
                    <i class="fas fa-user-md"></i>
                    Receptionist Dashboard
                </div>
                <div class="header-actions">
                    <!-- FAQ Button -->
                    <a href="../faq.php" class="faq-btn">
                        <i class="fas fa-question-circle"></i>
                        FAQ
                    </a>
                    
                    <!-- Notification Icon -->
                    <div class="notification-container">
                        <i class="fas fa-bell notification-icon"></i>
                        <?php if ($pending_count > 0): ?>
                        <span class="notification-badge"><?php echo $pending_count; ?></span>
                        <?php endif; ?>
                    </div>
                    
                    <!-- User Info (without profile picture) -->
                    <div class="user-info">
                        <div>
                            <div class="user-name"><?php echo $first_name . ' ' . $last_name; ?></div>
                            <div style="font-size: 0.875rem; color: rgba(255,255,255,0.7);"><?php echo $hospital_name; ?></div>
                        </div>
                    </div>
                    
                    <!-- Logout Button -->
                    <button class="logout-btn" onclick="logout()">
                        <i class="fas fa-sign-out-alt"></i>
                        Logout
                    </button>
                </div>
            </header>

            <!-- Dashboard Content -->
            <div class="dashboard">
                <!-- Dashboard Title -->
                <div class="dashboard-title">
                    <h1 class="dashboard-heading">Welcome back, <?php echo $first_name; ?>!</h1>
                    <p class="dashboard-subheading">Manage appointments and patient records for <?php echo $hospital_name; ?></p>
                </div>

                <!-- Stats Cards -->
                <div class="stats-container">
                    <div class="stat-card">
                        <div class="stat-header">
                            <div class="stat-icon pending">
                                <i class="fas fa-clock"></i>
                            </div>
                        </div>
                        <div class="stat-number"><?php echo $pending_count; ?></div>
                        <div class="stat-label">Pending Appointments</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-header">
                            <div class="stat-icon today">
                                <i class="fas fa-calendar-day"></i>
                            </div>
                        </div>
                        <div class="stat-number"><?php echo $today_count; ?></div>
                        <div class="stat-label">Today's Appointments</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-header">
                            <div class="stat-icon patients">
                                <i class="fas fa-users"></i>
                            </div>
                        </div>
                        <div class="stat-number"><?php echo $patient_count; ?></div>
                        <div class="stat-label">Total Patients</div>
                    </div>
                    
                    <div class="stat-card">
                        <div class="stat-header">
                            <div class="stat-icon overdue">
                                <i class="fas fa-exclamation-triangle"></i>
                            </div>
                        </div>
                        <div class="stat-number"><?php echo $overdue_count; ?></div>
                        <div class="stat-label">Overdue Appointments</div>
                    </div>
                </div>

                <!-- Success/Error Messages -->
                <?php if (!empty($success_message)): ?>
                <div class="alert success">
                    <i class="fas fa-check-circle"></i>
                    <?php echo $success_message; ?>
                </div>
                <?php endif; ?>

                <?php if (!empty($error_message)): ?>
                <div class="alert error">
                    <i class="fas fa-exclamation-circle"></i>
                    <?php echo $error_message; ?>
                </div>
                <?php endif; ?>

                <!-- Patient Search Section -->
                <div class="patient-search-section">
                    <h2 class="patient-search-title">
                        <i class="fas fa-search"></i>
                        Patient Search
                    </h2>
                    <form class="search-form" id="patientSearchForm">
                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                        <div class="search-input-group">
                            <label class="form-label">Patient Email</label>
                            <input type="email" name="email" class="form-input" placeholder="Enter patient email address" required>
                        </div>
                        <button type="submit" class="search-btn">
                            <i class="fas fa-search"></i>
                            Search
                        </button>
                    </form>
                    
                    <div id="patientInfo" class="patient-info" style="display: none;">
                        <div class="patient-details" id="patientDetails">
                            <!-- Patient details will be populated here -->
                        </div>
                    </div>
                </div>

                <!-- Filters Section -->
                <div class="filters-section">
                    <h2 class="filters-title">
                        <i class="fas fa-filter"></i>
                        Filter Appointments
                    </h2>
                    <form method="GET" class="filters-grid">
                        <div class="filter-group">
                            <label class="filter-label">Search by Patient Name</label>
                            <input type="text" name="name_filter" class="filter-input" 
                                   placeholder="Enter patient name" 
                                   value="<?php echo htmlspecialchars($name_filter); ?>">
                        </div>
                        
                        <div class="filter-group">
                            <label class="filter-label">Filter by Status</label>
                            <select name="status_filter" class="filter-select">
                                <option value="">All Statuses</option>
                                <option value="pending" <?php echo $status_filter === 'pending' ? 'selected' : ''; ?>>Pending</option>
                                <option value="scheduled" <?php echo $status_filter === 'scheduled' ? 'selected' : ''; ?>>Scheduled</option>
                                <option value="completed" <?php echo $status_filter === 'completed' ? 'selected' : ''; ?>>Completed</option>
                                <option value="overdue" <?php echo $status_filter === 'overdue' ? 'selected' : ''; ?>>Overdue</option>
                                <option value="canceled" <?php echo $status_filter === 'canceled' ? 'selected' : ''; ?>>Canceled</option>
                            </select>
                        </div>
                        
                        <div class="filter-group">
                            <label class="filter-label">Filter by Vaccine Type</label>
                            <select name="vaccine_filter" class="filter-select">
                                <option value="">All Vaccines</option>
                                <?php foreach ($vaccine_types as $vaccine): ?>
                                <option value="<?php echo htmlspecialchars($vaccine); ?>" 
                                        <?php echo $vaccine_filter === $vaccine ? 'selected' : ''; ?>>
                                    <?php echo htmlspecialchars($vaccine); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        
                        <div class="filter-actions">
                            <button type="submit" class="filter-btn primary">
                                <i class="fas fa-search"></i>
                                Apply Filters
                            </button>
                            <a href="<?php echo $_SERVER['PHP_SELF']; ?>" class="filter-btn secondary">
                                <i class="fas fa-times"></i>
                                Clear
                            </a>
                        </div>
                    </form>
                </div>

                <!-- Tabs -->
                <div class="tabs-container">
                    <div class="tabs-nav">
                        <button class="tab-btn active" onclick="showTab('pending')">
                            <i class="fas fa-clock"></i>
                            Pending Requests
                            <span class="table-count"><?php echo count($pending_immunizations); ?></span>
                        </button>
                        <button class="tab-btn" onclick="showTab('scheduled')">
                            <i class="fas fa-calendar-check"></i>
                            Scheduled Appointments
                            <span class="table-count"><?php echo count($scheduled_immunizations); ?></span>
                        </button>
                        <button class="tab-btn" onclick="showTab('overdue')">
                            <i class="fas fa-exclamation-triangle"></i>
                            Pending/Overdue
                            <span class="table-count"><?php echo count($overdue_scheduled_immunizations); ?></span>
                        </button>
                    </div>

                    <!-- Pending Requests Tab -->
                    <div id="pending" class="tab-content active">
                        <div class="table-container">
                            <div class="table-header">
                                <h2 class="table-title">
                                    <i class="fas fa-clock"></i>
                                    Pending Immunization Requests
                                </h2>
                            </div>
                            <div class="table-wrapper">
                                <?php if (empty($pending_immunizations)): ?>
                                <div class="empty-state">
                                    <div class="empty-icon">
                                        <i class="fas fa-inbox"></i>
                                    </div>
                                    <h3 class="empty-title">No Pending Requests</h3>
                                    <p class="empty-message">All immunization requests have been scheduled.</p>
                                </div>
                                <?php else: ?>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Patient Name</th>
                                            <th>Vaccine Type</th>
                                            <th>Request Date</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($pending_immunizations as $immunization): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?></td>
                                            <td><?php echo htmlspecialchars($immunization['vaccine_type']); ?></td>
                                            <td><?php echo date('M j, Y', strtotime($immunization['request_date'])); ?></td>
                                            <td>
                                                <span class="status-badge pending">
                                                    Pending
                                                </span>
                                            </td>
                                            <td>
                                                <div class="action-buttons">
                                                    <button class="action-btn schedule" onclick="openScheduleModal(<?php echo $immunization['id']; ?>, '<?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?>', '<?php echo htmlspecialchars($immunization['vaccine_type']); ?>')">
                                                        <i class="fas fa-calendar-plus"></i>
                                                        Schedule
                                                    </button>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Scheduled Appointments Tab -->
                    <div id="scheduled" class="tab-content">
                        <div class="table-container">
                            <div class="table-header">
                                <h2 class="table-title">
                                    <i class="fas fa-calendar-check"></i>
                                    Scheduled Appointments
                                </h2>
                            </div>
                            <div class="table-wrapper">
                                <?php if (empty($scheduled_immunizations)): ?>
                                <div class="empty-state">
                                    <div class="empty-icon">
                                        <i class="fas fa-calendar"></i>
                                    </div>
                                    <h3 class="empty-title">No Scheduled Appointments</h3>
                                    <p class="empty-message">No appointments have been scheduled yet.</p>
                                </div>
                                <?php else: ?>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Patient Name</th>
                                            <th>Vaccine Type</th>
                                            <th>Schedule Date</th>
                                            <th>Time</th>
                                            <th>Doctor</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($scheduled_immunizations as $immunization): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?></td>
                                            <td><?php echo htmlspecialchars($immunization['vaccine_type']); ?></td>
                                            <td><?php echo date('M j, Y', strtotime($immunization['schedule'])); ?></td>
                                            <td><?php echo $immunization['appointment_time'] ? date('h:i A', strtotime($immunization['appointment_time'])) : 'Not set'; ?></td>
                                            <td>
                                                <?php if ($immunization['doctor_first_name']): ?>
                                                    Dr. <?php echo htmlspecialchars($immunization['doctor_first_name'] . ' ' . $immunization['doctor_last_name']); ?>
                                                    <br><small style="color: rgba(255,255,255,0.7);"><?php echo htmlspecialchars($immunization['specialization']); ?></small>
                                                <?php else: ?>
                                                    Not assigned
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?php
                                                $status = strtolower($immunization['status']);
                                                $attended = (int)($immunization['attended'] ?? 0);
                                                $status_class = '';
                                                $status_display = '';
                                                
                                                if ($status === 'scheduled') {
                                                    if ($attended === 1) {
                                                        $status_display = 'Scheduled, Attended';
                                                        $status_class = 'completed';
                                                    } else {
                                                        $status_display = 'Scheduled, Not Attended';
                                                        $status_class = 'scheduled';
                                                    }
                                                } else {
                                                    $status_display = ucfirst($immunization['status']);
                                                    switch($status) {
                                                        case 'completed':
                                                            $status_class = 'completed';
                                                            break;
                                                        case 'pending':
                                                            $status_class = 'pending';
                                                            break;
                                                        case 'overdue':
                                                            $status_class = 'overdue';
                                                            break;
                                                        case 'canceled':
                                                            $status_class = 'canceled';
                                                            break;
                                                        case 'attended':
                                                            $status_class = 'attended';
                                                            break;
                                                        default:
                                                            $status_class = 'pending';
                                                    }
                                                }
                                                ?>
                                                <span class="status-badge <?php echo $status_class; ?>">
                                                    <?php echo $status_display; ?>
                                                </span>
                                            </td>
                                            <td>
                                                <div class="action-buttons">
                                                    <?php if (!in_array(strtolower($immunization['status']), ['completed', 'pending'])): ?>
                                                    <button class="action-btn reschedule" onclick="openScheduleModal(<?php echo $immunization['id']; ?>, '<?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?>', '<?php echo htmlspecialchars($immunization['vaccine_type']); ?>')">
                                                        <i class="fas fa-calendar-alt"></i>
                                                        Reschedule
                                                    </button>
                                                    <?php endif; ?>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Pending/Overdue Tab -->
                    <div id="overdue" class="tab-content">
                        <div class="table-container">
                            <div class="table-header">
                                <h2 class="table-title">
                                    <i class="fas fa-exclamation-triangle"></i>
                                    Pending/Overdue Appointments
                                </h2>
                            </div>
                            <div class="table-wrapper">
                                <?php if (empty($overdue_scheduled_immunizations)): ?>
                                <div class="empty-state">
                                    <div class="empty-icon">
                                        <i class="fas fa-check-circle"></i>
                                    </div>
                                    <h3 class="empty-title">All Caught Up!</h3>
                                    <p class="empty-message">No pending or overdue appointments at this time.</p>
                                </div>
                                <?php else: ?>
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Patient Name</th>
                                            <th>Vaccine Type</th>
                                            <th>Schedule Date</th>
                                            <th>Days Overdue</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($overdue_scheduled_immunizations as $immunization): ?>
                                        <tr>
                                            <td><?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?></td>
                                            <td><?php echo htmlspecialchars($immunization['vaccine_type']); ?></td>
                                            <td><?php echo date('M j, Y', strtotime($immunization['schedule'])); ?></td>
                                            <td>
                                                <?php if ($immunization['days_overdue'] > 0): ?>
                                                    <span style="color: var(--danger); font-weight: 600;">
                                                        <?php echo $immunization['days_overdue']; ?> days
                                                    </span>
                                                <?php elseif ($immunization['days_overdue'] == 0): ?>
                                                    <span style="color: var(--warning); font-weight: 600;">Today</span>
                                                <?php else: ?>
                                                    <span style="color: var(--info); font-weight: 600;">
                                                        <?php echo abs($immunization['days_overdue']); ?> days ahead
                                                    </span>
                                                <?php endif; ?>
                                            </td>
                                            <td>
                                                <?php
                                                $status = strtolower($immunization['status']);
                                                $status_class = $status === 'pending' ? 'pending' : 'scheduled';
                                                ?>
                                                <span class="status-badge <?php echo $status_class; ?>">
                                                    <?php echo ucfirst($immunization['status']); ?>
                                                </span>
                                            </td>
                                            <td>
                                                <div class="action-buttons">
                                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to mark this appointment as overdue?');">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                        <input type="hidden" name="immunization_id" value="<?php echo $immunization['id']; ?>">
                                                        <button type="submit" name="mark_as_overdue" class="action-btn overdue">
                                                            <i class="fas fa-exclamation-triangle"></i>
                                                            Mark Overdue
                                                        </button>
                                                    </form>
                                                    
                                                    <button class="action-btn reschedule" onclick="openScheduleModal(<?php echo $immunization['id']; ?>, '<?php echo htmlspecialchars($immunization['patient_first_name'] . ' ' . $immunization['patient_last_name']); ?>', '<?php echo htmlspecialchars($immunization['vaccine_type']); ?>')">
                                                        <i class="fas fa-calendar-alt"></i>
                                                        Reschedule
                                                    </button>
                                                    
                                                    <form method="POST" style="display: inline;" onsubmit="return confirm('Are you sure you want to mark this appointment as attended?');">
                                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                                        <input type="hidden" name="immunization_id" value="<?php echo $immunization['id']; ?>">
                                                        <button type="submit" name="mark_as_attended" class="action-btn attended">
                                                            <i class="fas fa-check"></i>
                                                            Mark as Attended
                                                        </button>
                                                    </form>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Schedule Appointment Modal - FIXED VERSION -->
    <div id="scheduleModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h2 class="modal-title">
                    <i class="fas fa-calendar-plus"></i>
                    Schedule Appointment
                </h2>
                <button class="close-btn" onclick="closeScheduleModal()">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            
            <form method="POST" id="scheduleForm">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <input type="hidden" name="form_token" value="<?php echo $form_token; ?>">
                <input type="hidden" name="immunization_id" id="modal_immunization_id">
                <input type="hidden" name="schedule_appointment" value="1">
                
                <div class="form-group">
                    <label class="form-label">Patient</label>
                    <input type="text" id="modal_patient_name" class="form-input" readonly>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Vaccine Type</label>
                    <input type="text" id="modal_vaccine_type" class="form-input" readonly>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Schedule Date *</label>
                    <input type="date" name="schedule_date" id="schedule_date" class="form-input" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Appointment Time *</label>
                    <input type="time" name="schedule_time" id="schedule_time" class="form-input" required>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Assign Doctor *</label>
                    <div class="doctor-search-container">
                        <input type="text" id="doctor_search" class="form-input" placeholder="Search for doctor by name or specialization" required>
                        <input type="hidden" name="doctor_id" id="selected_doctor_id" required>
                        <div id="doctor_suggestions" class="doctor-suggestions" style="display: none;"></div>
                    </div>
                </div>
                
                <div class="form-group">
                    <label class="form-label">Comments/Instructions</label>
                    <textarea name="comments" class="form-textarea" placeholder="Any special instructions or comments for the appointment"></textarea>
                </div>
                
                <div class="form-group">
                    <button type="submit" name="schedule_appointment" class="action-btn schedule" style="width: 100%; justify-content: center;">
                        <i class="fas fa-calendar-check"></i>
                        Schedule Appointment
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- JavaScript - FIXED VERSION -->
    <script>
        // CSRF Token for AJAX requests
        const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
        
        // Tab functionality
        function showTab(tabName) {
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(content => {
                content.classList.remove('active');
            });
            
            // Remove active class from all tab buttons
            const tabButtons = document.querySelectorAll('.tab-btn');
            tabButtons.forEach(button => {
                button.classList.remove('active');
            });
            
            // Show selected tab content
            document.getElementById(tabName).classList.add('active');
            
            // Add active class to clicked tab button
            event.target.classList.add('active');
        }

        // Patient search functionality
        document.getElementById('patientSearchForm').addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const email = formData.get('email');
            
            if (!email) {
                alert('Please enter a patient email address.');
                return;
            }
            
            // Show loading state
            const searchBtn = this.querySelector('.search-btn');
            const originalText = searchBtn.innerHTML;
            searchBtn.innerHTML = '<div class="spinner"></div> Searching...';
            searchBtn.disabled = true;
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                const patientInfo = document.getElementById('patientInfo');
                const patientDetails = document.getElementById('patientDetails');
                
                if (data.error) {
                    patientInfo.style.display = 'block';
                    patientDetails.innerHTML = `
                        <div class="alert error">
                            <i class="fas fa-exclamation-circle"></i>
                            ${data.error}
                        </div>
                    `;
                } else {
                    patientInfo.style.display = 'block';
                    patientDetails.innerHTML = `
                        <div class="patient-detail">
                            <div class="detail-label">Name</div>
                            <div class="detail-value">${data.first_name} ${data.last_name}</div>
                        </div>
                        <div class="patient-detail">
                            <div class="detail-label">Email</div>
                            <div class="detail-value">${data.email}</div>
                        </div>
                        <div class="patient-detail">
                            <div class="detail-label">Gender</div>
                            <div class="detail-value">${data.gender}</div>
                        </div>
                        <div class="patient-detail">
                            <div class="detail-label">Age</div>
                            <div class="detail-value">${data.age} years</div>
                        </div>
                        <div class="patient-detail">
                            <div class="detail-label">Status</div>
                            <div class="detail-value">
                                <span class="status-badge" style="background: rgba(16, 185, 129, 0.15); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3);">
                                    ${data.registration_status}
                                </span>
                            </div>
                        </div>
                    `;
                }
            })
            .catch(error => {
                console.error('Error:', error);
                const patientInfo = document.getElementById('patientInfo');
                const patientDetails = document.getElementById('patientDetails');
                patientInfo.style.display = 'block';
                patientDetails.innerHTML = `
                    <div class="alert error">
                        <i class="fas fa-exclamation-circle"></i>
                        An error occurred while searching for the patient.
                    </div>
                `;
            })
            .finally(() => {
                // Restore button state
                searchBtn.innerHTML = originalText;
                searchBtn.disabled = false;
            });
        });

        // Schedule modal functionality - FIXED VERSION
        function openScheduleModal(immunizationId, patientName, vaccineType) {
            document.getElementById('modal_immunization_id').value = immunizationId;
            document.getElementById('modal_patient_name').value = patientName;
            document.getElementById('modal_vaccine_type').value = vaccineType;
            
            // Set minimum date to today
            const today = new Date().toISOString().split('T')[0];
            document.getElementById('schedule_date').min = today;
            
            // Show modal
            document.getElementById('scheduleModal').classList.add('show');
            document.getElementById('scheduleModal').style.display = 'flex';
        }

        function closeScheduleModal() {
            document.getElementById('scheduleModal').classList.remove('show');
            document.getElementById('scheduleModal').style.display = 'none';
            document.getElementById('scheduleForm').reset();
            document.getElementById('doctor_suggestions').style.display = 'none';
            document.getElementById('selected_doctor_id').value = '';
        }

        // Doctor search functionality - FIXED VERSION
        let doctorSearchTimeout;
        document.getElementById('doctor_search').addEventListener('input', function() {
            const query = this.value.trim();
            const suggestionsDiv = document.getElementById('doctor_suggestions');
            
            clearTimeout(doctorSearchTimeout);
            
            if (query.length < 2) {
                suggestionsDiv.style.display = 'none';
                return;
            }
            
            doctorSearchTimeout = setTimeout(() => {
                fetch(`?search_doctor=${encodeURIComponent(query)}&hospital_id=<?php echo $receptionist_hospital_id; ?>`)
                    .then(response => response.json())
                    .then(doctors => {
                        if (doctors.length > 0) {
                            suggestionsDiv.innerHTML = doctors.map(doctor => `
                                <div class="doctor-suggestion" onclick="selectDoctor(${doctor.id}, '${doctor.first_name}', '${doctor.last_name}', '${doctor.specialization}')">
                                    <div class="doctor-name">Dr. ${doctor.first_name} ${doctor.last_name}</div>
                                    <div class="doctor-specialization">${doctor.specialization}</div>
                                </div>
                            `).join('');
                            suggestionsDiv.style.display = 'block';
                        } else {
                            suggestionsDiv.innerHTML = '<div class="doctor-suggestion">No doctors found</div>';
                            suggestionsDiv.style.display = 'block';
                        }
                    })
                    .catch(error => {
                        console.error('Error searching doctors:', error);
                        suggestionsDiv.style.display = 'none';
                    });
            }, 300);
        });

        function selectDoctor(doctorId, firstName, lastName, specialization) {
            document.getElementById('doctor_search').value = `Dr. ${firstName} ${lastName} - ${specialization}`;
            document.getElementById('selected_doctor_id').value = doctorId;
            document.getElementById('doctor_suggestions').style.display = 'none';
        }

        // Close doctor suggestions when clicking outside
        document.addEventListener('click', function(e) {
            if (!e.target.closest('.doctor-search-container')) {
                document.getElementById('doctor_suggestions').style.display = 'none';
            }
        });

        // Close modal when clicking outside
        document.getElementById('scheduleModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeScheduleModal();
            }
        });

        // Logout functionality
        function logout() {
            if (confirm('Are you sure you want to logout?')) {
                // Log security event
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=log_security_event&event_type=LOGOUT&details=User initiated logout&csrf_token=${csrfToken}`
                }).finally(() => {
                    window.location.href = '../logout.php';
                });
            }
        }

        // Session management
        let sessionTimer;
        let warningShown = false;

        function resetSessionTimer() {
            clearTimeout(sessionTimer);
            warningShown = false;
            
            // Send heartbeat to server
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `action=heartbeat&csrf_token=${csrfToken}`
            });
            
            // Set timer for 25 minutes (5 minutes before session expires)
            sessionTimer = setTimeout(() => {
                if (!warningShown) {
                    warningShown = true;
                    if (confirm('Your session will expire in 5 minutes. Do you want to continue working?')) {
                        resetSessionTimer();
                    } else {
                        window.location.href = '../logout.php';
                    }
                }
            }, 25 * 60 * 1000); // 25 minutes
        }

        // Initialize session timer
        resetSessionTimer();

        // Reset timer on user activity
        ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart'].forEach(event => {
            document.addEventListener(event, resetSessionTimer, true);
        });

        // Security monitoring
        let securityChecks = {
            tabFocusCount: 0,
            lastActivity: Date.now()
        };

        // Monitor tab focus changes
        document.addEventListener('visibilitychange', function() {
            if (document.hidden) {
                securityChecks.tabFocusCount++;
                if (securityChecks.tabFocusCount > 10) {
                    fetch('', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `action=log_security_event&event_type=SUSPICIOUS_TAB_SWITCHING&details=Excessive tab switching detected&csrf_token=${csrfToken}`
                    });
                }
            }
        });

        // Monitor for potential security threats
        function checkSecurityThreats() {
            // Check for rapid requests
            const now = Date.now();
            if (now - securityChecks.lastActivity < 100) {
                fetch('', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: `action=log_security_event&event_type=RAPID_REQUESTS&details=Potential automated requests detected&csrf_token=${csrfToken}`
                });
            }
            securityChecks.lastActivity = now;
        }

        // Monitor form submissions
        document.addEventListener('submit', function(e) {
            checkSecurityThreats();
        });

        // Auto-hide alerts after 5 seconds
        document.addEventListener('DOMContentLoaded', function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                setTimeout(() => {
                    alert.style.opacity = '0';
                    alert.style.transform = 'translateY(-20px)';
                    setTimeout(() => {
                        alert.remove();
                    }, 300);
                }, 5000);
            });
        });

        // Form validation - FIXED VERSION
        document.getElementById('scheduleForm').addEventListener('submit', function(e) {
            const doctorId = document.getElementById('selected_doctor_id').value;
            if (!doctorId) {
                e.preventDefault();
                alert('Please select a doctor from the search results.');
                return false;
            }
            
            const scheduleDate = document.getElementById('schedule_date').value;
            const today = new Date().toISOString().split('T')[0];
            if (scheduleDate < today) {
                e.preventDefault();
                alert('Schedule date cannot be in the past.');
                return false;
            }
            
            // Show loading state
            const submitBtn = this.querySelector('button[type="submit"]');
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<div class="spinner"></div> Scheduling...';
            submitBtn.disabled = true;
            
            // Re-enable button after 3 seconds to prevent permanent disable on error
            setTimeout(() => {
                submitBtn.innerHTML = originalText;
                submitBtn.disabled = false;
            }, 3000);
        });

        // Enhanced keyboard navigation
        document.addEventListener('keydown', function(e) {
            // Escape key closes modals
            if (e.key === 'Escape') {
                const modal = document.querySelector('.modal.show');
                if (modal) {
                    closeScheduleModal();
                }
            }
            
            // Ctrl+F opens search
            if (e.ctrlKey && e.key === 'f') {
                e.preventDefault();
                const searchInput = document.querySelector('input[name="name_filter"]');
                if (searchInput) {
                    searchInput.focus();
                }
            }
        });

        // Prevent form resubmission on page refresh
        if (window.history.replaceState) {
            window.history.replaceState(null, null, window.location.href);
        }

        // Initialize date picker with restrictions
        document.addEventListener('DOMContentLoaded', function() {
            const dateInput = document.getElementById('schedule_date');
            if (dateInput) {
                // Set minimum date to today
                const today = new Date().toISOString().split('T')[0];
                dateInput.min = today;
                
                // Set maximum date to 1 year from now
                const maxDate = new Date();
                maxDate.setFullYear(maxDate.getFullYear() + 1);
                dateInput.max = maxDate.toISOString().split('T')[0];
            }
        });

        // Performance optimization - debounce scroll events
        let scrollTimeout;
        window.addEventListener('scroll', function() {
            clearTimeout(scrollTimeout);
            scrollTimeout = setTimeout(() => {
                // Handle scroll events here if needed
            }, 100);
        });

        // Network status monitoring
        window.addEventListener('online', function() {
            console.log('Network connection restored');
        });

        window.addEventListener('offline', function() {
            console.log('Network connection lost');
            alert('Network connection lost. Please check your internet connection.');
        });

        // Accessibility improvements
        document.addEventListener('keydown', function(e) {
            // Tab navigation for modal
            if (e.key === 'Tab') {
                const modal = document.querySelector('.modal.show');
                if (modal) {
                    const focusableElements = modal.querySelectorAll(
                        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
                    );
                    const firstElement = focusableElements[0];
                    const lastElement = focusableElements[focusableElements.length - 1];

                    if (e.shiftKey) {
                        if (document.activeElement === firstElement) {
                            lastElement.focus();
                            e.preventDefault();
                        }
                    } else {
                        if (document.activeElement === lastElement) {
                            firstElement.focus();
                            e.preventDefault();
                        }
                    }
                }
            }
        });

        // Error handling for fetch requests
        function handleFetchError(error) {
            console.error('Fetch error:', error);
            alert('An error occurred while processing your request. Please try again.');
        }

        // Add global error handler
        window.addEventListener('error', function(e) {
            console.error('Global error:', e.error);
        });

        // Add unhandled promise rejection handler
        window.addEventListener('unhandledrejection', function(e) {
            console.error('Unhandled promise rejection:', e.reason);
        });
    </script>
</body>
</html>

<?php
// Close database connection
$conn->close();
?>
