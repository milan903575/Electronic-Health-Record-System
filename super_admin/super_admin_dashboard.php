<?php
session_start();
require_once '../connection.php';

// PHPMailer includes
require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Handle BLOB image display
if (isset($_GET['show_image']) && isset($_GET['hospital_id']) && isset($_GET['type'])) {
    $hospital_id = (int)$_GET['hospital_id'];
    $type = $_GET['type'];
    
    if ($type === 'license' || $type === 'gov_id') {
        $column = ($type === 'license') ? 'license_file' : 'gov_id_proof';
        $query = "SELECT $column FROM hospitals WHERE id = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "i", $hospital_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($row = mysqli_fetch_assoc($result)) {
            if (!empty($row[$column])) {
                header("Content-Type: image/jpeg");
                echo $row[$column];
                exit();
            }
        }
    }
    // If no image found, show placeholder
    header("Content-Type: image/png");
    echo base64_decode('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==');
    exit();
}

// CSRF Token Generation
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// CSRF Token Validation
function validateCSRFToken($token) {
    return hash_equals($_SESSION['csrf_token'], $token);
}

// Generate OTP
function generateOTP() {
    return sprintf("%06d", mt_rand(100000, 999999));
}

// Send OTP Email
function sendOTPEmail($email, $otp) {
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'your@gmail.com'; //replace email
        $mail->Password = ''; //replace password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;
        $mail->setFrom('your@gmail.com', 'Super Admin Security');
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = 'Super Admin Login - OTP Verification';
        $mail->Body = "
            <h2>Super Admin Login Verification</h2>
            <p>Your OTP for Super Admin login is: <strong style='font-size: 24px; color: #e74c3c;'>$otp</strong></p>
            <p>This OTP is valid for 5 minutes only.</p>
            <p>If you didn't request this, please ignore this email.</p>
        ";
        
        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}

// Send response email for contact/report
function sendResponseEmail($email, $subject, $message) {
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = 'milansooraj93@gmail.com';
        $mail->Password = 'ifag urwx cjry fsst';
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;
        $mail->setFrom('milansooraj93@gmail.com', 'Super Admin Support');
        $mail->addAddress($email);
        $mail->isHTML(true);
        $mail->Subject = 'Response to your ' . $subject;
        $mail->Body = "
            <h2>Response from Super Admin</h2>
            <p>Dear User,</p>
            <p>Thank you for contacting us. Here is our response:</p>
            <div style='background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0;'>
                " . nl2br(htmlspecialchars($message)) . "
            </div>
            <p>If you have any further questions, please don't hesitate to contact us.</p>
            <p>Best regards,<br>Super Admin Team</p>
        ";
        
        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}

// Check if user is blocked
function isUserBlocked($conn, $email) {
    $tables = ['patients', 'doctors', 'receptionist'];
    foreach ($tables as $table) {
        $query = "SELECT authorized FROM $table WHERE email = ? LIMIT 1";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        if ($row = mysqli_fetch_assoc($result)) {
            return $row['authorized'] == 0;
        }
    }
    return false;
}

// Update failed attempts
function updateFailedAttempts($conn, $email) {
    // Check if record exists
    $check_query = "SELECT failed_attempts FROM super_admin WHERE email = ?";
    $check_stmt = mysqli_prepare($conn, $check_query);
    mysqli_stmt_bind_param($check_stmt, "s", $email);
    mysqli_stmt_execute($check_stmt);
    $result = mysqli_stmt_get_result($check_stmt);
    
    if ($admin = mysqli_fetch_assoc($result)) {
        $failed_attempts = $admin['failed_attempts'] + 1;
        $blocked = ($failed_attempts >= 5) ? 1 : 0;
        
        $update_query = "UPDATE super_admin SET failed_attempts = ?, blocked = ? WHERE email = ?";
        $update_stmt = mysqli_prepare($conn, $update_query);
        mysqli_stmt_bind_param($update_stmt, "iis", $failed_attempts, $blocked, $email);
        mysqli_stmt_execute($update_stmt);
        
        return $failed_attempts;
    }
    return 0;
}

// Reset failed attempts on successful login
function resetFailedAttempts($conn, $email) {
    $query = "UPDATE super_admin SET failed_attempts = 0, blocked = 0 WHERE email = ?";
    $stmt = mysqli_prepare($conn, $query);
    mysqli_stmt_bind_param($stmt, "s", $email);
    mysqli_stmt_execute($stmt);
}

// Session timeout management
$session_timeout = 1800; // 30 minutes
if (isset($_SESSION['last_activity'])) {
    if (time() - $_SESSION['last_activity'] > $session_timeout) {
        session_destroy();
        header('Location: ../logout.php');
        exit();
    }
}
$_SESSION['last_activity'] = time();

// Handle AJAX requests for session refresh
if (isset($_POST['action']) && $_POST['action'] === 'refresh_session') {
    $_SESSION['last_activity'] = time();
    echo json_encode(['status' => 'success', 'remaining' => $session_timeout]);
    exit();
}

// Initialize login step
if (!isset($_SESSION['login_step'])) {
    $_SESSION['login_step'] = 1;
}

// Step 1: Email and Password Verification
if (isset($_POST['step1_login'])) {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        $login_error = "Invalid CSRF token";
    } else {
        $email = mysqli_real_escape_string($conn, $_POST['email']);
        $password = $_POST['password'];
        
        // Check if admin exists and is not blocked
        $query = "SELECT * FROM super_admin WHERE email = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($admin = mysqli_fetch_assoc($result)) {
            if ($admin['blocked'] == 1) {
                $login_error = "Account is blocked due to multiple failed attempts. Contact administrator.";
            } elseif (password_verify($password, $admin['password'])) {
                // Step 1 successful, generate and send OTP
                $otp = generateOTP();
                $_SESSION['login_otp'] = $otp;
                $_SESSION['login_email'] = $email;
                $_SESSION['otp_time'] = time();
                $_SESSION['login_step'] = 2;
                
                if (sendOTPEmail($email, $otp)) {
                    $success_message = "OTP sent to your email. Please check and enter the code.";
                } else {
                    $login_error = "Failed to send OTP. Please try again.";
                    $_SESSION['login_step'] = 1;
                }
            } else {
                $failed_attempts = updateFailedAttempts($conn, $email);
                if ($failed_attempts >= 5) {
                    $login_error = "Account blocked due to 5 failed attempts.";
                } else {
                    $remaining = 5 - $failed_attempts;
                    $login_error = "Invalid credentials. $remaining attempts remaining.";
                }
            }
        } else {
            $login_error = "Invalid credentials";
        }
    }
}

// Step 2: OTP Verification
if (isset($_POST['step2_otp'])) {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        $login_error = "Invalid CSRF token";
    } else {
        $entered_otp = $_POST['otp'];
        
        // Check OTP expiry (5 minutes)
        if (time() - $_SESSION['otp_time'] > 300) {
            $login_error = "OTP expired. Please start login process again.";
            $_SESSION['login_step'] = 1;
            unset($_SESSION['login_otp'], $_SESSION['login_email'], $_SESSION['otp_time']);
        } elseif ($entered_otp == $_SESSION['login_otp']) {
            $_SESSION['login_step'] = 3;
            $success_message = "OTP verified successfully. Please enter your authentication password.";
        } else {
            $failed_attempts = updateFailedAttempts($conn, $_SESSION['login_email']);
            if ($failed_attempts >= 5) {
                $login_error = "Account blocked due to 5 failed attempts.";
                $_SESSION['login_step'] = 1;
            } else {
                $remaining = 5 - $failed_attempts;
                $login_error = "Invalid OTP. $remaining attempts remaining.";
            }
        }
    }
}

// Step 3: Authentication Password
if (isset($_POST['step3_auth'])) {
    if (!validateCSRFToken($_POST['csrf_token'])) {
        $login_error = "Invalid CSRF token";
    } else {
        $auth_password = $_POST['auth_password'];
        $email = $_SESSION['login_email'];
        
        $query = "SELECT * FROM super_admin WHERE email = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($admin = mysqli_fetch_assoc($result)) {
            if ($auth_password === $admin['ath_password']) {
                // All steps successful - login
                $_SESSION['super_admin_id'] = $admin['id'];
                $_SESSION['super_admin_email'] = $admin['email'];
                $_SESSION['last_activity'] = time();
                
                // Reset failed attempts
                resetFailedAttempts($conn, $email);
                
                // Clear login session data
                unset($_SESSION['login_step'], $_SESSION['login_otp'], $_SESSION['login_email'], $_SESSION['otp_time']);
                
                header('Location: ' . $_SERVER['PHP_SELF']);
                exit();
            } else {
                $failed_attempts = updateFailedAttempts($conn, $email);
                if ($failed_attempts >= 5) {
                    $login_error = "Account blocked due to 5 failed attempts.";
                    $_SESSION['login_step'] = 1;
                } else {
                    $remaining = 5 - $failed_attempts;
                    $login_error = "Invalid authentication password. $remaining attempts remaining.";
                }
            }
        }
    }
}

// Resend OTP
if (isset($_POST['resend_otp'])) {
    if (isset($_SESSION['login_email'])) {
        $otp = generateOTP();
        $_SESSION['login_otp'] = $otp;
        $_SESSION['otp_time'] = time();
        
        if (sendOTPEmail($_SESSION['login_email'], $otp)) {
            $success_message = "New OTP sent to your email.";
        } else {
            $login_error = "Failed to send OTP. Please try again.";
        }
    }
}

// Check if admin is logged in
$is_logged_in = isset($_SESSION['super_admin_id']);

// Handle various actions
if ($is_logged_in && $_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Hospital approval/rejection
    if (isset($_POST['hospital_action'])) {
        $hospital_id = (int)$_POST['hospital_id'];
        $action = $_POST['hospital_action'];
        
        if ($action === 'approve') {
            $query = "UPDATE hospitals SET status = 'approved', verified = 1 WHERE id = ?";
        } elseif ($action === 'reject') {
            $query = "UPDATE hospitals SET status = 'rejected', verified = 1 WHERE id = ?";
        } elseif ($action === 'pending') {
            $query = "UPDATE hospitals SET status = 'pending', verified = 0 WHERE id = ?";
        }
        
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "i", $hospital_id);
        mysqli_stmt_execute($stmt);
        
        // Redirect to maintain current tab and filters
        $redirect_url = $_SERVER['PHP_SELF'] . '?tab=hospitals';
        if (isset($_GET['hospital_filter'])) {
            $redirect_url .= '&hospital_filter=' . urlencode($_GET['hospital_filter']);
        }
        header('Location: ' . $redirect_url);
        exit();
    }
    
    // Block/Unblock user
    if (isset($_POST['block_user'])) {
        $email = mysqli_real_escape_string($conn, $_POST['user_email']);
        $action = $_POST['block_action'];
        $authorized = ($action === 'block') ? 0 : 1;
        
        // Update in all user tables
        $tables = ['patients', 'doctors', 'receptionist'];
        foreach ($tables as $table) {
            $query = "UPDATE $table SET authorized = ? WHERE email = ?";
            $stmt = mysqli_prepare($conn, $query);
            mysqli_stmt_bind_param($stmt, "is", $authorized, $email);
            mysqli_stmt_execute($stmt);
        }
        
        // Redirect to maintain current tab and filters
        $current_tab = isset($_GET['tab']) ? $_GET['tab'] : 'security';
        $redirect_url = $_SERVER['PHP_SELF'] . '?tab=' . $current_tab;
        if ($current_tab === 'security' && isset($_GET['security_filter'])) {
            $redirect_url .= '&security_filter=' . urlencode($_GET['security_filter']);
        } elseif ($current_tab === 'logins' && isset($_GET['login_filter'])) {
            $redirect_url .= '&login_filter=' . urlencode($_GET['login_filter']);
        }
        header('Location: ' . $redirect_url);
        exit();
    }
    
    // Respond to contact/report
    if (isset($_POST['respond_contact'])) {
        $contact_id = (int)$_POST['contact_id'];
        $response_message = mysqli_real_escape_string($conn, $_POST['response_message']);
        
        // Get contact details
        $query = "SELECT email, title, contact_type FROM contacts_reports WHERE id = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "i", $contact_id);
        mysqli_stmt_execute($stmt);
        $result = mysqli_stmt_get_result($stmt);
        
        if ($contact = mysqli_fetch_assoc($result)) {
            // Update as resolved (only set resolved = 1)
            $update_query = "UPDATE contacts_reports SET resolved = 1 WHERE id = ?";
            $update_stmt = mysqli_prepare($conn, $update_query);
            mysqli_stmt_bind_param($update_stmt, "i", $contact_id);
            mysqli_stmt_execute($update_stmt);
            
            // Send email response
            $subject = $contact['contact_type'] . ' - ' . $contact['title'];
            sendResponseEmail($contact['email'], $subject, $response_message);
        }
        
        // Redirect to maintain current tab and filters
        $redirect_url = $_SERVER['PHP_SELF'] . '?tab=contacts';
        if (isset($_GET['contact_filter'])) {
            $redirect_url .= '&contact_filter=' . urlencode($_GET['contact_filter']);
        }
        header('Location: ' . $redirect_url);
        exit();
    }
    
    // Delete event/news
    if (isset($_POST['delete_event'])) {
        $event_id = (int)$_POST['event_id'];
        $query = "DELETE FROM events_news WHERE id = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "i", $event_id);
        mysqli_stmt_execute($stmt);
    }
    
    // Upload post - MODIFIED SECTION
    if (isset($_POST['upload_post'])) {
        $title = mysqli_real_escape_string($conn, $_POST['title']);
        $description = mysqli_real_escape_string($conn, $_POST['description']);
        $image_path = '';
        $video_path = '';
        
        // Create uploads/events directory if it doesn't exist
        $upload_dir = '../uploads/events/';
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
        }
        
        // Handle image upload
        if (!empty($_FILES['image']['name'])) {
            $allowed_img = ['jpg', 'jpeg', 'png', 'gif'];
            $img_ext = strtolower(pathinfo($_FILES['image']['name'], PATHINFO_EXTENSION));
            if (in_array($img_ext, $allowed_img)) {
                // Generate unique filename with timestamp and random number
                $timestamp = time();
                $random_num = rand(1000, 9999);
                $filename = "event_{$timestamp}_{$random_num}.{$img_ext}";
                $image_path = "../uploads/events/{$filename}";
                
                if (move_uploaded_file($_FILES['image']['tmp_name'], $image_path)) {
                    // File uploaded successfully
                } else {
                    $image_path = ''; // Reset if upload failed
                }
            }
        }
        
        // Handle video upload
        if (!empty($_FILES['video']['name'])) {
            $allowed_vid = ['mp4', 'avi', 'mov', 'wmv', 'flv'];
            $vid_ext = strtolower(pathinfo($_FILES['video']['name'], PATHINFO_EXTENSION));
            if (in_array($vid_ext, $allowed_vid)) {
                // Generate unique filename with timestamp and random number
                $timestamp = time();
                $random_num = rand(1000, 9999);
                $filename = "event_video_{$timestamp}_{$random_num}.{$vid_ext}";
                $video_path = "../uploads/events/{$filename}";
                
                if (move_uploaded_file($_FILES['video']['tmp_name'], $video_path)) {
                    // File uploaded successfully
                } else {
                    $video_path = ''; // Reset if upload failed
                }
            }
        }
        
        $query = "INSERT INTO events_news (title, description, image_path, video_path, posted_by, created_at) VALUES (?, ?, ?, ?, 'admin', NOW())";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "ssss", $title, $description, $image_path, $video_path);
        mysqli_stmt_execute($stmt);
    }
    
    // Delete FAQ
    if (isset($_POST['delete_faq'])) {
        $faq_id = (int)$_POST['faq_id'];
        
        mysqli_begin_transaction($conn);
        try {
            // Delete related records first
            $query1 = "DELETE FROM faq_conversion WHERE faq_id = ?";
            $stmt1 = mysqli_prepare($conn, $query1);
            mysqli_stmt_bind_param($stmt1, "i", $faq_id);
            mysqli_stmt_execute($stmt1);
            
            $query2 = "DELETE FROM faq_rating WHERE faq_id = ?";
            $stmt2 = mysqli_prepare($conn, $query2);
            mysqli_stmt_bind_param($stmt2, "i", $faq_id);
            mysqli_stmt_execute($stmt2);
            
            // Delete FAQ
            $query3 = "DELETE FROM faq WHERE id = ? OR parent_id = ?";
            $stmt3 = mysqli_prepare($conn, $query3);
            mysqli_stmt_bind_param($stmt3, "ii", $faq_id, $faq_id);
            mysqli_stmt_execute($stmt3);
            
            mysqli_commit($conn);
        } catch (Exception $e) {
            mysqli_rollback($conn);
        }
    }
    
    // Delete contact/report
    if (isset($_POST['delete_contact'])) {
        $contact_id = (int)$_POST['contact_id'];
        $query = "DELETE FROM contacts_reports WHERE id = ?";
        $stmt = mysqli_prepare($conn, $query);
        mysqli_stmt_bind_param($stmt, "i", $contact_id);
        mysqli_stmt_execute($stmt);
    }
}

// Fetch data functions with filters
function getHospitals($conn, $filter = '') {
    $query = "SELECT id, hospital_name, state, city, zipcode, email, status, license_file, gov_id_proof, director_approve FROM hospitals";
    
    if ($filter) {
        switch ($filter) {
            case 'pending':
                $query .= " WHERE status = 'pending'";
                break;
            case 'approved':
                $query .= " WHERE status = 'approved'";
                break;
            case 'rejected':
                $query .= " WHERE status = 'rejected'";
                break;
            case 'verified':
                $query .= " WHERE verified = 1";
                break;
            case 'unverified':
                $query .= " WHERE verified = 0";
                break;
        }
    }
    
    $query .= " ORDER BY id DESC";
    return mysqli_query($conn, $query);
}

function getSecurityLogs($conn, $filter = '') {
    $query = "SELECT email, event_type, ip_address, user_agent, additional_info, timestamp FROM security_logs";
    
    if ($filter) {
        switch ($filter) {
            case 'login':
                $query .= " WHERE event_type LIKE '%login%'";
                break;
            case 'dashboard':
                $query .= " WHERE event_type LIKE '%dashboard%'";
                break;
            case 'failed':
                $query .= " WHERE event_type LIKE '%failed%'";
                break;
            case 'suspicious':
                $query .= " WHERE event_type LIKE '%suspicious%' OR event_type LIKE '%block%'";
                break;
            case 'blocked':
                // Get emails that are blocked in any user table
                $query .= " WHERE email IN (
                    SELECT email FROM patients WHERE authorized = 0
                    UNION
                    SELECT email FROM doctors WHERE authorized = 0
                    UNION
                    SELECT email FROM receptionist WHERE authorized = 0
                )";
                break;
            case 'unblocked':
                // Get emails that are not blocked in any user table
                $query .= " WHERE email IN (
                    SELECT email FROM patients WHERE authorized = 1
                    UNION
                    SELECT email FROM doctors WHERE authorized = 1
                    UNION
                    SELECT email FROM receptionist WHERE authorized = 1
                )";
                break;
        }
    }
    
    $query .= " ORDER BY timestamp DESC LIMIT 100";
    return mysqli_query($conn, $query);
}

function getLoginAttempts($conn, $filter = '') {
    $query = "SELECT email, ip_address, success, timestamp FROM login_attempts";
    
    if ($filter) {
        switch ($filter) {
            case 'success_today':
                $query .= " WHERE success = 1 AND DATE(timestamp) = CURDATE()";
                break;
            case 'failed_all':
                $query .= " WHERE success = 0";
                break;
            case 'success_all':
                $query .= " WHERE success = 1";
                break;
            case 'failed_today':
                $query .= " WHERE success = 0 AND DATE(timestamp) = CURDATE()";
                break;
            case 'blocked':
                // Get emails that are blocked in any user table
                $query .= " WHERE email IN (
                    SELECT email FROM patients WHERE authorized = 0
                    UNION
                    SELECT email FROM doctors WHERE authorized = 0
                    UNION
                    SELECT email FROM receptionist WHERE authorized = 0
                )";
                break;
            case 'unblocked':
                // Get emails that are not blocked in any user table
                $query .= " WHERE email IN (
                    SELECT email FROM patients WHERE authorized = 1
                    UNION
                    SELECT email FROM doctors WHERE authorized = 1
                    UNION
                    SELECT email FROM receptionist WHERE authorized = 1
                )";
                break;
        }
    }
    
    $query .= " ORDER BY timestamp DESC LIMIT 100";
    return mysqli_query($conn, $query);
}

function getEventsNews($conn, $filter = '') {
    $query = "SELECT id, title, description, image_path, video_path, posted_by, hospital_name, created_at, state, city, hospital_id FROM events_news";
    
    if ($filter) {
        switch ($filter) {
            case 'admin':
                $query .= " WHERE posted_by = 'admin'";
                break;
            case 'hospital':
                $query .= " WHERE posted_by != 'admin'";
                break;
            case 'today':
                $query .= " WHERE DATE(created_at) = CURDATE()";
                break;
            case 'this_week':
                $query .= " WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
        }
    }
    
    $query .= " ORDER BY created_at DESC";
    return mysqli_query($conn, $query);
}

function getFAQs($conn, $filter = '') {
    $query = "SELECT id, user_id, parent_id, question, answer, attachment, attachment_type, created_at, updated_at, category FROM faq";
    
    if ($filter) {
        switch ($filter) {
            case 'answered':
                $query .= " WHERE answer IS NOT NULL AND answer != ''";
                break;
            case 'unanswered':
                $query .= " WHERE answer IS NULL OR answer = ''";
                break;
            case 'with_attachment':
                $query .= " WHERE attachment IS NOT NULL AND attachment != ''";
                break;
            default:
                $query .= " WHERE category LIKE '%" . mysqli_real_escape_string($GLOBALS['conn'], $filter) . "%'";
                break;
        }
    }
    
    $query .= " ORDER BY created_at DESC";
    return mysqli_query($conn, $query);
}

function getContactsReports($conn, $filter = '') {
    $query = "SELECT id, email, title, message, attachment, contact_type, created_at, resolved FROM contacts_reports";
    
    if ($filter) {
        switch ($filter) {
            case 'contact':
                $query .= " WHERE contact_type = 'contact'";
                break;
            case 'report':
                $query .= " WHERE contact_type = 'report'";
                break;
            case 'today':
                $query .= " WHERE DATE(created_at) = CURDATE()";
                break;
            case 'this_week':
                $query .= " WHERE created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)";
                break;
            case 'resolved':
                $query .= " WHERE resolved = 1";
                break;
            case 'unresolved':
                $query .= " WHERE resolved = 0 OR resolved IS NULL";
                break;
        }
    }
    
    $query .= " ORDER BY created_at DESC";
    return mysqli_query($conn, $query);
}

// Get current active tab and filters from URL parameters
$active_tab = isset($_GET['tab']) ? $_GET['tab'] : 'hospitals';
$hospital_filter = isset($_GET['hospital_filter']) ? $_GET['hospital_filter'] : '';
$security_filter = isset($_GET['security_filter']) ? $_GET['security_filter'] : '';
$login_filter = isset($_GET['login_filter']) ? $_GET['login_filter'] : '';
$event_filter = isset($_GET['event_filter']) ? $_GET['event_filter'] : '';
$faq_filter = isset($_GET['faq_filter']) ? $_GET['faq_filter'] : '';
$contact_filter = isset($_GET['contact_filter']) ? $_GET['contact_filter'] : '';
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Super Admin Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        
        .login-container {
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        
        .login-form {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 450px;
        }
        
        .login-form h2 {
            text-align: center;
            margin-bottom: 30px;
            color: #333;
        }
        
        .step-indicator {
            display: flex;
            justify-content: center;
            margin-bottom: 30px;
        }
        
        .step {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #ddd;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0 10px;
            font-weight: bold;
            color: white;
        }
        
        .step.active {
            background: #667eea;
        }
        
        .step.completed {
            background: #27ae60;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 5px;
            color: #555;
            font-weight: 500;
        }
        
        .form-group input, .form-group textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }
        
        .form-group input:focus, .form-group textarea:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .btn {
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
            transition: transform 0.2s;
            margin-bottom: 10px;
        }
        
        .btn:hover {
            transform: translateY(-2px);
        }
        
        .btn-secondary {
            background: #6c757d;
        }
        
        .error {
            color: #e74c3c;
            text-align: center;
            margin-bottom: 20px;
            padding: 10px;
            background: #fdf2f2;
            border-radius: 5px;
            border: 1px solid #fecaca;
        }
        
        .success {
            color: #27ae60;
            text-align: center;
            margin-bottom: 20px;
            padding: 10px;
            background: #f0f9f0;
            border-radius: 5px;
            border: 1px solid #a7f3d0;
        }
        
        .otp-timer {
            text-align: center;
            color: #e74c3c;
            font-weight: bold;
            margin-bottom: 15px;
        }
        
        .step-description {
            text-align: center;
            color: #666;
            margin-bottom: 20px;
            font-size: 14px;
        }
        
        .dashboard {
            background: white;
            min-height: 100vh;
        }
        
        .header {
            background: #2c3e50;
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .session-timer {
            background: #e74c3c;
            padding: 8px 15px;
            border-radius: 20px;
            font-weight: bold;
        }
        
        .nav-tabs {
            background: #34495e;
            padding: 0;
            display: flex;
            overflow-x: auto;
        }
        
        .nav-tab {
            padding: 15px 20px;
            color: white;
            cursor: pointer;
            border: none;
            background: none;
            white-space: nowrap;
            transition: background-color 0.3s;
        }
        
        .nav-tab:hover,
        .nav-tab.active {
            background: #667eea;
        }
        
        .tab-content {
            padding: 30px;
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .table th,
        .table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        .table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #333;
        }
        
        .table tr:hover {
            background: #f8f9fa;
        }
        
        .btn-sm {
            padding: 6px 12px;
            font-size: 14px;
            border-radius: 4px;
            border: none;
            cursor: pointer;
            margin: 2px;
            transition: all 0.2s;
        }
        
        .btn-success {
            background: #27ae60;
            color: white;
        }
        
        .btn-danger {
            background: #e74c3c;
            color: white;
        }
        
        .btn-warning {
            background: #f39c12;
            color: white;
        }
        
        .btn-info {
            background: #3498db;
            color: white;
        }
        
        .btn-sm:hover {
            transform: translateY(-1px);
            box-shadow: 0 2px 5px rgba(0,0,0,0.2);
        }
        
        .upload-form {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }
        
        .form-row {
            display: flex;
            gap: 20px;
            margin-bottom: 15px;
        }
        
        .form-col {
            flex: 1;
        }
        
        .filters {
            background: #e9ecef;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
            align-items: center;
        }
        
        .filter-group {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        
        .filter-group select,
        .filter-group button {
            padding: 8px 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background: white;
            cursor: pointer;
        }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
        }
        
        .status-approved {
            background: #d4edda;
            color: #155724;
        }
        
        .status-pending {
            background: #fff3cd;
            color: #856404;
        }
        
        .status-rejected {
            background: #f8d7da;
            color: #721c24;
        }
        
        .status-resolved {
            background: #d4edda;
            color: #155724;
        }
        
        .status-unresolved {
            background: #f8d7da;
            color: #721c24;
        }
        
        .blob-image {
            max-width: 100px;
            max-height: 100px;
            border-radius: 5px;
            border: 1px solid #ddd;
            cursor: pointer;
        }
        
        .image-modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.9);
        }
        
        .modal-content {
            margin: auto;
            display: block;
            width: 80%;
            max-width: 700px;
            max-height: 80%;
            margin-top: 5%;
        }
        
        .close {
            position: absolute;
            top: 15px;
            right: 35px;
            color: #f1f1f1;
            font-size: 40px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #bbb;
        }
        
        /* Confirmation Modal */
        .confirmation-modal {
            display: none;
            position: fixed;
            z-index: 1001;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .confirmation-content {
            background-color: white;
            margin: 15% auto;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 400px;
            text-align: center;
        }
        
        .confirmation-content h3 {
            margin-bottom: 20px;
            color: #333;
        }
        
        .confirmation-content p {
            margin-bottom: 25px;
            color: #666;
        }
        
        .confirmation-buttons {
            display: flex;
            gap: 15px;
            justify-content: center;
        }
        
        .confirmation-buttons button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
        }
        
        .confirm-yes {
            background: #e74c3c;
            color: white;
        }
        
        .confirm-no {
            background: #95a5a6;
            color: white;
        }
        
        /* Response Modal */
        .response-modal {
            display: none;
            position: fixed;
            z-index: 1002;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .response-content {
            background-color: white;
            margin: 10% auto;
            padding: 30px;
            border-radius: 10px;
            width: 90%;
            max-width: 600px;
        }
        
        .response-content h3 {
            margin-bottom: 20px;
            color: #333;
        }
        
        .response-buttons {
            display: flex;
            gap: 15px;
            justify-content: flex-end;
            margin-top: 20px;
        }
        
        .blocked-indicator {
            color: #e74c3c;
            font-weight: bold;
        }
        
        .unblocked-indicator {
            color: #27ae60;
            font-weight: bold;
        }
        
        @media (max-width: 768px) {
            .form-row {
                flex-direction: column;
            }
            
            .filters {
                flex-direction: column;
            }
            
            .table {
                font-size: 14px;
            }
            
            .nav-tabs {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>

<?php if (!$is_logged_in): ?>
    <!-- Login Form with 3-Step Verification -->
    <div class="login-container">
        <div class="login-form">
            <h2>🔐 Super Admin Login</h2>
            
            <!-- Step Indicator -->
            <div class="step-indicator">
                <div class="step <?php echo ($_SESSION['login_step'] >= 1) ? 'active' : ''; ?> <?php echo ($_SESSION['login_step'] > 1) ? 'completed' : ''; ?>">1</div>
                <div class="step <?php echo ($_SESSION['login_step'] >= 2) ? 'active' : ''; ?> <?php echo ($_SESSION['login_step'] > 2) ? 'completed' : ''; ?>">2</div>
                <div class="step <?php echo ($_SESSION['login_step'] >= 3) ? 'active' : ''; ?>">3</div>
            </div>
            
            <?php if (isset($login_error)): ?>
                <div class="error"><?php echo htmlspecialchars($login_error); ?></div>
            <?php endif; ?>
            
            <?php if (isset($success_message)): ?>
                <div class="success"><?php echo htmlspecialchars($success_message); ?></div>
            <?php endif; ?>
            
            <?php if ($_SESSION['login_step'] == 1): ?>
                <!-- Step 1: Email and Password -->
                <div class="step-description">Step 1: Enter your email and password</div>
                <form method="POST">
                    <div class="form-group">
                        <label for="email">Email:</label>
                        <input type="email" id="email" name="email" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="password">Password:</label>
                        <input type="password" id="password" name="password" required>
                    </div>
                    
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <button type="submit" name="step1_login" class="btn">Continue to OTP Verification</button>
                </form>
                
            <?php elseif ($_SESSION['login_step'] == 2): ?>
                <!-- Step 2: OTP Verification -->
                <div class="step-description">Step 2: Enter the OTP sent to your email</div>
                <div class="otp-timer" id="otpTimer">OTP expires in: <span id="countdown">5:00</span></div>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="otp">Enter OTP:</label>
                        <input type="text" id="otp" name="otp" maxlength="6" pattern="[0-9]{6}" required>
                    </div>
                    
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <button type="submit" name="step2_otp" class="btn">Verify OTP</button>
                </form>
                
                <form method="POST">
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <button type="submit" name="resend_otp" class="btn btn-secondary">Resend OTP</button>
                </form>
                
            <?php elseif ($_SESSION['login_step'] == 3): ?>
                <!-- Step 3: Authentication Password -->
                <div class="step-description">Step 3: Enter your authentication password</div>
                
                <form method="POST">
                    <div class="form-group">
                        <label for="auth_password">Authentication Password:</label>
                        <input type="password" id="auth_password" name="auth_password" required>
                    </div>
                    
                    <input type="hidden" name="csrf_token" value="<?php echo generateCSRFToken(); ?>">
                    <button type="submit" name="step3_auth" class="btn">Complete Login</button>
                </form>
            <?php endif; ?>
        </div>
    </div>

<?php else: ?>
    <!-- Dashboard -->
    <div class="dashboard">
        <div class="header">
            <h1>🏥 Super Admin Dashboard</h1>
            <div>
                <span class="session-timer" id="sessionTimer">Session: 30:00</span>
                <a href="../logout.php" class="btn btn-sm" style="margin-left: 15px;">Logout</a>
            </div>
        </div>
        
        <div class="nav-tabs">
            <button class="nav-tab <?php echo ($active_tab === 'hospitals') ? 'active' : ''; ?>" onclick="showTab('hospitals')">🏥 Hospitals</button>
            <button class="nav-tab <?php echo ($active_tab === 'security') ? 'active' : ''; ?>" onclick="showTab('security')">🔒 Security Logs</button>
            <button class="nav-tab <?php echo ($active_tab === 'logins') ? 'active' : ''; ?>" onclick="showTab('logins')">📊 Login Attempts</button>
            <button class="nav-tab <?php echo ($active_tab === 'events') ? 'active' : ''; ?>" onclick="showTab('events')">📰 Events/News</button>
            <button class="nav-tab <?php echo ($active_tab === 'upload') ? 'active' : ''; ?>" onclick="showTab('upload')">📤 Upload Post</button>
            <button class="nav-tab <?php echo ($active_tab === 'faq') ? 'active' : ''; ?>" onclick="showTab('faq')">❓ FAQ Management</button>
            <button class="nav-tab <?php echo ($active_tab === 'contacts') ? 'active' : ''; ?>" onclick="showTab('contacts')">📞 Contacts/Reports</button>
        </div>
        
        <!-- Hospitals Tab -->
        <div id="hospitals" class="tab-content <?php echo ($active_tab === 'hospitals') ? 'active' : ''; ?>">
            <h2>🏥 Hospital Registration Management</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by Status:</label>
                    <select onchange="filterHospitals(this.value)" id="hospitalFilter">
                        <option value="">All Hospitals</option>
                        <option value="pending" <?php echo ($hospital_filter === 'pending') ? 'selected' : ''; ?>>Pending</option>
                        <option value="approved" <?php echo ($hospital_filter === 'approved') ? 'selected' : ''; ?>>Approved</option>
                        <option value="rejected" <?php echo ($hospital_filter === 'rejected') ? 'selected' : ''; ?>>Rejected</option>
                        <option value="verified" <?php echo ($hospital_filter === 'verified') ? 'selected' : ''; ?>>Verified</option>
                        <option value="unverified" <?php echo ($hospital_filter === 'unverified') ? 'selected' : ''; ?>>Unverified</option>
                    </select>
                </div>
                <button onclick="clearHospitalFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Hospital Name</th>
                        <th>Location</th>
                        <th>Email</th>
                        <th>Status</th>
                        <th>License File</th>
                        <th>Gov ID Proof</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $hospitals = getHospitals($conn, $hospital_filter);
                    while ($hospital = mysqli_fetch_assoc($hospitals)):
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($hospital['hospital_name']); ?></td>
                        <td><?php echo htmlspecialchars($hospital['city'] . ', ' . $hospital['state'] . ' - ' . $hospital['zipcode']); ?></td>
                        <td><?php echo htmlspecialchars($hospital['email']); ?></td>
                        <td>
                            <span class="status-badge status-<?php echo $hospital['status']; ?>">
                                <?php echo ucfirst($hospital['status']); ?>
                            </span>
                        </td>
                        <td>
                            <?php if (!empty($hospital['license_file'])): ?>
                                <img src="?show_image=1&hospital_id=<?php echo $hospital['id']; ?>&type=license" 
                                     class="blob-image" 
                                     onclick="openModal(this.src)" 
                                     alt="License File">
                            <?php else: ?>
                                <span style="color: #999;">No file</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if (!empty($hospital['gov_id_proof'])): ?>
                                <img src="?show_image=1&hospital_id=<?php echo $hospital['id']; ?>&type=gov_id" 
                                     class="blob-image" 
                                     onclick="openModal(this.src)" 
                                     alt="Gov ID Proof">
                            <?php else: ?>
                                <span style="color: #999;">No file</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($hospital['status'] === 'pending'): ?>
                                <button onclick="confirmHospitalAction(<?php echo $hospital['id']; ?>, 'approve')" class="btn-sm btn-success">✅ Approve</button>
                                <button onclick="confirmHospitalAction(<?php echo $hospital['id']; ?>, 'reject')" class="btn-sm btn-danger">❌ Reject</button>
                            <?php else: ?>
                                <button onclick="confirmHospitalAction(<?php echo $hospital['id']; ?>, 'pending')" class="btn-sm btn-warning">🔄 Set Pending</button>
                                <?php if ($hospital['status'] === 'approved'): ?>
                                    <button onclick="confirmHospitalAction(<?php echo $hospital['id']; ?>, 'reject')" class="btn-sm btn-danger">❌ Reject</button>
                                <?php else: ?>
                                    <button onclick="confirmHospitalAction(<?php echo $hospital['id']; ?>, 'approve')" class="btn-sm btn-success">✅ Approve</button>
                                <?php endif; ?>
                            <?php endif; ?>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Security Logs Tab -->
        <div id="security" class="tab-content <?php echo ($active_tab === 'security') ? 'active' : ''; ?>">
            <h2>🔒 Security Logs Management</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by Event:</label>
                    <select onchange="filterSecurityLogs(this.value)" id="securityFilter">
                        <option value="">All Events</option>
                        <option value="login" <?php echo ($security_filter === 'login') ? 'selected' : ''; ?>>Login Events</option>
                        <option value="dashboard" <?php echo ($security_filter === 'dashboard') ? 'selected' : ''; ?>>Dashboard Access</option>
                        <option value="failed" <?php echo ($security_filter === 'failed') ? 'selected' : ''; ?>>Failed Attempts</option>
                        <option value="suspicious" <?php echo ($security_filter === 'suspicious') ? 'selected' : ''; ?>>Suspicious Activity</option>
                        <option value="blocked" <?php echo ($security_filter === 'blocked') ? 'selected' : ''; ?>>🚫 Blocked Users</option>
                        <option value="unblocked" <?php echo ($security_filter === 'unblocked') ? 'selected' : ''; ?>>✅ Unblocked Users</option>
                    </select>
                </div>
                <button onclick="clearSecurityFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Event Type</th>
                        <th>IP Address</th>
                        <th>User Agent</th>
                        <th>Timestamp</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $security_logs = getSecurityLogs($conn, $security_filter);
                    while ($log = mysqli_fetch_assoc($security_logs)):
                        $isBlocked = isUserBlocked($conn, $log['email']);
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($log['email']); ?></td>
                        <td><?php echo htmlspecialchars($log['event_type']); ?></td>
                        <td><?php echo htmlspecialchars($log['ip_address']); ?></td>
                        <td><?php echo htmlspecialchars(substr($log['user_agent'], 0, 50)) . '...'; ?></td>
                        <td><?php echo $log['timestamp']; ?></td>
                        <td>
                            <?php if ($isBlocked): ?>
                                <span class="blocked-indicator">🚫 Blocked</span>
                            <?php else: ?>
                                <span class="unblocked-indicator">✅ Active</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="user_email" value="<?php echo $log['email']; ?>">
                                <?php if ($isBlocked): ?>
                                    <button type="submit" name="block_user" value="1" class="btn-sm btn-success">✅ Unblock</button>
                                    <input type="hidden" name="block_action" value="unblock">
                                <?php else: ?>
                                    <button type="submit" name="block_user" value="1" class="btn-sm btn-danger">🚫 Block</button>
                                    <input type="hidden" name="block_action" value="block">
                                <?php endif; ?>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Login Attempts Tab -->
        <div id="logins" class="tab-content <?php echo ($active_tab === 'logins') ? 'active' : ''; ?>">
            <h2>📊 Login Attempts Monitoring</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by:</label>
                    <select onchange="filterLoginAttempts(this.value)" id="loginFilter">
                        <option value="">All Attempts</option>
                        <option value="success_today" <?php echo ($login_filter === 'success_today') ? 'selected' : ''; ?>>✅ Successful Today</option>
                        <option value="success_all" <?php echo ($login_filter === 'success_all') ? 'selected' : ''; ?>>✅ All Successful</option>
                        <option value="failed_today" <?php echo ($login_filter === 'failed_today') ? 'selected' : ''; ?>>❌ Failed Today</option>
                        <option value="failed_all" <?php echo ($login_filter === 'failed_all') ? 'selected' : ''; ?>>❌ All Failed</option>
                        <option value="blocked" <?php echo ($login_filter === 'blocked') ? 'selected' : ''; ?>>🚫 Blocked Users</option>
                        <option value="unblocked" <?php echo ($login_filter === 'unblocked') ? 'selected' : ''; ?>>✅ Unblocked Users</option>
                    </select>
                </div>
                <button onclick="clearLoginFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>IP Address</th>
                        <th>Success</th>
                        <th>Timestamp</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $login_attempts = getLoginAttempts($conn, $login_filter);
                    while ($attempt = mysqli_fetch_assoc($login_attempts)):
                        $isBlocked = isUserBlocked($conn, $attempt['email']);
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($attempt['email']); ?></td>
                        <td><?php echo htmlspecialchars($attempt['ip_address']); ?></td>
                        <td>
                            <span class="status-badge <?php echo $attempt['success'] ? 'status-approved' : 'status-rejected'; ?>">
                                <?php echo $attempt['success'] ? 'Success' : 'Failed'; ?>
                            </span>
                        </td>
                        <td><?php echo $attempt['timestamp']; ?></td>
                        <td>
                            <?php if ($isBlocked): ?>
                                <span class="blocked-indicator">🚫 Blocked</span>
                            <?php else: ?>
                                <span class="unblocked-indicator">✅ Active</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="user_email" value="<?php echo $attempt['email']; ?>">
                                <?php if ($isBlocked): ?>
                                    <button type="submit" name="block_user" value="1" class="btn-sm btn-success">✅ Unblock</button>
                                    <input type="hidden" name="block_action" value="unblock">
                                <?php else: ?>
                                    <button type="submit" name="block_user" value="1" class="btn-sm btn-danger">🚫 Block</button>
                                    <input type="hidden" name="block_action" value="block">
                                <?php endif; ?>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Events/News Tab -->
        <div id="events" class="tab-content <?php echo ($active_tab === 'events') ? 'active' : ''; ?>">
            <h2>📰 Event/News Management</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by:</label>
                    <select onchange="filterEvents(this.value)" id="eventFilter">
                        <option value="">All Posts</option>
                        <option value="admin" <?php echo ($event_filter === 'admin') ? 'selected' : ''; ?>>Admin Posts</option>
                        <option value="hospital" <?php echo ($event_filter === 'hospital') ? 'selected' : ''; ?>>Hospital Posts</option>
                        <option value="today" <?php echo ($event_filter === 'today') ? 'selected' : ''; ?>>Today's Posts</option>
                        <option value="this_week" <?php echo ($event_filter === 'this_week') ? 'selected' : ''; ?>>This Week</option>
                    </select>
                </div>
                <button onclick="clearEventFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Title</th>
                        <th>Posted By</th>
                        <th>Hospital</th>
                        <th>Location</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $events = getEventsNews($conn, $event_filter);
                    while ($event = mysqli_fetch_assoc($events)):
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($event['title']); ?></td>
                        <td><?php echo htmlspecialchars($event['posted_by']); ?></td>
                        <td><?php echo htmlspecialchars($event['hospital_name'] ?? 'N/A'); ?></td>
                        <td><?php echo htmlspecialchars(($event['city'] ?? '') . ', ' . ($event['state'] ?? '')); ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($event['created_at'])); ?></td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="event_id" value="<?php echo $event['id']; ?>">
                                <button type="submit" name="delete_event" value="1" class="btn-sm btn-danger" onclick="return confirm('Delete this post?')">🗑️ Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Upload Post Tab -->
        <div id="upload" class="tab-content <?php echo ($active_tab === 'upload') ? 'active' : ''; ?>">
            <h2>📤 Post Upload</h2>
            <form method="POST" enctype="multipart/form-data" class="upload-form">
                <div class="form-row">
                    <div class="form-col">
                        <label>Title:</label>
                        <input type="text" name="title" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-col">
                        <label>Description:</label>
                        <textarea name="description" rows="4" style="width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 8px;" required></textarea>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-col">
                        <label>Image:</label>
                        <input type="file" name="image" accept="image/*">
                    </div>
                    <div class="form-col">
                        <label>Video:</label>
                        <input type="file" name="video" accept="video/*">
                    </div>
                </div>
                <button type="submit" name="upload_post" class="btn">📤 Upload Post</button>
            </form>
        </div>
        
        <!-- FAQ Management Tab -->
        <div id="faq" class="tab-content <?php echo ($active_tab === 'faq') ? 'active' : ''; ?>">
            <h2>❓ FAQ Management</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by:</label>
                    <select onchange="filterFAQs(this.value)" id="faqFilter">
                        <option value="">All FAQs</option>
                        <option value="answered" <?php echo ($faq_filter === 'answered') ? 'selected' : ''; ?>>Answered</option>
                        <option value="unanswered" <?php echo ($faq_filter === 'unanswered') ? 'selected' : ''; ?>>Unanswered</option>
                        <option value="with_attachment" <?php echo ($faq_filter === 'with_attachment') ? 'selected' : ''; ?>>With Attachments</option>
                    </select>
                </div>
                <button onclick="clearFAQFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Question</th>
                        <th>Answer</th>
                        <th>Category</th>
                        <th>Created</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $faqs = getFAQs($conn, $faq_filter);
                    while ($faq = mysqli_fetch_assoc($faqs)):
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars(substr($faq['question'], 0, 100)) . '...'; ?></td>
                        <td><?php echo htmlspecialchars(substr($faq['answer'] ?? '', 0, 100)) . '...'; ?></td>
                        <td><?php echo htmlspecialchars($faq['category'] ?? 'General'); ?></td>
                        <td><?php echo date('Y-m-d', strtotime($faq['created_at'])); ?></td>
                        <td>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="faq_id" value="<?php echo $faq['id']; ?>">
                                <button type="submit" name="delete_faq" value="1" class="btn-sm btn-danger" onclick="return confirm('Delete this FAQ and all related data?')">🗑️ Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
        
        <!-- Contacts/Reports Tab -->
        <div id="contacts" class="tab-content <?php echo ($active_tab === 'contacts') ? 'active' : ''; ?>">
            <h2>📞 Contacts/Reports Management</h2>
            <div class="filters">
                <div class="filter-group">
                    <label>Filter by:</label>
                    <select onchange="filterContacts(this.value)" id="contactFilter">
                        <option value="">All Contacts/Reports</option>
                        <option value="contact" <?php echo ($contact_filter === 'contact') ? 'selected' : ''; ?>>Contacts Only</option>
                        <option value="report" <?php echo ($contact_filter === 'report') ? 'selected' : ''; ?>>Reports Only</option>
                        <option value="today" <?php echo ($contact_filter === 'today') ? 'selected' : ''; ?>>Today's Submissions</option>
                        <option value="this_week" <?php echo ($contact_filter === 'this_week') ? 'selected' : ''; ?>>This Week</option>
                        <option value="resolved" <?php echo ($contact_filter === 'resolved') ? 'selected' : ''; ?>>✅ Resolved</option>
                        <option value="unresolved" <?php echo ($contact_filter === 'unresolved') ? 'selected' : ''; ?>>⏳ Unresolved</option>
                    </select>
                </div>
                <button onclick="clearContactFilter()" class="btn-sm btn-info">🔄 Clear Filter</button>
            </div>
            <table class="table">
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Title</th>
                        <th>Type</th>
                        <th>Message</th>
                        <th>Created</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php
                    $contacts = getContactsReports($conn, $contact_filter);
                    while ($contact = mysqli_fetch_assoc($contacts)):
                    ?>
                    <tr>
                        <td><?php echo htmlspecialchars($contact['email']); ?></td>
                        <td><?php echo htmlspecialchars($contact['title']); ?></td>
                        <td>
                            <span class="status-badge <?php echo $contact['contact_type'] === 'report' ? 'status-rejected' : 'status-approved'; ?>">
                                <?php echo ucfirst($contact['contact_type']); ?>
                            </span>
                        </td>
                        <td><?php echo htmlspecialchars(substr($contact['message'], 0, 100)) . '...'; ?></td>
                        <td><?php echo date('Y-m-d H:i', strtotime($contact['created_at'])); ?></td>
                        <td>
                            <?php if ($contact['resolved'] == 1): ?>
                                <span class="status-badge status-resolved">✅ Resolved</span>
                            <?php else: ?>
                                <span class="status-badge status-unresolved">⏳ Pending</span>
                            <?php endif; ?>
                        </td>
                        <td>
                            <?php if ($contact['resolved'] != 1): ?>
                                <button onclick="openResponseModal(<?php echo $contact['id']; ?>, '<?php echo htmlspecialchars($contact['email']); ?>', '<?php echo htmlspecialchars($contact['title']); ?>')" class="btn-sm btn-info">📧 Respond</button>
                            <?php endif; ?>
                            <form method="POST" style="display: inline;">
                                <input type="hidden" name="contact_id" value="<?php echo $contact['id']; ?>">
                                <button type="submit" name="delete_contact" value="1" class="btn-sm btn-danger" onclick="return confirm('Delete this contact/report?')">🗑️ Delete</button>
                            </form>
                        </td>
                    </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        </div>
    </div>

    <!-- Image Modal -->
    <div id="imageModal" class="image-modal">
        <span class="close" onclick="closeModal()">&times;</span>
        <img class="modal-content" id="modalImage">
    </div>

    <!-- Confirmation Modal -->
    <div id="confirmationModal" class="confirmation-modal">
        <div class="confirmation-content">
            <h3>⚠️ Confirm Action</h3>
            <p id="confirmationMessage">Are you sure you want to change the hospital status?</p>
            <div class="confirmation-buttons">
                <button id="confirmYes" class="confirm-yes">Yes, Confirm</button>
                <button id="confirmNo" class="confirm-no" onclick="closeConfirmationModal()">Cancel</button>
            </div>
        </div>
    </div>

    <!-- Response Modal -->
    <div id="responseModal" class="response-modal">
        <div class="response-content">
            <h3>📧 Respond to Contact/Report</h3>
            <p><strong>Email:</strong> <span id="responseEmail"></span></p>
            <p><strong>Subject:</strong> <span id="responseSubject"></span></p>
            
            <form id="responseForm" method="POST">
                <input type="hidden" name="contact_id" id="responseContactId">
                <div class="form-group">
                    <label for="response_message">Your Response:</label>
                    <textarea name="response_message" id="response_message" rows="6" placeholder="Type your response message here..." required></textarea>
                </div>
                
                <div class="response-buttons">
                    <button type="button" onclick="closeResponseModal()" class="btn-sm btn-secondary">Cancel</button>
                    <button type="submit" name="respond_contact" class="btn-sm btn-success">📧 Send Response</button>
                </div>
            </form>
        </div>
    </div>

    <!-- Hidden form for hospital actions -->
    <form id="hospitalActionForm" method="POST" style="display: none;">
        <input type="hidden" name="hospital_id" id="hospitalActionId">
        <input type="hidden" name="hospital_action" id="hospitalActionType">
    </form>

    <script>
        // Session management
        let sessionTimeout = 1800; // 30 minutes
        let sessionTimer;
        let lastActivity = Date.now();
        
        function updateSessionTimer() {
            const now = Date.now();
            const elapsed = Math.floor((now - lastActivity) / 1000);
            const remaining = Math.max(0, sessionTimeout - elapsed);
            
            if (remaining === 0) {
                alert('Session expired! You will be redirected to logout.');
                window.location.href = '../logout.php';
                return;
            }
            
            const minutes = Math.floor(remaining / 60);
            const seconds = remaining % 60;
            document.getElementById('sessionTimer').textContent = 
                `Session: ${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
        }
        
        function refreshSession() {
            fetch(window.location.href, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: 'action=refresh_session'
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    lastActivity = Date.now();
                }
            });
        }
        
        // Reset activity timer on user interaction
        document.addEventListener('mousemove', () => {
            lastActivity = Date.now();
            refreshSession();
        });
        
        document.addEventListener('keypress', () => {
            lastActivity = Date.now();
            refreshSession();
        });
        
        // Start session timer
        sessionTimer = setInterval(updateSessionTimer, 1000);
        updateSessionTimer();
        
        // Tab management with URL persistence
        function showTab(tabName) {
            // Hide all tabs
            const tabs = document.querySelectorAll('.tab-content');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            // Remove active class from nav tabs
            const navTabs = document.querySelectorAll('.nav-tab');
            navTabs.forEach(tab => tab.classList.remove('active'));
            
            // Show selected tab
            document.getElementById(tabName).classList.add('active');
            event.target.classList.add('active');
            
            // Update URL without page refresh
            const url = new URL(window.location);
            url.searchParams.set('tab', tabName);
            window.history.pushState({}, '', url);
        }
        
        // Hospital filter functions
        function filterHospitals(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'hospitals');
            if (filter) {
                url.searchParams.set('hospital_filter', filter);
            } else {
                url.searchParams.delete('hospital_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearHospitalFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'hospitals');
            url.searchParams.delete('hospital_filter');
            window.location.href = url.toString();
        }
        
        // Security logs filter functions
        function filterSecurityLogs(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'security');
            if (filter) {
                url.searchParams.set('security_filter', filter);
            } else {
                url.searchParams.delete('security_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearSecurityFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'security');
            url.searchParams.delete('security_filter');
            window.location.href = url.toString();
        }
        
        // Login attempts filter functions
        function filterLoginAttempts(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'logins');
            if (filter) {
                url.searchParams.set('login_filter', filter);
            } else {
                url.searchParams.delete('login_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearLoginFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'logins');
            url.searchParams.delete('login_filter');
            window.location.href = url.toString();
        }
        
        // Events filter functions
        function filterEvents(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'events');
            if (filter) {
                url.searchParams.set('event_filter', filter);
            } else {
                url.searchParams.delete('event_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearEventFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'events');
            url.searchParams.delete('event_filter');
            window.location.href = url.toString();
        }
        
        // FAQ filter functions
        function filterFAQs(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'faq');
            if (filter) {
                url.searchParams.set('faq_filter', filter);
            } else {
                url.searchParams.delete('faq_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearFAQFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'faq');
            url.searchParams.delete('faq_filter');
            window.location.href = url.toString();
        }
        
        // Contacts filter functions
        function filterContacts(filter) {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'contacts');
            if (filter) {
                url.searchParams.set('contact_filter', filter);
            } else {
                url.searchParams.delete('contact_filter');
            }
            window.location.href = url.toString();
        }
        
        function clearContactFilter() {
            const url = new URL(window.location);
            url.searchParams.set('tab', 'contacts');
            url.searchParams.delete('contact_filter');
            window.location.href = url.toString();
        }
        
        // Image modal functions
        function openModal(imageSrc) {
            document.getElementById('imageModal').style.display = 'block';
            document.getElementById('modalImage').src = imageSrc;
        }
        
        function closeModal() {
            document.getElementById('imageModal').style.display = 'none';
        }
        
        // Hospital action confirmation modal
        function confirmHospitalAction(hospitalId, action) {
            const actionMessages = {
                'approve': 'Are you sure you want to APPROVE this hospital?',
                'reject': 'Are you sure you want to REJECT this hospital?',
                'pending': 'Are you sure you want to set this hospital status to PENDING?'
            };
            
            document.getElementById('confirmationMessage').textContent = actionMessages[action];
            document.getElementById('hospitalActionId').value = hospitalId;
            document.getElementById('hospitalActionType').value = action;
            document.getElementById('confirmationModal').style.display = 'block';
            
            // Set up the confirm button
            document.getElementById('confirmYes').onclick = function() {
                document.getElementById('hospitalActionForm').submit();
            };
        }
        
        function closeConfirmationModal() {
            document.getElementById('confirmationModal').style.display = 'none';
        }
        
        // Response modal functions
        function openResponseModal(contactId, email, subject) {
            document.getElementById('responseContactId').value = contactId;
            document.getElementById('responseEmail').textContent = email;
            document.getElementById('responseSubject').textContent = subject;
            document.getElementById('response_message').value = '';
            document.getElementById('responseModal').style.display = 'block';
        }
        
        function closeResponseModal() {
            document.getElementById('responseModal').style.display = 'none';
        }
        
        // Close modals when clicking outside
        window.onclick = function(event) {
            const imageModal = document.getElementById('imageModal');
            const confirmModal = document.getElementById('confirmationModal');
            const responseModal = document.getElementById('responseModal');
            
            if (event.target == imageModal) {
                closeModal();
            }
            if (event.target == confirmModal) {
                closeConfirmationModal();
            }
            if (event.target == responseModal) {
                closeResponseModal();
            }
        }
        
        // Close modals with Escape key
        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                closeModal();
                closeConfirmationModal();
                closeResponseModal();
            }
        });
    </script>

<?php endif; ?>

<script>
// OTP Timer (only for step 2)
<?php if (!$is_logged_in && $_SESSION['login_step'] == 2): ?>
let otpStartTime = <?php echo $_SESSION['otp_time']; ?>;
let otpDuration = 300; // 5 minutes

function updateOTPTimer() {
    let currentTime = Math.floor(Date.now() / 1000);
    let elapsed = currentTime - otpStartTime;
    let remaining = Math.max(0, otpDuration - elapsed);
    
    if (remaining === 0) {
        document.getElementById('countdown').textContent = 'EXPIRED';
        document.getElementById('otpTimer').style.color = '#e74c3c';
        return;
    }
    
    let minutes = Math.floor(remaining / 60);
    let seconds = remaining % 60;
    document.getElementById('countdown').textContent = 
        `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

// Update OTP timer every second
setInterval(updateOTPTimer, 1000);
updateOTPTimer();
<?php endif; ?>
</script>

</body>
</html>
