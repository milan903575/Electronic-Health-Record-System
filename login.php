<?php
include 'connection.php';
session_start();

// Security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains');

// Rate limiting configuration
$max_attempts = 5;
$lockout_duration = 300; // 5 minutes in seconds
$attempt_window = 900; // 15 minutes in seconds

// CSRF token generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Function to log security events
function logSecurityEvent($conn, $email, $event_type, $ip_address, $user_agent) {
    $stmt = $conn->prepare("INSERT INTO security_logs (email, event_type, ip_address, user_agent, timestamp) VALUES (?, ?, ?, ?, NOW())");
    $stmt->bind_param("ssss", $email, $event_type, $ip_address, $user_agent);
    $stmt->execute();
    $stmt->close();
}

// FIXED: Function to check if account is locked and auto-clear expired locks
function checkAccountLock($conn, $email) {
    $stmt = $conn->prepare("SELECT locked_until, failed_attempts FROM user_security WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        if ($row['locked_until'] && strtotime($row['locked_until']) > time()) {
            // Still locked
            $stmt->close();
            return strtotime($row['locked_until']);
        } else if ($row['locked_until'] && strtotime($row['locked_until']) <= time()) {
            // Lock has expired - RESET EVERYTHING
            $clear_stmt = $conn->prepare("UPDATE user_security SET locked_until = NULL, failed_attempts = 0 WHERE email = ?");
            $clear_stmt->bind_param("s", $email);
            $clear_stmt->execute();
            $clear_stmt->close();
            
            // Also clear old login attempts
            $clear_attempts_stmt = $conn->prepare("DELETE FROM login_attempts WHERE email = ? AND success = 0");
            $clear_attempts_stmt->bind_param("s", $email);
            $clear_attempts_stmt->execute();
            $clear_attempts_stmt->close();
        }
    }
    $stmt->close();
    return false;
}

// Function to lock account
function lockAccount($conn, $email, $lockout_duration, $max_attempts) {
    $locked_until = date('Y-m-d H:i:s', time() + $lockout_duration);
    $stmt = $conn->prepare("INSERT INTO user_security (email, failed_attempts, locked_until, last_attempt) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE failed_attempts = ?, locked_until = ?, last_attempt = NOW()");
    $stmt->bind_param("sisss", $email, $max_attempts, $locked_until, $max_attempts, $locked_until);
    $stmt->execute();
    $stmt->close();
}

// FIXED: Simple function to record failed attempt
function recordFailedAttempt($conn, $email, $ip_address) {
    // Record the failed login attempt
    $stmt = $conn->prepare("INSERT INTO login_attempts (email, ip_address, success, timestamp) VALUES (?, ?, 0, NOW())");
    $stmt->bind_param("ss", $email, $ip_address);
    $stmt->execute();
    $stmt->close();

    // Update the failed attempts count
    $stmt = $conn->prepare("INSERT INTO user_security (email, failed_attempts, last_attempt) VALUES (?, 1, NOW()) ON DUPLICATE KEY UPDATE failed_attempts = failed_attempts + 1, last_attempt = NOW()");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->close();
}

// FIXED: Function to get current failed attempts count
function getFailedAttemptsCount($conn, $email) {
    $stmt = $conn->prepare("SELECT failed_attempts FROM user_security WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();
    $failed_count = 0;
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $failed_count = $row['failed_attempts'] ?? 0;
    }
    $stmt->close();
    return $failed_count;
}

// Function to reset failed attempts
function resetFailedAttempts($conn, $email) {
    $stmt = $conn->prepare("UPDATE user_security SET failed_attempts = 0, locked_until = NULL WHERE email = ?");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->close();
}

// Function to record successful login
function recordSuccessfulLogin($conn, $email, $ip_address) {
    $stmt = $conn->prepare("INSERT INTO login_attempts (email, ip_address, success, timestamp) VALUES (?, ?, 1, NOW())");
    $stmt->bind_param("ss", $email, $ip_address);
    $stmt->execute();
    $stmt->close();
}

// Function to sanitize input
function sanitizeInput($data) {
    return htmlspecialchars(trim($data), ENT_QUOTES, 'UTF-8');
}

// Function to validate email
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
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

// Initialize variables
$message = '';
$message_type = '';
$redirect_url = '';
$locked_until = 0;
$is_locked = false;
$remaining_attempts = 0;

// POST/REDIRECT/GET PATTERN - Handle POST requests and redirect
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        logSecurityEvent($conn, '', 'CSRF_ATTACK', $ip_address, $user_agent);
        $_SESSION['login_message'] = 'Security token mismatch. Please refresh the page and try again.';
        $_SESSION['login_message_type'] = 'error';
        header('Location: login.php');
        exit;
    } else if (isset($_POST['email']) && isset($_POST['password'])) {
        // Sanitize and validate inputs
        $email = sanitizeInput($_POST['email']);
        $password = $_POST['password'];
        
        // Validate email format
        if (!validateEmail($email)) {
            logSecurityEvent($conn, $email, 'INVALID_EMAIL_FORMAT', $ip_address, $user_agent);
            $_SESSION['login_message'] = "Invalid email format.";
            $_SESSION['login_message_type'] = 'error';
            header('Location: login.php');
            exit;
        } else if (strlen($email) > 255 || strlen($password) > 255) {
            logSecurityEvent($conn, $email, 'INPUT_TOO_LONG', $ip_address, $user_agent);
            $_SESSION['login_message'] = "Input too long.";
            $_SESSION['login_message_type'] = 'error';
            header('Location: login.php');
            exit;
        } else {
            // FIRST: Check account lock status (this will auto-clear expired locks)
            $locked_until = checkAccountLock($conn, $email);
            if ($locked_until) {
                logSecurityEvent($conn, $email, 'LOGIN_ATTEMPT_WHILE_LOCKED', $ip_address, $user_agent);
                $_SESSION['login_message'] = "Account temporarily locked due to multiple failed login attempts.";
                $_SESSION['login_message_type'] = 'locked';
                $_SESSION['login_locked_until'] = $locked_until;
                header('Location: login.php');
                exit;
            }
            
            // FIXED: Single authentication check for all user types
            $user_found = false;
            $password_correct = false;
            $user_data = null;
            $user_type = '';
            
            // Check patient login
            $sql_patient = "SELECT * FROM patients WHERE email = ?";
            $stmt_patient = $conn->prepare($sql_patient);
            $stmt_patient->bind_param("s", $email);
            $stmt_patient->execute();
            $result_patient = $stmt_patient->get_result();
            
            if ($result_patient->num_rows > 0) {
                $user_found = true;
                $user_data = $result_patient->fetch_assoc();
                $user_type = 'patient';
                if (password_verify($password, $user_data['password'])) {
                    $password_correct = true;
                }
            }
            $stmt_patient->close();
            
            // Check doctor login if not found in patients
            if (!$user_found) {
                $sql_doctor = "SELECT * FROM doctors WHERE email = ?";
                $stmt_doctor = $conn->prepare($sql_doctor);
                $stmt_doctor->bind_param("s", $email);
                $stmt_doctor->execute();
                $result_doctor = $stmt_doctor->get_result();
                
                if ($result_doctor->num_rows > 0) {
                    $user_found = true;
                    $user_data = $result_doctor->fetch_assoc();
                    $user_type = 'doctor';
                    if (password_verify($password, $user_data['password'])) {
                        $password_correct = true;
                    }
                }
                $stmt_doctor->close();
            }
            
            // Check receptionist login if not found in patients or doctors
            if (!$user_found) {
                $sql_receptionist = "SELECT * FROM receptionist WHERE email = ?";
                $stmt_receptionist = $conn->prepare($sql_receptionist);
                $stmt_receptionist->bind_param("s", $email);
                $stmt_receptionist->execute();
                $result_receptionist = $stmt_receptionist->get_result();
                
                if ($result_receptionist->num_rows > 0) {
                    $user_found = true;
                    $user_data = $result_receptionist->fetch_assoc();
                    $user_type = 'receptionist';
                    if (password_verify($password, $user_data['password'])) {
                        $password_correct = true;
                    }
                }
                $stmt_receptionist->close();
            }
            
            // Handle authentication result
            if ($user_found && $password_correct) {
                // Successful login - handle based on user type
                session_regenerate_id(true);
                $_SESSION['user_id'] = $user_data['id'];
                $_SESSION['user_type'] = $user_type;
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                
                resetFailedAttempts($conn, $email);
                recordSuccessfulLogin($conn, $email, $ip_address);
                logSecurityEvent($conn, $email, 'SUCCESSFUL_LOGIN', $ip_address, $user_agent);
                
                // Set redirect based on user type and status
                if ($user_type === 'patient') {
                    $_SESSION['profile_picture'] = $user_data['profile_picture'];
                    $_SESSION['login_redirect_url'] = "patient/verify_face.php";
                    $_SESSION['login_message'] = "Credentials verified. Proceeding to face verification.";
                    $_SESSION['login_message_type'] = 'success';
                } elseif ($user_type === 'doctor') {
                    if ($user_data['registration_status'] === 'pending') {
                        $_SESSION['login_message'] = "Your application is under review.";
                        $_SESSION['login_message_type'] = 'warning';
                    } elseif ($user_data['registration_status'] === 'rejected') {
                        $_SESSION['login_message'] = "Your application has been rejected. Please contact support.";
                        $_SESSION['login_message_type'] = 'error';
                    } elseif ($user_data['registration_status'] === 'approved') {
                        $_SESSION['login_redirect_url'] = "doctor/doctor_profile.php";
                        $_SESSION['login_message'] = "Login successful! Welcome to your dashboard.";
                        $_SESSION['login_message_type'] = 'success';
                    }
                } elseif ($user_type === 'receptionist') {
                    if ($user_data['status'] === 'pending') {
                        $_SESSION['login_message'] = "Your application is under review.";
                        $_SESSION['login_message_type'] = 'warning';
                    } elseif ($user_data['status'] === 'rejected') {
                        $_SESSION['login_message'] = "Your application has been rejected. Please contact support.";
                        $_SESSION['login_message_type'] = 'error';
                    } elseif ($user_data['status'] === 'approved') {
                        $_SESSION['login_redirect_url'] = "receptionist/receptionist_dashboard.php";
                        $_SESSION['login_message'] = "Login successful! Welcome to your dashboard.";
                        $_SESSION['login_message_type'] = 'success';
                    }
                }
            } else {
                // FAILED LOGIN - Record only once
                recordFailedAttempt($conn, $email, $ip_address);
                
                if ($user_found) {
                    logSecurityEvent($conn, $email, 'FAILED_LOGIN_WRONG_PASSWORD', $ip_address, $user_agent);
                } else {
                    logSecurityEvent($conn, $email, 'EMAIL_NOT_FOUND', $ip_address, $user_agent);
                }
                
                // Get current failed attempts count AFTER recording the failure
                $current_failed_count = getFailedAttemptsCount($conn, $email);
                
                // Check if account should be locked
                if ($current_failed_count >= $max_attempts) {
                    lockAccount($conn, $email, $lockout_duration, $max_attempts);
                    logSecurityEvent($conn, $email, 'ACCOUNT_LOCKED', $ip_address, $user_agent);
                    $_SESSION['login_message'] = "Account locked due to multiple failed attempts.";
                    $_SESSION['login_message_type'] = 'locked';
                    $_SESSION['login_locked_until'] = time() + $lockout_duration;
                } else {
                    $remaining_attempts = $max_attempts - $current_failed_count;
                    if ($user_found) {
                        $_SESSION['login_message'] = "Incorrect password. {$remaining_attempts} attempt" . ($remaining_attempts == 1 ? '' : 's') . " remaining.";
                    } else {
                        $_SESSION['login_message'] = "Email address not found. {$remaining_attempts} attempt" . ($remaining_attempts == 1 ? '' : 's') . " remaining.";
                    }
                    $_SESSION['login_message_type'] = 'warning';
                }
            }
            
            header('Location: login.php');
            exit;
        }
    } else {
        logSecurityEvent($conn, '', 'MISSING_CREDENTIALS', $ip_address, $user_agent);
        $_SESSION['login_message'] = "Email and password fields are required.";
        $_SESSION['login_message_type'] = 'error';
        header('Location: login.php');
        exit;
    }
}

// GET REQUEST - Display messages from session and clear them
if (isset($_SESSION['login_message'])) {
    $message = $_SESSION['login_message'];
    $message_type = $_SESSION['login_message_type'] ?? '';
    unset($_SESSION['login_message'], $_SESSION['login_message_type']);
}

if (isset($_SESSION['login_redirect_url'])) {
    $redirect_url = $_SESSION['login_redirect_url'];
    unset($_SESSION['login_redirect_url']);
}

if (isset($_SESSION['login_locked_until'])) {
    $locked_until = $_SESSION['login_locked_until'];
    $is_locked = true;
    unset($_SESSION['login_locked_until']);
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap');

        :root {
            --primary-color: #4361ee;
            --secondary-color: #3a0ca3;
            --accent-color: #a0c4ff;
            --text-primary: #2b2d42;
            --text-secondary: #6c757d;
            --bg-gradient: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            --card-bg: #ffffff;
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            --error-color: #dc3545;
            --warning-color: #fd7e14;
            --success-color: #28a745;
            --locked-color: #e74c3c;
            --locked-bg: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 50%, #dc3545 100%);
            --locked-shadow: 0 20px 40px rgba(231, 76, 60, 0.4);
            --unlock-color: #28a745;
        }
        
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;    
            font-family: 'Outfit', sans-serif;
        }

        body {
            background: linear-gradient(135deg, #a0c4ff 0%, #6fa1ff 100%);
            min-height: 100vh;
        }

        .container {
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            padding: 20px;
        }

        .screen {        
            background: white;
            position: relative;    
            width: 360px;
            border-radius: 20px;
            overflow: hidden;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.15);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        
        .screen:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }

        .screen__content {
            position: relative;    
            height: 100%;
            z-index: 1;
            padding: 35px 30px;
        }

        .screen__background {        
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            z-index: 0;
            overflow: hidden;
        }

        .screen__background__shape {
            position: absolute;
            transform: rotate(45deg);
        }

        .screen__background__shape1 {
            height: 520px;
            width: 520px;
            background: rgba(160, 196, 255, 0.1);    
            top: -50px;
            right: 120px;    
            border-radius: 72px;
        }

        .screen__background__shape2 {
            height: 220px;
            width: 220px;
            background: rgba(131, 174, 253, 0.1);    
            top: -172px;
            right: 0;    
            border-radius: 32px;
        }

        .login {
            width: 100%;
            padding-top: 20px;
        }
        
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        
        .login-header h1 {
            color: var(--primary-color);
            font-size: 1.8rem;
            margin-bottom: 8px;
        }

        .login__field {
            position: relative;
            margin-bottom: 24px;
        }

        .login__icon {
            position: absolute;
            top: 50%;
            transform: translateY(-50%);
            left: 12px;
            color: #6fa1ff;
            font-size: 1rem;
            transition: color 0.3s;
        }

        .login__input {
            width: 100%;
            padding: 14px;
            padding-left: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            background-color: #f9fafb;
            font-size: 0.95rem;
            transition: border-color 0.3s, box-shadow 0.3s;
        }

        .login__input:focus {
            outline: none;
            border-color: #6fa1ff;
            box-shadow: 0 0 0 3px rgba(111, 161, 255, 0.15);
        }
        
        .login__input:focus + .login__icon {
            color: #4361ee;
        }

        .login__submit {
            width: 100%;
            padding: 14px;
            border: none;
            border-radius: 8px;
            background: linear-gradient(to right, #4361ee, #6fa1ff);
            color: white;
            font-weight: 600;
            font-size: 1rem;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: transform 0.3s, box-shadow 0.3s;
            box-shadow: 0 4px 12px rgba(111, 161, 255, 0.3);
        }

        .login__submit:hover:not(:disabled) {
            transform: translateY(-2px);
            box-shadow: 0 6px 15px rgba(111, 161, 255, 0.4);
        }
        
        .login__submit:active {
            transform: translateY(0);
        }

        .login__submit:disabled {
            background: #ccc;
            cursor: not-allowed;
            box-shadow: none;
        }

        .button__icon {
            margin-left: 8px;
        }

        /* Simple Lock Screen Styles */
        .lock-screen {
            text-align: center;
            padding: 30px 20px;
            background: var(--locked-bg);
            border-radius: 16px;
            margin-bottom: 25px;
            box-shadow: var(--locked-shadow);
            animation: fadeIn 0.5s ease-out;
        }

        .security-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 255, 255, 0.15);
            padding: 8px 16px;
            border-radius: 25px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            font-size: 0.85rem;
            color: white;
            font-weight: 500;
        }

        .lock-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .lock-subtitle {
            font-size: 0.95rem;
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 25px;
            line-height: 1.5;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
        }

        .countdown-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .countdown-title {
            font-size: 1rem;
            color: var(--locked-color);
            margin-bottom: 15px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .countdown-timer {
            display: flex;
            justify-content: center;
            gap: 15px;
            margin: 15px 0;
        }

        .time-unit {
            text-align: center;
            background: linear-gradient(145deg, #ffffff, #f0f0f0);
            border-radius: 12px;
            padding: 12px 8px;
            box-shadow: 
                0 4px 8px rgba(0, 0, 0, 0.1),
                inset 0 1px 0 rgba(255, 255, 255, 0.8);
            min-width: 65px;
            position: relative;
            overflow: hidden;
        }

        .time-unit::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 2px;
            background: linear-gradient(90deg, var(--locked-color), #ff6b6b);
        }

        .time-value {
            font-size: 1.8rem;
            font-weight: 800;
            color: var(--locked-color);
            display: block;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }

        .time-label {
            font-size: 0.7rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 0.8px;
            margin-top: 4px;
            font-weight: 600;
        }

        .security-info {
            background: rgba(255, 255, 255, 0.1);
            border-radius: 10px;
            padding: 15px;
            margin: 20px 0;
            backdrop-filter: blur(5px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .security-info-title {
            font-size: 0.9rem;
            font-weight: 600;
            color: white;
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .security-info-text {
            font-size: 0.8rem;
            color: rgba(255, 255, 255, 0.8);
            line-height: 1.4;
        }

        /* Simple Loader */
        .simple-loader {
            width: 40px;
            height: 40px;
            margin: 0 auto 20px;
            border: 4px solid rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            border-top-color: white;
            animation: spin 1s linear infinite;
        }

        /* Unlock Message Styles */
        .unlock-message {
            text-align: center;
            padding: 30px 20px;
            background: linear-gradient(135deg, #28a745 0%, #20c997 50%, #17a2b8 100%);
            border-radius: 16px;
            margin-bottom: 25px;
            box-shadow: 0 20px 40px rgba(40, 167, 69, 0.4);
            animation: unlockSlide 0.8s ease-out;
        }

        .unlock-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: rgba(255, 255, 255, 0.15);
            padding: 8px 16px;
            border-radius: 25px;
            margin-bottom: 20px;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            font-size: 0.85rem;
            color: white;
            font-weight: 500;
        }

        .unlock-icon {
            font-size: 3rem;
            color: white;
            margin-bottom: 15px;
            animation: unlockBounce 1s ease-out;
        }

        .unlock-title {
            font-size: 1.4rem;
            font-weight: 700;
            color: white;
            margin-bottom: 8px;
            text-shadow: 0 2px 4px rgba(0, 0, 0, 0.3);
        }

        .unlock-subtitle {
            font-size: 0.95rem;
            color: rgba(255, 255, 255, 0.9);
            margin-bottom: 25px;
            line-height: 1.5;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.2);
        }

        /* Alert Styles */
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            font-size: 0.9rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            animation: slideDown 0.3s ease-out;
        }

        .alert-error {
            background-color: rgba(220, 53, 69, 0.1);
            color: var(--error-color);
            border: 1px solid rgba(220, 53, 69, 0.2);
        }

        .alert-warning {
            background-color: rgba(253, 126, 20, 0.1);
            color: var(--warning-color);
            border: 1px solid rgba(253, 126, 20, 0.2);
        }

        .alert-success {
            background-color: rgba(40, 167, 69, 0.1);
            color: var(--success-color);
            border: 1px solid rgba(40, 167, 69, 0.2);
        }

        .alert-icon {
            margin-right: 10px;
            font-size: 1.1rem;
        }

        .alert-content {
            flex: 1;
        }

        /* Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        @keyframes slideDown {
            from {
                opacity: 0;
                transform: translateY(-20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        @keyframes unlockSlide {
            0% {
                opacity: 0;
                transform: translateY(-30px) scale(0.9);
            }
            100% {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        @keyframes unlockBounce {
            0%, 20%, 50%, 80%, 100% {
                transform: translateY(0);
            }
            40% {
                transform: translateY(-10px);
            }
            60% {
                transform: translateY(-5px);
            }
        }

        .forgot-password {
            text-align: center;
            margin-top: 20px;
        }
        
        .forgot-password a {
            color: #4361ee;
            text-decoration: none;
            font-weight: 500;
            transition: color 0.3s;
            display: inline-flex;
            align-items: center;
            gap: 5px;
        }
        
        .forgot-password a:hover {
            color: #3a0ca3;
            text-decoration: underline;
        }

        .create-account {
            text-align: center;
            margin-top: 25px;
        }
        
        .create-account h3 {
            color: #6c757d;
            font-size: 0.9rem;
            margin-bottom: 12px;
            font-weight: 500;
        }

        .social-icons {
            display: flex;
            align-items: center;
            justify-content: center;
            flex-wrap: wrap;
            gap: 10px;
        }

        .social-login__icon {
            padding: 8px 12px;
            background-color: #f1f5f9;
            color: #4361ee;
            text-decoration: none;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
            transition: all 0.3s;
        }

        .social-login__icon:hover {
            background-color: #4361ee;
            color: white;
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="screen">
            <div class="screen__content">
                <div class="login-header">
                    <h1>Welcome Back</h1>
                </div>

                <?php if ($is_locked && $locked_until): ?>
                    <!-- Lock Screen with countdown -->
                    <div class="lock-screen" id="lockScreen">
                        <div class="security-badge">
                            <i class="fas fa-shield-alt"></i>
                            <span>Security Protection Active</span>
                        </div>
                        
                        <div class="simple-loader"></div>
                        
                        <div class="lock-title">Account Temporarily Locked</div>
                        <div class="lock-subtitle">
                            Your account has been secured due to multiple failed login attempts. 
                            This is an automated security measure to protect your account.
                        </div>
                        
                        <div class="countdown-container">
                            <div class="countdown-title">Unlock Timer</div>
                            <div class="countdown-timer" id="countdown-timer">
                                <div class="time-unit">
                                    <span class="time-value" id="hours">00</span>
                                    <span class="time-label">Hours</span>
                                </div>
                                <div class="time-unit">
                                    <span class="time-value" id="minutes">00</span>
                                    <span class="time-label">Minutes</span>
                                </div>
                                <div class="time-unit">
                                    <span class="time-value" id="seconds">00</span>
                                    <span class="time-label">Seconds</span>
                                </div>
                            </div>
                        </div>
                        
                        <div class="security-info">
                            <div class="security-info-title">
                                <i class="fas fa-info-circle"></i>
                                Security Information
                            </div>
                            <div class="security-info-text">
                                Your account will automatically unlock when the timer reaches zero. 
                                You can then continue with valid credentials.
                            </div>
                        </div>
                    </div>

                    <!-- Unlock Message (hidden initially) -->
                    <div class="unlock-message" id="unlockMessage" style="display: none;">
                        <div class="unlock-badge">
                            <i class="fas fa-unlock-alt"></i>
                            <span>Account Unlocked</span>
                        </div>
                        
                        <i class="fas fa-unlock-alt unlock-icon"></i>
                        
                        <div class="unlock-title">Account Successfully Unlocked</div>
                        <div class="unlock-subtitle">
                            Your account has been unlocked. You can now continue with valid credentials.
                        </div>
                    </div>
                <?php else: ?>
                    <!-- Regular login form -->
                    <?php if (!empty($message) && $message_type !== 'locked'): ?>
                        <div class="alert alert-<?php echo $message_type; ?>">
                            <i class="alert-icon fas fa-<?php 
                                echo $message_type === 'error' ? 'exclamation-circle' : 
                                    ($message_type === 'warning' ? 'exclamation-triangle' : 'check-circle'); 
                            ?>"></i>
                            <div class="alert-content">
                                <?php echo htmlspecialchars($message, ENT_QUOTES, 'UTF-8'); ?>
                            </div>
                        </div>
                    <?php endif; ?>

                    <form class="login" action="login.php" method="POST" id="loginForm">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES, 'UTF-8'); ?>">
                        <div class="login__field">
                            <input type="email" class="login__input" id="email" name="email" placeholder="Email" required maxlength="255">
                            <i class="login__icon fas fa-envelope"></i>
                        </div>
                        <div class="login__field">
                            <input type="password" class="login__input" id="password" name="password" placeholder="Password" required maxlength="255">
                            <i class="login__icon fas fa-lock"></i>
                        </div>
                        <button class="login__submit" type="submit">
                            <span>Log In</span>
                            <i class="button__icon fas fa-chevron-right"></i>
                        </button>
                    </form>
                <?php endif; ?>

                <!-- Always show forgot password and registration links -->
                <div class="forgot-password">
                    <a href="forget_password/forget_password.php">
                        <i class="fas fa-key"></i>
                        Forgot Password?
                    </a>
                </div>
                <div class="create-account">
                    <h3>Create Account via</h3>
                    <div class="social-icons">
                        <a href="patient/patient_registration.php" class="social-login__icon">
                            <i class="fas fa-user"></i> Patient
                        </a>
                        <a href="doctor/doctor_registration.php" class="social-login__icon">
                            <i class="fas fa-user-md"></i> Doctor
                        </a>
                        <a href="receptionist/receptionist_registration.php" class="social-login__icon">
                            <i class="fas fa-user-tie"></i> Receptionist
                        </a>
                        <a href="admin/hospital_registration.php" class="social-login__icon">
                            <i class="fas fa-hospital"></i> Hospital
                        </a>
                    </div>
                </div>
            </div>
            <div class="screen__background">
                <span class="screen__background__shape screen__background__shape1"></span>
                <span class="screen__background__shape screen__background__shape2"></span>
            </div>        
        </div>
    </div>

    <script>
        // Countdown timer for locked accounts
        <?php if ($is_locked && $locked_until): ?>
        const lockedUntil = <?php echo $locked_until; ?>;
        
        function updateCountdown() {
            const now = Math.floor(Date.now() / 1000);
            const remaining = lockedUntil - now;
            
            if (remaining <= 0) {
                // Show unlock message
                document.getElementById('lockScreen').style.display = 'none';
                document.getElementById('unlockMessage').style.display = 'block';
                
                // Auto-reload after 3 seconds to show login form
                setTimeout(function() {
                    location.reload();
                }, 3000);
                return;
            }
            
            const hours = Math.floor(remaining / 3600);
            const minutes = Math.floor((remaining % 3600) / 60);
            const seconds = remaining % 60;
            
            document.getElementById('hours').textContent = hours.toString().padStart(2, '0');
            document.getElementById('minutes').textContent = minutes.toString().padStart(2, '0');
            document.getElementById('seconds').textContent = seconds.toString().padStart(2, '0');
        }
        
        updateCountdown();
        setInterval(updateCountdown, 1000);
        <?php endif; ?>

        // Auto-redirect on success
        <?php if (!empty($redirect_url)): ?>
        setTimeout(function() {
            window.location.href = '<?php echo htmlspecialchars($redirect_url, ENT_QUOTES, 'UTF-8'); ?>';
        }, 2000);
        <?php endif; ?>

        // Form validation
        document.addEventListener("DOMContentLoaded", function() {
            const form = document.getElementById("loginForm");
            const emailInput = document.getElementById("email");
            const passwordInput = document.getElementById("password");

            if (form) {
                form.addEventListener("submit", function(event) {
                    const errors = [];

                    // Email validation
                    if (!emailInput.value.trim()) {
                        errors.push("Email is required.");
                    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailInput.value)) {
                        errors.push("Please enter a valid email address.");
                    }

                    // Password validation
                    if (!passwordInput.value) {
                        errors.push("Password is required.");
                    }

                    if (errors.length > 0) {
                        event.preventDefault();
                        alert(errors.join('\n'));
                    }
                });

                // Real-time email validation
                emailInput.addEventListener("blur", function() {
                    if (this.value && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(this.value)) {
                        this.style.borderColor = "#dc3545";
                    } else {
                        this.style.borderColor = "#e0e0e0";
                    }
                });
            }
        });
    </script>
</body>
</html>
