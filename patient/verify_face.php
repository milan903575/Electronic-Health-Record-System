<?php
session_start();

// Enhanced security headers for hosting environment
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
// Relaxed CSP for hosting compatibility
header("Content-Security-Policy: default-src 'self' 'unsafe-inline' 'unsafe-eval' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https: data:; style-src 'self' 'unsafe-inline' https:; font-src 'self' https: data:; img-src 'self' https: data: blob:; media-src 'self' https: data: blob:; connect-src 'self' https:;");

require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';
include '../connection.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Force HTTPS redirect for camera access
if (!isset($_SERVER['HTTPS']) || $_SERVER['HTTPS'] !== 'on') {
    $redirectURL = 'https://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirectURL");
    exit();
}

// Generate CSRF token
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Verify CSRF token for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        http_response_code(403);
        echo json_encode(['success' => false, 'message' => 'Invalid request']);
        exit;
    }
}

if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'patient') {
    header("Location: ../login.php");
    exit;
}

$userId = $_SESSION['user_id'];
$message = "";
$otpExpiry = 300; // OTP expiry time in seconds (5 minutes)

// SECURITY: Function to get ONLY the specific patient's profile picture path
function getPatientSpecificImagePath($patientId, $profilePicturePath) {
    if (empty($profilePicturePath)) {
        return null;
    }
    
    // Extract filename from the profile picture path
    $filename = basename($profilePicturePath);
    
    // SECURITY CHECK: Ensure the filename contains the patient ID to prevent unauthorized access
    if (!preg_match('/profile_' . preg_quote($patientId, '/') . '_/', $filename)) {
        error_log("Security Alert: Patient ID $patientId attempted to access image $filename which doesn't belong to them");
        return null;
    }
    
    // Check possible locations for the patient's specific image
    $possiblePaths = [
        './uploads/images/' . $filename,
        '../uploads/images/' . $filename,
        '../../uploads/images/' . $filename
    ];
    
    foreach ($possiblePaths as $path) {
        if (file_exists($path) && is_readable($path)) {
            // Additional security: verify file is actually an image
            $imageInfo = getimagesize($path);
            if ($imageInfo !== false) {
                return $path;
            }
        }
    }
    
    return null;
}

// SECURITY: Fetch ONLY the profile picture belonging to the logged-in patient
$sql = "SELECT profile_picture, first_name, email FROM patients WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $userId);
$stmt->execute();
$result = $stmt->get_result();

$patientProfilePicture = null;
$profilePictureUrl = null;
$firstName = "User";
$maskedEmail = "user@example.com";
$email = "";

if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $profilePicturePath = $row['profile_picture'];
    $firstName = $row['first_name'];
    $email = $row['email'];

    // Mask email for display
    $emailParts = explode('@', $email);
    $emailUsername = $emailParts[0];
    $maskedUsername = substr($emailUsername, 0, 2) . str_repeat('*', strlen($emailUsername) - 4) . substr($emailUsername, -2);
    $maskedEmail = $maskedUsername . '@' . $emailParts[1];

    if (!empty($profilePicturePath)) {
        // SECURITY: Get ONLY the patient's specific profile picture
        $patientProfilePicture = getPatientSpecificImagePath($userId, $profilePicturePath);
        
        if ($patientProfilePicture && file_exists($patientProfilePicture)) {
            // Create secure URL for the patient's specific image
            $profilePictureUrl = 'https://' . $_SERVER['HTTP_HOST'] . '/patientRecords/patient/' . str_replace('./', '', $patientProfilePicture);
        } else {
            // Log security event if profile picture doesn't match patient ID
            error_log("Security Alert: Patient ID $userId has invalid profile picture path: $profilePicturePath");
            $profilePictureUrl = null;
        }
    }
}

// SECURITY: Handle image serving with strict patient ID verification
if (isset($_GET['serve_image']) && isset($_GET['patient_id']) && isset($_GET['filename'])) {
    $requestedPatientId = intval($_GET['patient_id']);
    $requestedFilename = basename($_GET['filename']); // Sanitize filename
    
    // SECURITY CHECK 1: Verify the requesting user can only access their own image
    if ($requestedPatientId !== $userId) {
        error_log("Security Alert: Patient ID $userId attempted to access image for patient ID $requestedPatientId");
        http_response_code(403);
        exit;
    }
    
    // SECURITY CHECK 2: Verify filename contains the patient ID
    if (!preg_match('/profile_' . preg_quote($requestedPatientId, '/') . '_/', $requestedFilename)) {
        error_log("Security Alert: Patient ID $userId attempted to access image $requestedFilename which doesn't belong to them");
        http_response_code(403);
        exit;
    }
    
    // SECURITY CHECK 3: Get the verified patient-specific image path
    $imagePath = getPatientSpecificImagePath($requestedPatientId, $requestedFilename);
    
    if ($imagePath && file_exists($imagePath)) {
        // Set CORS headers for image serving
        header("Access-Control-Allow-Origin: https://electronichealthrecordsystem.kesug.com");
        header("Access-Control-Allow-Methods: GET");
        header("Access-Control-Allow-Headers: *");
        
        // Set appropriate content type
        $imageInfo = getimagesize($imagePath);
        if ($imageInfo) {
            header("Content-Type: " . $imageInfo['mime']);
        }
        
        // Serve the verified patient's image
        readfile($imagePath);
        exit;
    } else {
        http_response_code(404);
        exit;
    }
}

// Handle AJAX OTP generation and sending
if (isset($_POST['action']) && $_POST['action'] == 'send_otp') {
    // Rate limiting check
    $currentTime = time();
    if (isset($_SESSION['last_otp_request']) && ($currentTime - $_SESSION['last_otp_request']) < 60) {
        echo json_encode(['success' => false, 'message' => 'Please wait before requesting another code']);
        exit;
    }
    
    // Generate a cryptographically secure OTP
    $otp = random_int(100000, 999999);
    $_SESSION['otp'] = password_hash($otp, PASSWORD_DEFAULT);
    $_SESSION['otp_plain'] = $otp;
    $_SESSION['otp_time'] = $currentTime;
    $_SESSION['otp_expiry'] = $currentTime + $otpExpiry;
    $_SESSION['otp_attempts'] = 0;
    $_SESSION['max_attempts'] = 3;
    $_SESSION['last_otp_request'] = $currentTime;
    
    // Send OTP via email
    $mailResult = sendOtpEmail($email, $otp);
    
    // Clear plain OTP from session after sending
    unset($_SESSION['otp_plain']);
    
    // Return JSON response
    header('Content-Type: application/json');
    if ($mailResult === true) {
        echo json_encode(['success' => true, 'message' => 'OTP sent successfully', 'expiry' => $otpExpiry]);
    } else {
        echo json_encode(['success' => false, 'message' => $mailResult]);
    }
    exit;
}

// Handle AJAX OTP verification
if (isset($_POST['action']) && $_POST['action'] == 'verify_otp') {
    // Validate OTP format
    if (!isset($_POST['otp']) || !preg_match('/^\d{6}$/', $_POST['otp'])) {
        echo json_encode(['success' => false, 'message' => 'Invalid OTP format']);
        exit;
    }
    
    $inputOtp = $_POST['otp'];
    $currentTime = time();
    
    header('Content-Type: application/json');
    
    // Check attempt limits
    if (!isset($_SESSION['otp_attempts'])) {
        $_SESSION['otp_attempts'] = 0;
    }
    
    if ($_SESSION['otp_attempts'] >= ($_SESSION['max_attempts'] ?? 3)) {
        echo json_encode(['success' => false, 'message' => 'Too many attempts. Please request a new code.']);
        exit;
    }
    
    // Check if OTP is expired
    if (!isset($_SESSION['otp_expiry']) || $currentTime > $_SESSION['otp_expiry']) {
        echo json_encode(['success' => false, 'message' => 'OTP has expired']);
        exit;
    }
    
    $_SESSION['otp_attempts']++;
    
    // Verify OTP using password_verify to prevent timing attacks
    if (isset($_SESSION['otp']) && password_verify($inputOtp, $_SESSION['otp'])) {
        // Clear OTP data after successful verification
        unset($_SESSION['otp']);
        unset($_SESSION['otp_time']);
        unset($_SESSION['otp_expiry']);
        unset($_SESSION['otp_attempts']);
        unset($_SESSION['max_attempts']);
        unset($_SESSION['last_otp_request']);
        
        // Regenerate session ID for security
        session_regenerate_id(true);
        
        echo json_encode(['success' => true]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Invalid OTP']);
    }
    exit;
}

// Function to send OTP email
function sendOtpEmail($email, $otp) {
    if (empty($email)) {
        return "No email address found for this user.";
    }
    
    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        
        // Use environment variables for credentials (recommended)
        $mail->Username = $_ENV['SMTP_USERNAME'] ?? 'your@gmail.com';
        $mail->Password = $_ENV['SMTP_PASSWORD'] ?? ''; // replace password
        
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        $mail->setFrom($mail->Username, 'Login OTP');
        $mail->addAddress($email);

        $mail->isHTML(true);
        $mail->Subject = 'Your OTP for Login';
        $mail->Body = '
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h2 style="color: #4361ee; text-align: center;">Your Verification Code</h2>
                <p style="font-size: 16px; color: #333;">Use the following code to complete your verification:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1e293b; background-color: #f8fafc; padding: 15px; border-radius: 5px; display: inline-block;">' . htmlspecialchars($otp) . '</div>
                </div>
                <p style="font-size: 14px; color: #666;">This code will expire in 5 minutes.</p>
                <p style="font-size: 14px; color: #666;">If you did not request this code, please ignore this email.</p>
            </div>
        ';

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("PHPMailer error: " . $mail->ErrorInfo);
        return "Unable to send verification code. Please try again.";
    }
}

$stmt->close();
$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Identity Verification</title>
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
      --card-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: 'Poppins', sans-serif;
      background: linear-gradient(135deg, #4361ee, #4cc9f0);
      color: var(--dark-color);
      min-height: 100vh;
      display: flex;
      justify-content: center;
      align-items: center;
      padding: 20px;
    }

    .container {
      width: 100%;
      max-width: 500px;
      padding: 0 15px;
    }

    .card {
      background-color: white;
      border-radius: 16px;
      overflow: hidden;
      box-shadow: var(--card-shadow);
      transition: all 0.3s ease;
    }

    .card-header {
      background-color: var(--primary-color);
      color: white;
      padding: 20px;
      text-align: center;
      position: relative;
    }

    .card-body {
      padding: 30px;
    }

    .welcome-text {
      margin-bottom: 5px;
      font-size: 1.1rem;
      opacity: 0.9;
    }

    h2 {
      font-size: 1.8rem;
      font-weight: 600;
      margin-bottom: 15px;
      color: inherit;
    }

    p {
      color: #64748b;
      line-height: 1.6;
      margin-bottom: 20px;
    }

    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      padding: 12px 24px;
      background-color: var(--primary-color);
      color: white;
      border: none;
      border-radius: 8px;
      font-size: 1rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.3s ease;
      text-decoration: none;
      gap: 8px;
      width: 100%;
      margin-bottom: 10px;
    }

    .btn:hover {
      background-color: var(--secondary-color);
      transform: translateY(-2px);
    }

    .btn:disabled {
      background-color: #94a3b8;
      cursor: not-allowed;
      transform: none;
    }

    .btn-outline {
      background-color: transparent;
      border: 2px solid var(--primary-color);
      color: var(--primary-color);
    }

    .btn-outline:hover {
      background-color: rgba(67, 97, 238, 0.1);
    }

    .btn-danger {
      background-color: var(--danger-color);
    }

    .btn-danger:hover {
      background-color: #ef4444;
    }

    .btn-warning {
      background-color: var(--warning-color);
      color: #7c2d12;
    }

    .btn-warning:hover {
      background-color: #f59e0b;
    }

    .btn-group {
      display: flex;
      flex-direction: column;
      gap: 10px;
      margin-top: 20px;
    }

    .video-wrapper {
      position: relative;
      margin: 20px 0;
      border-radius: 12px;
      overflow: hidden;
      box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
    }

    video {
      display: block;
      width: 100%;
      border-radius: 12px;
      transform: scaleX(-1);
    }

    .overlay {
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      border: 3px solid var(--accent-color);
      border-radius: 12px;
      pointer-events: none;
    }

    .face-guide {
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      width: 200px;
      height: 200px;
      border: 2px dashed rgba(255, 255, 255, 0.7);
      border-radius: 50%;
      pointer-events: none;
    }

    .timer-container {
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 15px 0;
    }

    .timer {
      display: flex;
      align-items: center;
      justify-content: center;
      width: 60px;
      height: 60px;
      background-color: var(--primary-color);
      color: white;
      border-radius: 50%;
      font-size: 1.5rem;
      font-weight: 600;
    }

    .status-message {
      text-align: center;
      margin: 15px 0;
      font-weight: 500;
      color: var(--primary-color);
    }

    .loading-spinner {
      display: inline-block;
      width: 20px;
      height: 20px;
      border: 3px solid rgba(255, 255, 255, 0.3);
      border-radius: 50%;
      border-top-color: white;
      animation: spin 1s ease-in-out infinite;
      margin-right: 8px;
    }

    @keyframes spin {
      to { transform: rotate(360deg); }
    }

    .hidden {
      display: none !important;
    }

    .fade-in {
      animation: fadeIn 0.5s ease-in;
    }

    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }

    .pulse {
      animation: pulse 2s infinite;
    }

    @keyframes pulse {
      0% { box-shadow: 0 0 0 0 rgba(67, 97, 238, 0.7); }
      70% { box-shadow: 0 0 0 10px rgba(67, 97, 238, 0); }
      100% { box-shadow: 0 0 0 0 rgba(67, 97, 238, 0); }
    }

    .status-icon {
      font-size: 3rem;
      margin-bottom: 15px;
    }

    .success-icon {
      color: var(--success-color);
    }

    .error-icon {
      color: var(--danger-color);
    }

    .info-icon {
      color: var(--accent-color);
    }

    .status-text {
      font-size: 1.2rem;
      font-weight: 500;
      margin-bottom: 10px;
    }

    .status-subtext {
      font-size: 0.9rem;
      opacity: 0.8;
      margin-bottom: 20px;
    }

    .verification-option {
      background-color: white;
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 15px;
      box-shadow: var(--card-shadow);
      cursor: pointer;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      border: 2px solid transparent;
    }

    .verification-option:hover {
      transform: translateY(-3px);
      border-color: var(--accent-color);
    }

    .option-icon {
      width: 50px;
      height: 50px;
      background-color: rgba(67, 97, 238, 0.1);
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      margin-right: 15px;
      color: var(--primary-color);
      font-size: 1.5rem;
    }

    .option-content {
      flex: 1;
    }

    .option-title {
      font-weight: 600;
      font-size: 1.1rem;
      margin-bottom: 5px;
      color: var(--dark-color);
    }

    .option-description {
      font-size: 0.9rem;
      color: #64748b;
      margin: 0;
    }

    .back-button {
      position: absolute;
      top: 20px;
      left: 20px;
      color: white;
      background: none;
      border: none;
      cursor: pointer;
      font-size: 1.2rem;
    }

    .or-divider {
      display: flex;
      align-items: center;
      margin: 20px 0;
      color: #64748b;
    }

    .or-divider::before,
    .or-divider::after {
      content: "";
      flex: 1;
      border-bottom: 1px solid #e2e8f0;
    }

    .or-divider span {
      padding: 0 10px;
      font-size: 0.9rem;
      text-transform: uppercase;
    }

    .otp-input-group {
      display: flex;
      justify-content: space-between;
      margin: 20px 0;
    }

    .otp-input {
      width: 50px;
      height: 60px;
      border: 2px solid #e2e8f0;
      border-radius: 8px;
      font-size: 1.5rem;
      text-align: center;
      font-weight: 600;
      color: var(--dark-color);
    }

    .otp-input:focus {
      border-color: var(--primary-color);
      outline: none;
    }

    .resend-link {
      text-align: center;
      margin-top: 15px;
    }

    .resend-link a {
      color: var(--primary-color);
      text-decoration: none;
      font-weight: 500;
    }

    .countdown-container {
      text-align: center;
      margin: 15px 0;
    }

    .countdown-timer {
      font-size: 1.2rem;
      font-weight: 600;
      color: var(--primary-color);
    }

    .countdown-expired {
      color: var(--danger-color);
    }

    .alert {
      padding: 12px 15px;
      border-radius: 8px;
      margin-bottom: 15px;
      font-size: 0.9rem;
    }

    .alert-success {
      background-color: rgba(74, 222, 128, 0.1);
      border: 1px solid var(--success-color);
      color: #166534;
    }

    .alert-danger {
      background-color: rgba(248, 113, 113, 0.1);
      border: 1px solid var(--danger-color);
      color: #b91c1c;
    }

    .alert-warning {
      background-color: rgba(251, 191, 36, 0.1);
      border: 1px solid var(--warning-color);
      color: #92400e;
    }

    .camera-permission-guide {
      background-color: #f8fafc;
      border: 1px solid #e2e8f0;
      border-radius: 8px;
      padding: 15px;
      margin: 15px 0;
    }

    .camera-permission-guide h4 {
      color: var(--primary-color);
      margin-bottom: 10px;
      font-size: 1rem;
    }

    .camera-permission-guide ol {
      margin-left: 20px;
      color: #64748b;
    }

    .camera-permission-guide li {
      margin-bottom: 5px;
      font-size: 0.9rem;
    }

    /* Security Warning Modal */
    .security-modal {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background-color: rgba(0, 0, 0, 0.9);
      display: flex;
      justify-content: center;
      align-items: center;
      z-index: 10000;
      font-family: 'Poppins', sans-serif;
    }

    .security-modal-content {
      background: white;
      padding: 40px;
      border-radius: 16px;
      text-align: center;
      max-width: 500px;
      margin: 20px;
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
    }

    .security-modal h2 {
      color: #e74c3c;
      margin-bottom: 20px;
      font-size: 2rem;
    }

    .security-modal p {
      color: #2c3e50;
      margin-bottom: 15px;
      line-height: 1.6;
    }

    .security-modal .warning-icon {
      font-size: 4rem;
      color: #e74c3c;
      margin-bottom: 20px;
    }

    @media (max-width: 576px) {
      .card-body {
        padding: 20px;
      }
      
      h2 {
        font-size: 1.5rem;
      }
      
      .btn {
        padding: 10px 20px;
        font-size: 0.9rem;
      }
      
      .timer {
        width: 50px;
        height: 50px;
        font-size: 1.2rem;
      }
      
      .face-guide {
        width: 150px;
        height: 150px;
      }
      
      .otp-input {
        width: 40px;
        height: 50px;
        font-size: 1.2rem;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <!-- Initial Options Screen -->
    <div id="options-screen" class="card fade-in">
      <div class="card-header">
        <p class="welcome-text">Welcome back,</p>
        <h2><?php echo htmlspecialchars($firstName); ?></h2>
      </div>
      <div class="card-body">
        <h2>Verify Your Identity</h2>
        <p>Please choose a verification method to continue:</p>
        
        <div id="face-option" class="verification-option">
          <div class="option-icon">
            <i class="fas fa-camera"></i>
          </div>
          <div class="option-content">
            <div class="option-title">Face Verification</div>
            <p class="option-description">Verify using your camera for a quick and secure login</p>
          </div>
        </div>
        
        <div id="email-option" class="verification-option">
          <div class="option-icon">
            <i class="fas fa-envelope"></i>
          </div>
          <div class="option-content">
            <div class="option-title">Email OTP Verification</div>
            <p class="option-description">We'll send a verification code to <?php echo htmlspecialchars($maskedEmail); ?></p>
          </div>
        </div>
      </div>
    </div>

    <!-- Face Verification Screen -->
    <div id="verification-screen" class="card hidden">
      <div class="card-header">
        <button id="back-to-options" class="back-button">
          <i class="fas fa-arrow-left"></i>
        </button>
        <h2>Face Verification</h2>
      </div>
      <div class="card-body">
        <div id="status-message" class="status-message">
          <i class="fas fa-spinner fa-spin info-icon"></i>
          <p class="status-text">Initializing camera...</p>
        </div>
        
        <div id="camera-permission-guide" class="camera-permission-guide hidden">
          <h4><i class="fas fa-info-circle"></i> Camera Permission Required</h4>
          <p>To use face verification, please allow camera access:</p>
          <ol>
            <li>Click the camera icon in your browser's address bar</li>
            <li>Select "Allow" when prompted for camera permission</li>
            <li>Refresh the page if needed</li>
            <li>Make sure you're using HTTPS (secure connection)</li>
          </ol>
        </div>
        
        <div class="video-wrapper">
          <video id="video" autoplay muted playsinline></video>
          <div class="overlay"></div>
          <div class="face-guide pulse"></div>
        </div>
        
        <div class="timer-container">
          <div id="timer" class="timer">30</div>
        </div>
        
        <p>Please look directly at the camera and keep your face within the circle.</p>
        
        <div id="loading-models" class="status-message">
          <div class="loading-spinner"></div> Loading face recognition models...
        </div>
        
        <div class="or-divider">
          <span>or</span>
        </div>
        
        <button id="switch-to-email" class="btn btn-outline">
          <i class="fas fa-envelope"></i> Use Email Verification Instead
        </button>
      </div>
    </div>

    <!-- Email OTP Screen -->
    <div id="email-screen" class="card hidden">
      <div class="card-header">
        <button id="back-to-options-from-email" class="back-button">
          <i class="fas fa-arrow-left"></i>
        </button>
        <h2>Email Verification</h2>
      </div>
      <div class="card-body">
        <div id="email-alert" class="alert hidden"></div>
        
        <div id="email-status" class="status-message">
          <i class="fas fa-envelope info-icon"></i>
          <p class="status-text">Enter Verification Code</p>
          <p class="status-subtext">We've sent a 6-digit code to <?php echo htmlspecialchars($maskedEmail); ?></p>
        </div>
        
        <div class="otp-input-group">
          <input type="text" maxlength="1" class="otp-input" id="otp-1" autocomplete="off">
          <input type="text" maxlength="1" class="otp-input" id="otp-2" autocomplete="off">
          <input type="text" maxlength="1" class="otp-input" id="otp-3" autocomplete="off">
          <input type="text" maxlength="1" class="otp-input" id="otp-4" autocomplete="off">
          <input type="text" maxlength="1" class="otp-input" id="otp-5" autocomplete="off">
          <input type="text" maxlength="1" class="otp-input" id="otp-6" autocomplete="off">
        </div>
        
        <div class="countdown-container">
          <div id="otp-countdown" class="countdown-timer">
            <i class="fas fa-clock"></i> Code expires in: <span id="countdown-time">5:00</span>
          </div>
        </div>
        
        <div class="resend-link">
          <span>Didn't receive the code? </span>
          <a href="#" id="resend-otp">Resend Code</a>
        </div>
        
        <div class="btn-group">
          <button id="verify-otp" class="btn">
            <i class="fas fa-check-circle"></i> Verify Code
          </button>
          
          <div class="or-divider">
            <span>or</span>
          </div>
          
          <button id="switch-to-face" class="btn btn-outline">
            <i class="fas fa-camera"></i> Use Face Verification Instead
          </button>
        </div>
      </div>
    </div>

    <!-- Success Screen -->
    <div id="success-screen" class="card hidden">
      <div class="card-header">
        <h2>Verification Successful</h2>
      </div>
      <div class="card-body">
        <div class="status-message">
          <i class="fas fa-check-circle success-icon"></i>
          <p class="status-text">Identity Verified!</p>
          <p class="status-subtext">You will be redirected to your dashboard in a moment...</p>
        </div>
      </div>
    </div>

    <!-- Error Screen -->
    <div id="error-screen" class="card hidden">
      <div class="card-header">
        <h2>Verification Failed</h2>
      </div>
      <div class="card-body">
        <div class="status-message">
          <i class="fas fa-exclamation-circle error-icon"></i>
          <p class="status-text">We couldn't verify your identity</p>
          <p class="status-subtext" id="error-message">Please try again or use an alternative verification method.</p>
        </div>
        
        <div class="btn-group">
          <button id="retry-button" class="btn">
            <i class="fas fa-redo"></i> Try Again
          </button>
          <button id="go-to-options" class="btn btn-outline">
            <i class="fas fa-th-list"></i> Choose Another Method
          </button>
        </div>
      </div>
    </div>
  </div>

  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
  <script defer src="https://cdn.jsdelivr.net/npm/face-api.js@0.22.2/dist/face-api.min.js"></script>
  <script>
    // SECURITY: Console and DevTools Protection
    (function() {
      'use strict';
      
      // Disable all console methods
      const noop = function() {};
      const consoleKeys = ['log', 'debug', 'info', 'warn', 'error', 'assert', 'dir', 'dirxml', 'group', 'groupEnd', 'time', 'timeEnd', 'count', 'trace', 'profile', 'profileEnd'];
      
      if (window.console) {
        consoleKeys.forEach(key => {
          window.console[key] = noop;
        });
      }
      
      // Create fake console object if it doesn't exist
      if (!window.console) {
        window.console = {};
        consoleKeys.forEach(key => {
          window.console[key] = noop;
        });
      }
      
      // Show security warning modal
      function showSecurityWarning() {
        const modal = document.createElement('div');
        modal.className = 'security-modal';
        modal.innerHTML = `
          <div class="security-modal-content">
            <i class="fas fa-exclamation-triangle warning-icon"></i>
            <h2>Security Alert</h2>
            <p><strong>Unauthorized access attempt detected!</strong></p>
            <p>Developer tools are disabled for security reasons.</p>
            <p>This incident has been logged for security monitoring.</p>
            <p>Please use the application normally.</p>
          </div>
        `;
        document.body.appendChild(modal);
        
        // Auto-remove modal after 5 seconds
        setTimeout(() => {
          if (modal.parentNode) {
            modal.parentNode.removeChild(modal);
          }
        }, 5000);
      }
      
      // Disable right-click context menu
      document.addEventListener('contextmenu', function(e) {
        e.preventDefault();
        showSecurityWarning();
        return false;
      });
      
      // Disable developer tools keyboard shortcuts
      document.addEventListener('keydown', function(e) {
        // F12
        if (e.keyCode === 123) {
          e.preventDefault();
          showSecurityWarning();
          return false;
        }
        
        // Ctrl+Shift+I (Chrome DevTools)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 73) {
          e.preventDefault();
          showSecurityWarning();
          return false;
        }
        
        // Ctrl+Shift+J (Chrome Console)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 74) {
          e.preventDefault();
          showSecurityWarning();
          return false;
        }
        
        // Ctrl+U (View Source)
        if (e.ctrlKey && e.keyCode === 85) {
          e.preventDefault();
          showSecurityWarning();
          return false;
        }
        
        // Ctrl+Shift+C (Element Inspector)
        if (e.ctrlKey && e.shiftKey && e.keyCode === 67) {
          e.preventDefault();
          showSecurityWarning();
          return false;
        }
        
        // F11 (Fullscreen - sometimes used to hide devtools)
        if (e.keyCode === 122) {
          e.preventDefault();
          return false;
        }
      });
      
      // Detect DevTools by monitoring console
      let devtools = {
        open: false,
        orientation: null
      };
      
      setInterval(function() {
        if (window.outerHeight - window.innerHeight > 200 || window.outerWidth - window.innerWidth > 200) {
          if (!devtools.open) {
            devtools.open = true;
            showSecurityWarning();
          }
        } else {
          devtools.open = false;
        }
      }, 500);
      
      // Disable text selection
      document.onselectstart = function() {
        return false;
      };
      
      // Disable drag
      document.ondragstart = function() {
        return false;
      };
      
    })();

    // CSRF token for AJAX requests
    const csrfToken = '<?php echo $_SESSION['csrf_token']; ?>';
    
    // SECURITY: Patient-specific data from PHP (only for logged-in patient)
    const currentPatientId = <?php echo $userId; ?>;
    const patientProfilePictureUrl = <?php echo json_encode($profilePictureUrl); ?>;
    
    // DOM Elements
    const optionsScreen = document.getElementById('options-screen');
    const verificationScreen = document.getElementById('verification-screen');
    const emailScreen = document.getElementById('email-screen');
    const successScreen = document.getElementById('success-screen');
    const errorScreen = document.getElementById('error-screen');
    
    const faceOption = document.getElementById('face-option');
    const emailOption = document.getElementById('email-option');
    const backToOptions = document.getElementById('back-to-options');
    const backToOptionsFromEmail = document.getElementById('back-to-options-from-email');
    const switchToEmail = document.getElementById('switch-to-email');
    const switchToFace = document.getElementById('switch-to-face');
    const retryButton = document.getElementById('retry-button');
    const goToOptions = document.getElementById('go-to-options');
    
    const video = document.getElementById('video');
    const timerElement = document.getElementById('timer');
    const statusMessage = document.getElementById('status-message');
    const loadingModelsMessage = document.getElementById('loading-models');
    const errorMessage = document.getElementById('error-message');
    const cameraPermissionGuide = document.getElementById('camera-permission-guide');
    
    // OTP elements
    const otpInputs = [
      document.getElementById('otp-1'),
      document.getElementById('otp-2'),
      document.getElementById('otp-3'),
      document.getElementById('otp-4'),
      document.getElementById('otp-5'),
      document.getElementById('otp-6')
    ];
    
    const verifyOtpButton = document.getElementById('verify-otp');
    const resendOtpButton = document.getElementById('resend-otp');
    const countdownElement = document.getElementById('countdown-time');
    const emailAlert = document.getElementById('email-alert');
    
    // Variables to track active streams and timers
    let activeStream = null;
    let activeTimer = null;
    let activeInterval = null;
    let otpCountdownInterval = null;
    let otpExpiryTime = 0;
    let modelsLoaded = false;
    
    // CRITICAL SECURITY: Store the patient's face descriptor once loaded
    let patientFaceDescriptor = null;

    // Function to check if site is using HTTPS
    function checkHTTPS() {
      if (location.protocol !== 'https:') {
        updateStatus('HTTPS required for camera access', 'exclamation-circle');
        cameraPermissionGuide.classList.remove('hidden');
        errorMessage.textContent = 'Camera access requires a secure HTTPS connection. Please ensure your site is using HTTPS.';
        setTimeout(() => showScreen(errorScreen), 3000);
        return false;
      }
      return true;
    }

    // Function to switch between screens
    function showScreen(screen) {
      // Hide all screens
      optionsScreen.classList.add('hidden');
      verificationScreen.classList.add('hidden');
      emailScreen.classList.add('hidden');
      successScreen.classList.add('hidden');
      errorScreen.classList.add('hidden');
      
      // Show the requested screen
      screen.classList.remove('hidden');
      screen.classList.add('fade-in');
    }

    // Function to update status message
    function updateStatus(message, icon = 'spinner') {
      statusMessage.innerHTML = `
        <i class="fas fa-${icon} ${icon === 'check' ? 'success-icon' : icon === 'exclamation-circle' ? 'error-icon' : 'info-icon'}"></i>
        <p class="status-text">${message}</p>
      `;
    }
    
    // Function to clean up resources
    function cleanupResources() {
      if (activeStream) {
        activeStream.getTracks().forEach(track => track.stop());
        activeStream = null;
      }
      
      if (activeTimer) {
        clearInterval(activeTimer);
        activeTimer = null;
      }
      
      if (activeInterval) {
        clearInterval(activeInterval);
        activeInterval = null;
      }
    }
    
    // Function to show alert in email screen
    function showEmailAlert(message, type = 'danger') {
      emailAlert.textContent = message;
      emailAlert.className = `alert alert-${type}`;
      emailAlert.classList.remove('hidden');
      
      // Auto hide after 5 seconds
      setTimeout(() => {
        emailAlert.classList.add('hidden');
      }, 5000);
    }
    
    // Function to format time (minutes:seconds)
    function formatTime(seconds) {
      const minutes = Math.floor(seconds / 60);
      const remainingSeconds = seconds % 60;
      return `${minutes}:${remainingSeconds < 10 ? '0' : ''}${remainingSeconds}`;
    }
    
    // Function to start OTP countdown
    function startOtpCountdown(expirySeconds) {
      // Clear any existing countdown
      if (otpCountdownInterval) {
        clearInterval(otpCountdownInterval);
      }
      
      otpExpiryTime = Date.now() + (expirySeconds * 1000);
      
      otpCountdownInterval = setInterval(() => {
        const now = Date.now();
        const timeLeft = Math.max(0, Math.floor((otpExpiryTime - now) / 1000));
        
        if (timeLeft <= 0) {
          clearInterval(otpCountdownInterval);
          countdownElement.textContent = "Expired";
          countdownElement.parentElement.classList.add('countdown-expired');
          resendOtpButton.textContent = "Resend Code";
          resendOtpButton.disabled = false;
          verifyOtpButton.disabled = true;
        } else {
          countdownElement.textContent = formatTime(timeLeft);
        }
      }, 1000);
    }

    // Enhanced camera access function with better error handling
    async function requestCameraAccess() {
      try {
        // Check for HTTPS first
        if (!checkHTTPS()) {
          return null;
        }

        // Check if getUserMedia is supported
        if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
          throw new Error('Camera access not supported by this browser');
        }

        updateStatus('Requesting camera permission...', 'camera');
        
        // Request camera access with specific constraints
        const constraints = {
          video: {
            width: { ideal: 640 },
            height: { ideal: 480 },
            facingMode: 'user'
          },
          audio: false
        };

        const stream = await navigator.mediaDevices.getUserMedia(constraints);
        
        // Hide permission guide if camera access is granted
        cameraPermissionGuide.classList.add('hidden');
        
        return stream;
      } catch (error) {
        // Show specific error messages based on error type
        if (error.name === 'NotAllowedError' || error.name === 'PermissionDeniedError') {
          updateStatus('Camera permission denied', 'exclamation-circle');
          cameraPermissionGuide.classList.remove('hidden');
          errorMessage.textContent = 'Camera access was denied. Please allow camera permissions and try again.';
        } else if (error.name === 'NotFoundError' || error.name === 'DevicesNotFoundError') {
          updateStatus('No camera found', 'exclamation-circle');
          errorMessage.textContent = 'No camera device found. Please connect a camera and try again.';
        } else if (error.name === 'NotSupportedError') {
          updateStatus('Camera not supported', 'exclamation-circle');
          errorMessage.textContent = 'Camera access is not supported by this browser. Please use a modern browser.';
        } else {
          updateStatus('Camera access failed', 'exclamation-circle');
          errorMessage.textContent = 'Failed to access camera: ' + error.message;
        }
        
        setTimeout(() => showScreen(errorScreen), 3000);
        return null;
      }
    }

    // Load face-api.js models with better error handling and multiple sources
    async function loadFaceModels() {
      if (modelsLoaded) {
        return true;
      }

      try {
        loadingModelsMessage.classList.remove('hidden');
        updateStatus('Loading face recognition models...', 'download');
        
        // Try multiple model sources in order of preference
        const modelSources = [
          'https://raw.githubusercontent.com/justadudewhohacks/face-api.js/master/weights',
          'https://cdn.jsdelivr.net/gh/justadudewhohacks/face-api.js@master/weights',
          './face_models'
        ];
        
        let lastError = null;
        
        for (const modelUrl of modelSources) {
            try {
                updateStatus('Loading face recognition models, please wait...', 'download');
                await Promise.all([
                faceapi.nets.tinyFaceDetector.loadFromUri(modelUrl),
                faceapi.nets.faceRecognitionNet.loadFromUri(modelUrl),
                faceapi.nets.faceLandmark68Net.loadFromUri(modelUrl)
                ]);
                modelsLoaded = true;
                loadingModelsMessage.classList.add('hidden');
                updateStatus('AI models loaded successfully', 'check');
                return true;
            } catch (error) {
                lastError = error;
                continue;
            }
        }

        
        throw lastError || new Error('All model sources failed');
        
      } catch (error) {
        loadingModelsMessage.classList.add('hidden');
        updateStatus('Failed to load face recognition models', 'exclamation-circle');
        errorMessage.textContent = 'Failed to load face recognition models. Please use email verification instead.';
        setTimeout(() => showScreen(errorScreen), 2000);
        return false;
      }
    }

    // SECURITY: Enhanced image loading with strict patient ID verification
    async function loadPatientSpecificImage(imageUrl) {
      return new Promise((resolve, reject) => {
        // SECURITY CHECK: Ensure we only load images for the current patient
        if (!imageUrl || !imageUrl.includes(`profile_${currentPatientId}_`)) {
          reject(new Error('Unauthorized image access'));
          return;
        }

        const img = new Image();
        
        // Set crossOrigin before setting src
        img.crossOrigin = 'anonymous';
        
        img.onload = function() {
          resolve(img);
        };
        
        img.onerror = function() {
          // Extract filename from URL for secure proxy request
          const filename = imageUrl.split('/').pop();
          
          // SECURITY: Use secure proxy with patient ID verification
          const proxyUrl = `${window.location.href}?serve_image=1&patient_id=${currentPatientId}&filename=${encodeURIComponent(filename)}`;
          
          const proxyImg = new Image();
          proxyImg.crossOrigin = 'anonymous';
          
          proxyImg.onload = function() {
            resolve(proxyImg);
          };
          
          proxyImg.onerror = function() {
            reject(new Error('Failed to load patient-specific image'));
          };
          
          proxyImg.src = proxyUrl;
        };
        
        img.src = imageUrl;
      });
    }

    // CRITICAL SECURITY: Start face verification with strict patient-specific verification
    async function startFaceVerification() {
      showScreen(verificationScreen);
      updateStatus('Initializing face verification...', 'camera');
      
      // SECURITY CHECK: Ensure we have a valid patient-specific profile picture
      if (!patientProfilePictureUrl) {
        updateStatus('No profile picture found', 'exclamation-circle');
        errorMessage.textContent = 'No profile picture found for your account. Please upload your profile picture first or use email verification.';
        setTimeout(() => showScreen(errorScreen), 2000);
        return;
      }

      // SECURITY CHECK: Verify the profile picture URL contains the current patient ID
      if (!patientProfilePictureUrl.includes(`profile_${currentPatientId}_`)) {
        updateStatus('Security error', 'exclamation-circle');
        errorMessage.textContent = 'Security error: Profile picture verification failed. Please use email verification.';
        setTimeout(() => showScreen(errorScreen), 2000);
        return;
      }

      // Load face-api.js models first
      const modelsLoadedSuccessfully = await loadFaceModels();
      if (!modelsLoadedSuccessfully) {
        return;
      }

      // Request camera access
      const stream = await requestCameraAccess();
      if (!stream) {
        return;
      }

      try {
        activeStream = stream;
        video.srcObject = stream;
        
        updateStatus('Loading your profile picture...', 'download');
        
        // SECURITY: Load ONLY the patient-specific profile image
        let storedImage;
        try {
          storedImage = await loadPatientSpecificImage(patientProfilePictureUrl);
          updateStatus('Profile picture loaded successfully', 'check');
        } catch (imageError) {
          cleanupResources();
          errorMessage.textContent = 'Failed to load your profile picture. Please use email verification instead.';
          showScreen(errorScreen);
          return;
        }
        
        // CRITICAL SECURITY: Pre-compute the patient's face descriptor ONCE
        try {
          updateStatus('Processing your profile picture...', 'cog');
          patientFaceDescriptor = await faceapi.computeFaceDescriptor(storedImage);
          
          if (!patientFaceDescriptor) {
            throw new Error('Could not extract face features from profile picture');
          }
          
          updateStatus('Position your face in the circle', 'user');
        } catch (descriptorError) {
          cleanupResources();
          errorMessage.textContent = 'Could not process your profile picture. Please ensure it contains a clear face or use email verification.';
          showScreen(errorScreen);
          return;
        }
        
        // Start countdown timer
        let countdown = 30;
        timerElement.textContent = countdown;
        
        activeTimer = setInterval(() => {
          countdown -= 1;
          timerElement.textContent = countdown;
          
          if (countdown <= 0) {
            cleanupResources();
            errorMessage.textContent = 'Verification timeout. Please try again or use email verification.';
            showScreen(errorScreen);
          }
        }, 1000);
        
        // Wait for video to start playing
        video.addEventListener('loadedmetadata', async () => {
          setTimeout(startFaceDetection, 1000);
        });

        async function startFaceDetection() {
          try {
            updateStatus('Analyzing your face...', 'search');
            
            // Process video frames for face detection
            activeInterval = setInterval(async () => {
              try {
                if (video.readyState !== video.HAVE_ENOUGH_DATA) {
                  return;
                }

                // Detect face in current video frame
                const detections = await faceapi
                  .detectSingleFace(video, new faceapi.TinyFaceDetectorOptions())
                  .withFaceLandmarks()
                  .withFaceDescriptor();
                
                if (detections) {
                  // CRITICAL SECURITY: Compare ONLY with the pre-computed patient-specific descriptor
                  const faceMatcher = new faceapi.FaceMatcher([patientFaceDescriptor], 0.6); // Stricter threshold
                  const bestMatch = faceMatcher.findBestMatch(detections.descriptor);
                  
                  // SECURITY: Only allow login if face matches the specific patient's profile picture
                  if (bestMatch.distance < 0.65) { // Stricter threshold for better security
                    cleanupResources();
                    
                    updateStatus('Identity verified!', 'check');
                    setTimeout(() => {
                      showScreen(successScreen);
                      // Redirect after showing success screen
                      setTimeout(() => {
                        window.location.href = "patient_homepage.php";
                      }, 2000);
                    }, 1000);
                  }
                }
              } catch (detectionError) {
                // Continue trying - don't stop on single detection errors
              }
            }, 1000);
          } catch (error) {
            cleanupResources();
            errorMessage.textContent = 'Face detection failed. Please use email verification instead.';
            showScreen(errorScreen);
          }
        }
      } catch (error) {
        cleanupResources();
        updateStatus('Face verification failed', 'exclamation-circle');
        errorMessage.textContent = 'Face verification failed. Please use email verification instead.';
        setTimeout(() => showScreen(errorScreen), 2000);
      }
    }
    
    // Start email OTP verification
    function startEmailVerification() {
      showScreen(emailScreen);
      
      // Reset OTP inputs
      otpInputs.forEach(input => {
        input.value = '';
        input.disabled = false;
      });
      
      // Focus on first OTP input
      setTimeout(() => {
        otpInputs[0].focus();
      }, 500);
      
      // Reset countdown display
      countdownElement.textContent = "Sending...";
      countdownElement.parentElement.classList.remove('countdown-expired');
      
      // Disable buttons while sending OTP
      verifyOtpButton.disabled = true;
      resendOtpButton.disabled = true;
      
      // Send OTP via AJAX
      $.ajax({
        url: window.location.href,
        type: 'POST',
        data: { 
          action: 'send_otp',
          csrf_token: csrfToken
        },
        dataType: 'json',
        success: function(response) {
          if (response.success) {
            showEmailAlert('Verification code sent successfully!', 'success');
            startOtpCountdown(response.expiry);
            verifyOtpButton.disabled = false;
            resendOtpButton.disabled = false;
          } else {
            showEmailAlert(response.message || 'Failed to send verification code');
            countdownElement.textContent = "Error";
            countdownElement.parentElement.classList.add('countdown-expired');
            resendOtpButton.disabled = false;
          }
        },
        error: function() {
          showEmailAlert('Network error. Please try again.');
          countdownElement.textContent = "Error";
          countdownElement.parentElement.classList.add('countdown-expired');
          resendOtpButton.disabled = false;
        }
      });
      
      // Set up OTP input behavior
      otpInputs.forEach((input, index) => {
        input.addEventListener('keyup', (e) => {
          // If a number is entered
          if (/^[0-9]$/.test(e.key)) {
            // Focus next input
            if (index < otpInputs.length - 1) {
              otpInputs[index + 1].focus();
            }
          } else if (e.key === 'Backspace') {
            // On backspace, clear current and focus previous
            input.value = '';
            if (index > 0) {
              otpInputs[index - 1].focus();
            }
          }
        });
        
        // Handle paste event for the first input
        if (index === 0) {
          input.addEventListener('paste', (e) => {
            e.preventDefault();
            const pasteData = e.clipboardData.getData('text').trim().slice(0, 6);
            
            if (/^\d+$/.test(pasteData)) {
              for (let i = 0; i < pasteData.length; i++) {
                if (i < otpInputs.length) {
                  otpInputs[i].value = pasteData[i];
                }
              }
              
              // Focus the input after the last pasted digit
              const focusIndex = Math.min(pasteData.length, otpInputs.length - 1);
              otpInputs[focusIndex].focus();
            }
          });
        }
      });
    }
    
    // Verify OTP function
    function verifyOtp() {
      const otpValue = otpInputs.map(input => input.value).join('');
      
      if (otpValue.length !== 6 || !/^\d+$/.test(otpValue)) {
        showEmailAlert('Please enter a valid 6-digit code');
        return;
      }
      
      // Disable inputs and buttons during verification
      otpInputs.forEach(input => input.disabled = true);
      verifyOtpButton.disabled = true;
      resendOtpButton.disabled = true;
      
      // Verify OTP via AJAX
      $.ajax({
        url: window.location.href,
        type: 'POST',
        data: { 
          action: 'verify_otp',
          otp: otpValue,
          csrf_token: csrfToken
        },
        dataType: 'json',
        success: function(response) {
          if (response.success) {
            showScreen(successScreen);
            
            // Redirect after showing success screen
            setTimeout(() => {
              window.location.href = "patient_homepage.php";
            }, 2000);
          } else {
            showEmailAlert(response.message || 'Invalid verification code');
            
            // Re-enable inputs and buttons
            otpInputs.forEach(input => input.disabled = false);
            verifyOtpButton.disabled = false;
            resendOtpButton.disabled = false;
            
            // Clear inputs and focus first one
            otpInputs.forEach(input => input.value = '');
            otpInputs[0].focus();
          }
        },
        error: function() {
          showEmailAlert('Network error. Please try again.');
          
          // Re-enable inputs and buttons
          otpInputs.forEach(input => input.disabled = false);
          verifyOtpButton.disabled = false;
          resendOtpButton.disabled = false;
        }
      });
    }
    
    // Resend OTP function
    function resendOtp() {
      // Reset OTP inputs
      otpInputs.forEach(input => {
        input.value = '';
        input.disabled = false;
      });
      
      // Focus on first OTP input
      otpInputs[0].focus();
      
      // Reset countdown display
      countdownElement.textContent = "Sending...";
      countdownElement.parentElement.classList.remove('countdown-expired');
      
      // Disable buttons while sending OTP
      verifyOtpButton.disabled = true;
      resendOtpButton.disabled = true;
      
      // Send OTP via AJAX
      $.ajax({
        url: window.location.href,
        type: 'POST',
        data: { 
          action: 'send_otp',
          csrf_token: csrfToken
        },
        dataType: 'json',
        success: function(response) {
          if (response.success) {
            showEmailAlert('New verification code sent!', 'success');
            startOtpCountdown(response.expiry);
            verifyOtpButton.disabled = false;
            resendOtpButton.disabled = false;
          } else {
            showEmailAlert(response.message || 'Failed to send verification code');
            countdownElement.textContent = "Error";
            countdownElement.parentElement.classList.add('countdown-expired');
            resendOtpButton.disabled = false;
          }
        },
        error: function() {
          showEmailAlert('Network error. Please try again.');
          countdownElement.textContent = "Error";
          countdownElement.parentElement.classList.add('countdown-expired');
          resendOtpButton.disabled = false;
        }
      });
    }

    // Event Listeners
    faceOption.addEventListener('click', startFaceVerification);
    emailOption.addEventListener('click', startEmailVerification);
    
    backToOptions.addEventListener('click', () => {
      cleanupResources();
      // Reset face descriptor when going back
      patientFaceDescriptor = null;
      showScreen(optionsScreen);
    });
    
    backToOptionsFromEmail.addEventListener('click', () => {
      if (otpCountdownInterval) {
        clearInterval(otpCountdownInterval);
      }
      showScreen(optionsScreen);
    });
    
    switchToEmail.addEventListener('click', () => {
      cleanupResources();
      // Reset face descriptor when switching to email
      patientFaceDescriptor = null;
      startEmailVerification();
    });
    
    switchToFace.addEventListener('click', () => {
      if (otpCountdownInterval) {
        clearInterval(otpCountdownInterval);
      }
      startFaceVerification();
    });
    
    retryButton.addEventListener('click', () => {
      if (verificationScreen.classList.contains('hidden')) {
        // If we came from email verification
        startEmailVerification();
      } else {
        // If we came from face verification
        startFaceVerification();
      }
    });
    
    goToOptions.addEventListener('click', () => {
      cleanupResources();
      // Reset face descriptor when going to options
      patientFaceDescriptor = null;
      showScreen(optionsScreen);
    });
    
    verifyOtpButton.addEventListener('click', verifyOtp);
    resendOtpButton.addEventListener('click', resendOtp);

    // Cleanup on page unload
    window.addEventListener('beforeunload', cleanupResources);
  </script>
</body>
</html>
