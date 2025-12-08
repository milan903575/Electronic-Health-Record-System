<?php
// Security headers and configuration
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_strict_mode', 1);
ini_set('session.cookie_samesite', 'Strict');

// Start session with secure settings
session_start();

// Security Headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src \'self\' https://fonts.gstatic.com; img-src \'self\' data: https: blob:; connect-src \'self\' https://quickchart.io;');

// CSRF Token Validation
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Retrieve existing CSRF token from session
$csrf_token = isset($_SESSION['csrf_token']) ? $_SESSION['csrf_token'] : '';

// Include database connection
include '../connection.php';

// Enhanced session validation
if (!isset($_SESSION['user_id']) || 
    !isset($_SESSION['user_type']) || 
    $_SESSION['user_type'] != 'patient' ||
    !isset($_SESSION['csrf_token'])) {
    
    // Clear potentially compromised session
    session_destroy();
    header("Location: ../login.html");
    exit;
}

// Additional security: Check session timeout (30 minutes)
$timeout_duration = 1800; // 30 minutes
if (isset($_SESSION['last_activity']) && 
    (time() - $_SESSION['last_activity']) > $timeout_duration) {
    session_destroy();
    header("Location: ../login.html?timeout=1");
    exit;
}
$_SESSION['last_activity'] = time();

$patient_id = (int)$_SESSION['user_id'];

// Fetch patient data with prepared statement
$sql_patient = "SELECT * FROM patients WHERE id = ? LIMIT 1";
$stmt_patient = $conn->prepare($sql_patient);
if (!$stmt_patient) {
    die("Database error: " . $conn->error);
}

$stmt_patient->bind_param("i", $patient_id);
$stmt_patient->execute();
$result_patient = $stmt_patient->get_result();
$patient = $result_patient->fetch_assoc();
$stmt_patient->close();

// Check if patient exists
if (!$patient) {
    session_destroy();
    header("Location: ../login.html");
    exit;
}

// Calculate age safely
$age = 'N/A';
if (isset($patient['date_of_birth']) && !empty($patient['date_of_birth'])) {
    try {
        $dob_date = new DateTime($patient['date_of_birth']);
        $now = new DateTime();
        $age = $now->diff($dob_date)->y;
    } catch (Exception $e) {
        $age = 'N/A';
    }
}

// Set default profile picture with proper path validation
$profile_picture = 'uploads/images/default_profile.png';
if (isset($patient['profile_picture']) && !empty($patient['profile_picture'])) {
    $pic_path = htmlspecialchars($patient['profile_picture'], ENT_QUOTES, 'UTF-8');
    // Validate file path to prevent directory traversal
    if (strpos($pic_path, '..') === false && file_exists($pic_path)) {
        $profile_picture = $pic_path;
    }
}

// Handle profile picture upload with enhanced security
$upload_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['profile_picture'])) {
    
    // Validate CSRF token
    if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
        $upload_message = "Security error: Invalid request token.";
    } else {
        $target_dir = "uploads/images/";
        
        // Create directory if it doesn't exist
        if (!file_exists($target_dir)) {
            if (!mkdir($target_dir, 0755, true)) {
                $upload_message = "Error: Could not create upload directory.";
            }
        }
        
        if (empty($upload_message)) {
            $file_extension = strtolower(pathinfo($_FILES["profile_picture"]["name"], PATHINFO_EXTENSION));
            $new_filename = "profile_" . $patient_id . "_" . time() . "." . $file_extension;
            $target_file = $target_dir . $new_filename;
            
            // Enhanced file validation
            $allowed_types = array('jpg', 'jpeg', 'png');
            $max_file_size = 5000000; // 5MB
            
            // Check file size
            if ($_FILES["profile_picture"]["size"] > $max_file_size) {
                $upload_message = "Error: File size too large. Maximum size is 5MB.";
            }
            // Check file type
            elseif (!in_array($file_extension, $allowed_types)) {
                $upload_message = "Error: Only JPG, JPEG & PNG files are allowed.";
            }
            // Validate file is actually an image
            elseif (!getimagesize($_FILES["profile_picture"]["tmp_name"])) {
                $upload_message = "Error: File is not a valid image.";
            }
            // Check for upload errors
            elseif ($_FILES["profile_picture"]["error"] !== UPLOAD_ERR_OK) {
                $upload_message = "Error: File upload failed.";
            }
            else {
                // Move uploaded file
                if (move_uploaded_file($_FILES["profile_picture"]["tmp_name"], $target_file)) {
                    // Update database
                    $update_sql = "UPDATE patients SET profile_picture = ? WHERE id = ?";
                    $update_stmt = $conn->prepare($update_sql);
                    
                    if ($update_stmt) {
                        $update_stmt->bind_param("si", $target_file, $patient_id);
                        
                        if ($update_stmt->execute()) {
                            $profile_picture = $target_file;
                            $upload_message = "Profile picture updated successfully!";
                        } else {
                            $upload_message = "Error: Could not update database.";
                            // Remove uploaded file if database update fails
                            unlink($target_file);
                        }
                        $update_stmt->close();
                    } else {
                        $upload_message = "Error: Database preparation failed.";
                        unlink($target_file);
                    }
                } else {
                    $upload_message = "Error: Could not save uploaded file.";
                }
            }
        }
    }
}

$conn->close();

// Generate patient data for QR code with proper data sanitization
$patient_data = array(
    'name' => isset($patient['first_name']) && isset($patient['last_name']) ? 
        htmlspecialchars($patient['first_name'] . ' ' . $patient['last_name'], ENT_QUOTES, 'UTF-8') : 'N/A',
    'email' => isset($patient['email']) ? htmlspecialchars($patient['email'], ENT_QUOTES, 'UTF-8') : 'N/A',
    'age' => $age,
    'gender' => isset($patient['gender']) ? htmlspecialchars($patient['gender'], ENT_QUOTES, 'UTF-8') : 'N/A',
    'dob' => isset($patient['date_of_birth']) ? htmlspecialchars($patient['date_of_birth'], ENT_QUOTES, 'UTF-8') : 'N/A',
    'blood_group' => isset($patient['blood_group']) ? htmlspecialchars($patient['blood_group'], ENT_QUOTES, 'UTF-8') : 'N/A',
    'patient_id' => $patient_id
);

// Create QR code data
$qr_data = json_encode($patient_data, JSON_UNESCAPED_UNICODE);
$qr_code_url = "https://quickchart.io/qr?size=200x200&format=png&margin=1&qzone=1&text=" . urlencode($qr_data);
// Fallback QR code generation using different service
$qr_code_fallback = "https://api.qrserver.com/v1/create-qr-code/?size=200x200&format=png&data=" . urlencode($qr_data);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Patient Profile | MedFuture</title>
    
    <!-- Multiple Font Awesome CDN sources for reliability -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" integrity="sha512-iecdLmaskl7CVkqkXNQ/ZH/XLlvWZOJyj7Yy7tcenmpD1ypASozpmT/E0iPtmFIB46ZmdtAc9eNBvH0H/ZpiBw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
    
    <!-- Fallback Font Awesome -->
    <link rel="stylesheet" href="https://pro.fontawesome.com/releases/v5.10.0/css/all.css" integrity="sha384-AYmEC3Yw5cVb3ZcuHtOA93w35dYTsvhLPVnYs9eStHfGJvOvKxVfELGroGkvsg+p" crossorigin="anonymous"/>
    
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    
    <style>
        :root {
            --primary-color: #4361ee;
            --secondary-color: #3a0ca3;
            --accent-color: #4cc9f0;
            --text-primary: #2b2d42;
            --text-secondary: #6c757d;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --card-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            --border-radius: 16px;
            --transition-speed: 0.3s;
            --success-color: #28a745;
            --error-color: #dc3545;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Outfit', sans-serif;
            color: var(--text-primary);
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }
        
        /* Icon fallback styles - ensures icons are visible even if Font Awesome fails */
        .icon-fallback {
            display: inline-block;
            width: 1em;
            height: 1em;
            text-align: center;
            line-height: 1;
            font-weight: bold;
        }
        
        /* Specific icon fallbacks */
        .fa-camera:before, .icon-camera:before { content: "📷"; }
        .fa-user:before, .icon-user:before { content: "👤"; }
        .fa-envelope:before, .icon-envelope:before { content: "✉"; }
        .fa-venus-mars:before, .icon-gender:before { content: "⚥"; }
        .fa-calendar-alt:before, .icon-calendar:before { content: "📅"; }
        .fa-hourglass-half:before, .icon-age:before { content: "⏳"; }
        .fa-tint:before, .icon-blood:before { content: "🩸"; }
        .fa-user-md:before, .icon-patient:before { content: "👨‍⚕️"; }
        .fa-shield-alt:before, .icon-shield:before { content: "🛡"; }
        .fa-chevron-left:before, .icon-back:before { content: "←"; }
        .fa-upload:before, .icon-upload:before { content: "⬆"; }

        .profile-container {
            width: 100%;
            max-width: 900px;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            margin: 20px;
        }
        
        .profile-card {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--card-shadow);
            overflow: hidden;
            padding: 30px;
            position: relative;
            transition: transform var(--transition-speed), box-shadow var(--transition-speed);
        }
        
        .profile-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.15);
        }
        
        .profile-header {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-bottom: 30px;
            position: relative;
        }
        
        .profile-img-container {
            position: relative;
            width: 120px;
            height: 120px;
            margin-bottom: 15px;
        }
        
        .profile-img {
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: 50%;
            border: 4px solid var(--primary-color);
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            transition: all var(--transition-speed);
        }
        
        .upload-overlay {
            position: absolute;
            bottom: 0;
            right: 0;
            background: var(--primary-color);
            color: white;
            width: 35px;
            height: 35px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.2);
            transition: all var(--transition-speed);
            font-size: 14px;
        }
        
        .upload-overlay:hover {
            background: var(--secondary-color);
            transform: scale(1.1);
        }
        
        .profile-name {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--primary-color);
            margin-bottom: 5px;
            text-align: center;
        }
        
        .profile-badge {
            display: inline-flex;
            align-items: center;
            padding: 5px 12px;
            background: rgba(67, 97, 238, 0.1);
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 500;
            color: var(--primary-color);
            margin-bottom: 5px;
        }
        
        .badge-icon {
            margin-right: 6px;
            font-size: 12px;
        }
        
        .profile-details {
            display: grid;
            grid-template-columns: 1fr;
            gap: 15px;
        }
        
        .detail {
            display: flex;
            align-items: center;
            padding: 15px;
            background: rgba(245, 247, 250, 0.5);
            border-radius: 12px;
            transition: all var(--transition-speed);
        }
        
        .detail:hover {
            background: rgba(245, 247, 250, 0.8);
            transform: translateX(5px);
        }
        
        .detail-icon {
            display: flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            background: var(--primary-color);
            border-radius: 10px;
            margin-right: 15px;
            color: white;
            font-size: 16px;
            flex-shrink: 0;
        }
        
        .detail-content {
            flex-grow: 1;
        }
        
        .detail-label {
            font-size: 0.8rem;
            color: var(--text-secondary);
            font-weight: 500;
            margin-bottom: 3px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .detail-value {
            font-size: 1rem;
            font-weight: 600;
            color: var(--text-primary);
        }
        
        .qr-section {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 30px;
            background: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--card-shadow);
        }

        .qr-title {
            font-size: 1.3rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 20px;
            text-align: center;
        }
        
        .qr-description {
            font-size: 0.9rem;
            color: var(--text-secondary);
            text-align: center;
            margin-bottom: 25px;
            line-height: 1.5;
        }
        
        .qr-code {
            width: 200px;
            height: 200px;
            margin-bottom: 20px;
            border: 1px solid #eaeaea;
            border-radius: 10px;
            padding: 10px;
            background: white;
            object-fit: contain;
        }
        
        .qr-info {
            font-size: 0.85rem;
            color: var(--text-secondary);
            text-align: center;
            margin-top: 15px;
        }
        
        .button-wrapper {
            text-align: center;
            margin-top: 30px;
            grid-column: span 2;
        }
        
        .action-button {
            display: inline-flex;
            align-items: center;
            padding: 12px 30px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 30px;
            font-weight: 600;
            font-size: 0.95rem;
            cursor: pointer;
            transition: all var(--transition-speed);
            text-decoration: none;
            box-shadow: 0 5px 15px rgba(67, 97, 238, 0.3);
        }
        
        .action-button:hover {
            background: var(--secondary-color);
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(67, 97, 238, 0.4);
        }
        
        .action-button .icon {
            margin-right: 8px;
            font-size: 14px;
        }
        
        /* Upload form styling */
        .upload-form {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }
        
        .upload-form-content {
            background: white;
            padding: 30px;
            border-radius: 15px;
            width: 90%;
            max-width: 400px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        
        .upload-form-title {
            font-size: 1.3rem;
            font-weight: 600;
            margin-bottom: 20px;
            color: var(--primary-color);
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-primary);
        }
        
        .file-input-wrapper {
            position: relative;
            overflow: hidden;
            display: inline-block;
            cursor: pointer;
        }
        
        .file-input {
            position: absolute;
            font-size: 100px;
            opacity: 0;
            right: 0;
            top: 0;
            cursor: pointer;
        }
        
        .file-input-button {
            display: inline-flex;
            align-items: center;
            padding: 10px 15px;
            background: #f1f1f1;
            border: 1px solid #ddd;
            border-radius: 5px;
            font-size: 0.9rem;
            color: var(--text-primary);
            transition: all 0.3s;
            cursor: pointer;
        }
        
        .file-input-button:hover {
            background: #e9e9e9;
        }
        
        .file-input-button .icon {
            margin-right: 5px;
        }
        
        .selected-file {
            margin-top: 10px;
            font-size: 0.85rem;
            color: var(--text-secondary);
        }
        
        .form-buttons {
            display: flex;
            justify-content: flex-end;
            gap: 10px;
            margin-top: 20px;
        }
        
        .form-button {
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
        }
        
        .cancel-button {
            background: #f1f1f1;
            color: var(--text-primary);
        }
        
        .cancel-button:hover {
            background: #e1e1e1;
        }
        
        .submit-button {
            background: var(--primary-color);
            color: white;
        }
        
        .submit-button:hover {
            background: var(--secondary-color);
        }
        
        .upload-message {
            margin-top: 10px;
            padding: 10px;
            border-radius: 5px;
            font-size: 0.9rem;
            text-align: center;
        }
        
        .upload-success {
            background: rgba(40, 167, 69, 0.1);
            color: var(--success-color);
            border: 1px solid rgba(40, 167, 69, 0.2);
        }
        
        .upload-error {
            background: rgba(220, 53, 69, 0.1);
            color: var(--error-color);
            border: 1px solid rgba(220, 53, 69, 0.2);
        }
        
        /* Security indicator */
        .security-indicator {
            position: fixed;
            top: 10px;
            right: 10px;
            background: var(--success-color);
            color: white;
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.8rem;
            z-index: 1001;
            display: flex;
            align-items: center;
            gap: 5px;
        }
        
        /* Responsive styles */
        @media (max-width: 768px) {
            .profile-container {
                grid-template-columns: 1fr;
            }
            
            .button-wrapper {
                grid-column: span 1;
            }
            
            .profile-img-container {
                width: 100px;
                height: 100px;
            }
            
            .upload-overlay {
                width: 30px;
                height: 30px;
                font-size: 12px;
            }
        }
        
        /* Loading state for icons */
        .icon-loading {
            opacity: 0.5;
            animation: pulse 1.5s ease-in-out infinite;
        }
        
        @keyframes pulse {
            0% { opacity: 0.5; }
            50% { opacity: 1; }
            100% { opacity: 0.5; }
        }
    </style>
</head>
<body>
    <div class="security-indicator">
        <span class="fa fa-shield-alt icon-shield"></span>
        Secure Session
    </div>
    
    <div class="profile-container">
        <div class="profile-card">
            <div class="profile-header">
                <div class="profile-img-container">
                    <img class="profile-img" src="<?php echo htmlspecialchars($profile_picture, ENT_QUOTES, 'UTF-8'); ?>" alt="Profile Picture" onerror="this.src='uploads/images/default_profile.png'">
                    <div class="upload-overlay" id="upload-trigger">
                        <span class="fa fa-camera icon-camera"></span>
                    </div>
                </div>
                <h2 class="profile-name"><?php echo htmlspecialchars($patient['first_name'] . ' ' . $patient['last_name'], ENT_QUOTES, 'UTF-8'); ?></h2>
                <div class="profile-badge">
                    <span class="fa fa-user-md icon-patient badge-icon"></span>
                    Patient
                </div>
            </div>
            
            <div class="profile-details">
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-user icon-user"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Full Name</div>
                        <div class="detail-value"><?php echo htmlspecialchars($patient['first_name'] . ' ' . $patient['last_name'], ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-envelope icon-envelope"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Email</div>
                        <div class="detail-value"><?php echo htmlspecialchars($patient['email'], ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-venus-mars icon-gender"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Gender</div>
                        <div class="detail-value"><?php echo htmlspecialchars($patient['gender'], ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-calendar-alt icon-calendar"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Date of Birth</div>
                        <div class="detail-value"><?php echo htmlspecialchars($patient['date_of_birth'], ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-hourglass-half icon-age"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Age</div>
                        <div class="detail-value"><?php echo htmlspecialchars($age, ENT_QUOTES, 'UTF-8'); ?></div>
                    </div>
                </div>
                
                <div class="detail">
                    <div class="detail-icon">
                        <span class="fa fa-tint icon-blood"></span>
                    </div>
                    <div class="detail-content">
                        <div class="detail-label">Blood Group</div>
                        <div class="detail-value"><?php echo isset($patient['blood_group']) ? htmlspecialchars($patient['blood_group'], ENT_QUOTES, 'UTF-8') : 'N/A'; ?></div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="qr-section">
            <h3 class="qr-title">Patient QR Code</h3>
            <p class="qr-description">Scan this QR code to quickly share your medical information with healthcare providers.</p>
            <img class="qr-code" 
                 src="<?php echo htmlspecialchars($qr_code_url, ENT_QUOTES, 'UTF-8'); ?>" 
                 alt="Patient QR Code"
                 onerror="this.src='<?php echo htmlspecialchars($qr_code_fallback, ENT_QUOTES, 'UTF-8'); ?>'">
            <p class="qr-info">This QR code contains your basic profile information including name, email, age, gender, and date of birth.</p>
        </div>
        
        <div class="button-wrapper">
            <a href="patient_homepage.php" class="action-button">
                <span class="fa fa-chevron-left icon-back icon"></span>
                Back to Dashboard
            </a>
        </div>
    </div>
    
    <!-- Profile Picture Upload Form -->
    <div class="upload-form" id="upload-form">
        <div class="upload-form-content">
            <h3 class="upload-form-title">Update Profile Picture</h3>
            
            <?php if (!empty($upload_message)): ?>
                <div class="upload-message <?php echo strpos($upload_message, 'successfully') !== false ? 'upload-success' : 'upload-error'; ?>">
                    <?php echo htmlspecialchars($upload_message, ENT_QUOTES, 'UTF-8'); ?>
                </div>
            <?php endif; ?>
            
            <form action="" method="post" enctype="multipart/form-data">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($csrf_token, ENT_QUOTES, 'UTF-8'); ?>">
                
                <div class="form-group">
                    <label class="form-label">Select a new profile picture</label>
                    <div class="file-input-wrapper">
                        <button type="button" class="file-input-button">
                            <span class="fa fa-upload icon-upload icon"></span>
                            Choose File
                        </button>
                        <input type="file" name="profile_picture" id="profile_picture" class="file-input" accept="image/jpeg,image/png,image/jpg" required>
                    </div>
                    <div class="selected-file" id="selected-file">No file chosen</div>
                </div>
                
                <div class="form-buttons">
                    <button type="button" class="form-button cancel-button" id="cancel-upload">Cancel</button>
                    <button type="submit" class="form-button submit-button">Upload</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
        // Enhanced icon loading and fallback system
        document.addEventListener('DOMContentLoaded', function() {
            // Check if Font Awesome is loaded
            function checkFontAwesome() {
                const testElement = document.createElement('i');
                testElement.className = 'fa fa-user';
                testElement.style.position = 'absolute';
                testElement.style.left = '-9999px';
                document.body.appendChild(testElement);
                
                const computed = window.getComputedStyle(testElement, ':before');
                const fontFamily = computed.getPropertyValue('font-family');
                document.body.removeChild(testElement);
                
                return fontFamily.indexOf('FontAwesome') !== -1 || fontFamily.indexOf('Font Awesome') !== -1;
            }
            
            // Apply fallback classes if Font Awesome fails to load
            function applyIconFallbacks() {
                if (!checkFontAwesome()) {
                    console.warn('Font Awesome not loaded, applying fallbacks');
                    
                    // Replace FA classes with fallback classes
                    const iconMappings = {
                        'fa-camera': 'icon-camera',
                        'fa-user': 'icon-user',
                        'fa-envelope': 'icon-envelope',
                        'fa-venus-mars': 'icon-gender',
                        'fa-calendar-alt': 'icon-calendar',
                        'fa-hourglass-half': 'icon-age',
                        'fa-tint': 'icon-blood',
                        'fa-user-md': 'icon-patient',
                        'fa-shield-alt': 'icon-shield',
                        'fa-chevron-left': 'icon-back',
                        'fa-upload': 'icon-upload'
                    };
                    
                    Object.keys(iconMappings).forEach(faClass => {
                        const elements = document.querySelectorAll('.' + faClass);
                        elements.forEach(el => {
                            el.classList.add(iconMappings[faClass]);
                            el.classList.add('icon-fallback');
                        });
                    });
                }
            }
            
            // Apply fallbacks after a short delay to ensure CSS is loaded
            setTimeout(applyIconFallbacks, 100);
            
            // Profile picture upload functionality
            const uploadTrigger = document.getElementById('upload-trigger');
            const uploadForm = document.getElementById('upload-form');
            const cancelUpload = document.getElementById('cancel-upload');
            const fileInput = document.getElementById('profile_picture');
            const selectedFile = document.getElementById('selected-file');
            
            // Validate file types
            const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png'];
            const maxSize = 5 * 1024 * 1024; // 5MB
            
            if (uploadTrigger) {
                uploadTrigger.addEventListener('click', function() {
                    uploadForm.style.display = 'flex';
                });
            }
            
            if (cancelUpload) {
                cancelUpload.addEventListener('click', function() {
                    uploadForm.style.display = 'none';
                    fileInput.value = '';
                    selectedFile.textContent = 'No file chosen';
                });
            }
            
            if (fileInput) {
                fileInput.addEventListener('change', function() {
                    if (this.files && this.files[0]) {
                        const file = this.files[0];
                        
                        // Validate file type
                        if (!allowedTypes.includes(file.type)) {
                            alert('Please select a valid image file (JPG, JPEG, or PNG).');
                            this.value = '';
                            selectedFile.textContent = 'No file chosen';
                            return;
                        }
                        
                        // Validate file size
                        if (file.size > maxSize) {
                            alert('File size must be less than 5MB.');
                            this.value = '';
                            selectedFile.textContent = 'No file chosen';
                            return;
                        }
                        
                        selectedFile.textContent = file.name;
                    } else {
                        selectedFile.textContent = 'No file chosen';
                    }
                });
            }
            
            // Close modal when clicking outside the form
            if (uploadForm) {
                uploadForm.addEventListener('click', function(e) {
                    if (e.target === uploadForm) {
                        uploadForm.style.display = 'none';
                        fileInput.value = '';
                        selectedFile.textContent = 'No file chosen';
                    }
                });
            }
            
            // Auto-hide success/error message after 5 seconds
            const uploadMessage = document.querySelector('.upload-message');
            if (uploadMessage) {
                setTimeout(function() {
                    uploadMessage.style.opacity = '0';
                    setTimeout(function() {
                        uploadMessage.style.display = 'none';
                    }, 300);
                }, 5000);
            }
            
            // Session timeout warning
            let sessionTimeout = 1800000; // 30 minutes in milliseconds
            let warningShown = false;
            
            setTimeout(function() {
                if (!warningShown) {
                    warningShown = true;
                    if (confirm('Your session will expire in 5 minutes. Click OK to extend your session.')) {
                        // Refresh page to extend session
                        window.location.reload();
                    }
                }
            }, sessionTimeout - 300000); // Show warning 5 minutes before expiry
            
            // Retry icon loading if initial load fails
            window.addEventListener('load', function() {
                setTimeout(function() {
                    applyIconFallbacks();
                }, 500);
            });
        });
        
        // Additional fallback for very slow connections
        setTimeout(function() {
            const icons = document.querySelectorAll('[class*="fa-"]');
            icons.forEach(icon => {
                if (window.getComputedStyle(icon, ':before').content === 'none' || 
                    window.getComputedStyle(icon, ':before').content === '""') {
                    icon.classList.add('icon-fallback');
                }
            });
        }, 2000);
    </script>
</body>
</html>
