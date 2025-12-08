<?php
// Security Headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");

// Start session securely
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', 1);
ini_set('session.use_only_cookies', 1);
session_start();

include 'connection.php';

// Generate CSRF token if not exists
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// User authentication and role determination
$user_type = '';
$hospital_id = null;

if (isset($_SESSION['user_type']) && in_array($_SESSION['user_type'], ['patient', 'doctor', 'receptionist'])) {
    $user_type = $_SESSION['user_type'];
    $hospital_id = $_SESSION['hospital_id'] ?? null;
} elseif (isset($_SESSION['hospital_id'])) {
    $user_type = 'admin';
    $hospital_id = $_SESSION['hospital_id'];
} else {
    die('Unauthorized access. Please login first.');
}

// Only require hospital_id for non-patients
if (empty($user_type)) {
    die('Invalid session data. Please login again.');
}
if ($user_type !== 'patient' && empty($hospital_id)) {
    die('Invalid session data. Please login again.');
}

$message = '';
$error = '';

// Process form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $error = 'CSRF token validation failed. Please refresh the page and try again.';
    } else {
        try {
            // Sanitize and validate input
            $email = filter_var(trim($_POST['email'] ?? ''), FILTER_VALIDATE_EMAIL);
            $title = htmlspecialchars(trim($_POST['title'] ?? ''), ENT_QUOTES, 'UTF-8');
            $user_message = htmlspecialchars(trim($_POST['message'] ?? ''), ENT_QUOTES, 'UTF-8');

            // Validation
            if (!$email) {
                throw new Exception('Please enter a valid email address.');
            }
            if (empty($title) || strlen($title) < 5 || strlen($title) > 255) {
                throw new Exception('Title must be between 5 and 255 characters.');
            }
            if (empty($user_message) || strlen($user_message) < 10 || strlen($user_message) > 1000) {
                throw new Exception('Message must be between 10 and 1000 characters.');
            }

            // Handle file upload
            $attachment_path = null;
            if (isset($_FILES['attachment']) && $_FILES['attachment']['error'] === UPLOAD_ERR_OK) {
                $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
                $max_size = 5 * 1024 * 1024; // 5MB

                if (!in_array($_FILES['attachment']['type'], $allowed_types)) {
                    throw new Exception('Invalid file type. Only JPEG, PNG, GIF, PDF, and TXT files are allowed.');
                }
                if ($_FILES['attachment']['size'] > $max_size) {
                    throw new Exception('File size must be less than 5MB.');
                }

                // Create upload directory if it doesn't exist
                $upload_dir = 'uploads/reports/';
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }

                // Generate unique filename
                $file_extension = pathinfo($_FILES['attachment']['name'], PATHINFO_EXTENSION);
                $filename = uniqid() . '_' . time() . '.' . $file_extension;
                $attachment_path = $upload_dir . $filename;

                if (!move_uploaded_file($_FILES['attachment']['tmp_name'], $attachment_path)) {
                    throw new Exception('Failed to upload file.');
                }
            }

            // Insert into database
            $stmt = $conn->prepare("INSERT INTO contacts_reports (email, title, message, attachment, contact_type, hospital_id, created_at) VALUES (?, ?, ?, ?, 'report', ?, NOW())");
            $db_hospital_id = ($user_type === 'patient') ? null : $hospital_id;
            $stmt->bind_param("ssssi", $email, $title, $user_message, $attachment_path, $db_hospital_id);

            if ($stmt->execute()) {
                $message = "Your report has been submitted successfully. Our team will review it shortly.";
                // Clear form data on success
                $_POST = array();
            } else {
                throw new Exception('Failed to submit report. Please try again.');
            }
            $stmt->close();

        } catch (Exception $e) {
            $error = $e->getMessage();
            // Clean up uploaded file if database insert failed
            if (isset($attachment_path) && file_exists($attachment_path)) {
                unlink($attachment_path);
            }
        }
    }
}

// Function to get role-specific message
function getRoleMessage($user_type) {
    switch ($user_type) {
        case 'patient':
            return "Please report important issues related to our website or hospital services. If you have problems with specific doctors or receptionists, please contact your hospital directly through the 'Contact Hospital' option in your dashboard.";
        case 'doctor':
            return "Report any technical issues with the platform, patient management concerns, or system-related problems. For hospital-specific administrative issues, please contact your hospital administration.";
        case 'receptionist':
            return "Report system bugs, patient registration issues, or technical problems with the platform. For internal hospital matters, please contact your hospital administration.";
        case 'admin':
            return "Report any system-wide issues, security concerns, or platform improvements. Your feedback helps us maintain and improve the system for all users.";
        default:
            return "Please describe your issue in detail so we can assist you better.";
    }
}

$role_message = getRoleMessage($user_type);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Send Report - Healthcare System</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-blue: #87CEEB;
            --dark-blue: #4682B4;
            --sky-blue: #87CEEB;
            --light-blue: #E0F6FF;
            --white: #ffffff;
            --text-dark: #2D3748;
            --text-light: #718096;
            --success-green: #48BB78;
            --error-red: #F56565;
            --border-light: #E2E8F0;
            --shadow-light: rgba(135, 206, 235, 0.15);
            --shadow-medium: rgba(135, 206, 235, 0.25);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, var(--sky-blue) 0%, var(--light-blue) 100%);
            min-height: 100vh;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 600px;
            margin: 0 auto;
            background: var(--white);
            border-radius: 24px;
            box-shadow: 
                0 20px 60px var(--shadow-medium),
                0 8px 25px var(--shadow-light);
            overflow: hidden;
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .header {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--dark-blue) 100%);
            color: var(--white);
            padding: 48px 40px 32px;
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
            bottom: 0;
            background: url('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><pattern id="grid" width="10" height="10" patternUnits="userSpaceOnUse"><path d="M 10 0 L 0 0 0 10" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="0.5"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }

        .header-content {
            position: relative;
            z-index: 1;
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 12px;
            letter-spacing: -0.025em;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 16px;
        }

        .header h1 i {
            font-size: 2.2rem;
            opacity: 0.9;
        }

        .header p {
            font-size: 1.125rem;
            opacity: 0.95;
            font-weight: 400;
            margin-top: 8px;
        }

        .role-info {
            background: linear-gradient(135deg, #f8fbff 0%, #e6f3ff 100%);
            margin: 24px 32px;
            padding: 24px 28px;
            border-radius: 16px;
            border-left: 5px solid var(--primary-blue);
            box-shadow: 0 4px 12px rgba(135, 206, 235, 0.1);
        }

        .role-info-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 12px;
            font-weight: 600;
            color: var(--dark-blue);
            font-size: 1.1rem;
        }

        .role-info-header i {
            color: var(--primary-blue);
            font-size: 1.2rem;
        }

        .role-info-text {
            color: #4a6fa5;
            font-size: 1rem;
            line-height: 1.6;
        }

        .form-container {
            padding: 40px 32px 48px;
        }

        .form-group {
            margin-bottom: 32px;
            position: relative;
        }

        .form-group:last-child {
            margin-bottom: 0;
        }

        label {
            display: flex;
            align-items: center;
            gap: 10px;
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--dark-blue);
            margin-bottom: 12px;
            letter-spacing: -0.01em;
        }

        label i {
            color: var(--primary-blue);
            font-size: 1.1rem;
        }

        .required {
            color: var(--error-red);
            margin-left: 4px;
            font-weight: 700;
        }

        input[type="email"],
        input[type="text"],
        textarea {
            width: 100%;
            padding: 16px 20px;
            border: 2px solid var(--border-light);
            border-radius: 12px;
            font-size: 1.05rem;
            background: #fafbfc;
            color: var(--text-dark);
            font-family: inherit;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.04);
        }

        input[type="email"]:focus,
        input[type="text"]:focus,
        textarea:focus {
            outline: none;
            border-color: var(--primary-blue);
            background: var(--white);
            box-shadow: 
                0 0 0 4px rgba(135, 206, 235, 0.15),
                0 4px 16px rgba(135, 206, 235, 0.2);
            transform: translateY(-2px);
        }

        textarea {
            min-height: 120px;
            resize: vertical;
            line-height: 1.6;
        }

        .drag-drop-area {
            border: 3px dashed #c1d9f0;
            border-radius: 16px;
            padding: 48px 24px;
            text-align: center;
            background: linear-gradient(135deg, #fafbff 0%, #f0f7ff 100%);
            cursor: pointer;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .drag-drop-area::before {
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(135, 206, 235, 0.1), transparent);
            transition: left 0.6s ease;
        }

        .drag-drop-area:hover::before {
            left: 100%;
        }

        .drag-drop-area:hover,
        .drag-drop-area.dragover {
            border-color: var(--primary-blue);
            background: linear-gradient(135deg, #e6f3ff 0%, #cce6ff 100%);
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(135, 206, 235, 0.2);
        }

        .drag-drop-content {
            position: relative;
            z-index: 1;
        }

        .drag-drop-icon {
            font-size: 3rem;
            color: var(--primary-blue);
            margin-bottom: 16px;
            display: block;
        }

        .drag-drop-text {
            font-size: 1.2rem;
            color: var(--dark-blue);
            font-weight: 600;
            margin-bottom: 8px;
        }

        .drag-drop-subtext {
            font-size: 1rem;
            color: var(--text-light);
        }

        .file-input-hidden {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            left: 0;
            top: 0;
            cursor: pointer;
        }

        .file-preview {
            margin-top: 16px;
            background: linear-gradient(135deg, #e6f7ff 0%, #cce6ff 100%);
            border-radius: 12px;
            padding: 16px 20px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            border: 2px solid #b4d9ee;
            font-size: 1.05rem;
            box-shadow: 0 4px 12px rgba(135, 206, 235, 0.1);
        }

        .file-preview-info {
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--dark-blue);
            font-weight: 500;
        }

        .file-preview i {
            color: var(--primary-blue);
            font-size: 1.2rem;
        }

        .remove-file {
            background: none;
            border: none;
            color: var(--error-red);
            cursor: pointer;
            font-size: 1.3rem;
            padding: 8px;
            border-radius: 50%;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .remove-file:hover {
            background: rgba(245, 101, 101, 0.1);
            transform: scale(1.1);
        }

        .file-requirements {
            font-size: 0.95rem;
            color: var(--text-light);
            margin-top: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .file-requirements i {
            color: var(--primary-blue);
        }

        .submit-btn {
            background: linear-gradient(135deg, var(--primary-blue) 0%, var(--dark-blue) 100%);
            color: var(--white);
            padding: 18px 32px;
            border: none;
            border-radius: 12px;
            font-size: 1.2rem;
            font-weight: 600;
            cursor: pointer;
            width: 100%;
            box-shadow: 0 8px 25px rgba(135, 206, 235, 0.3);
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 12px;
            letter-spacing: 0.025em;
        }

        .submit-btn:hover {
            background: linear-gradient(135deg, var(--dark-blue) 0%, #2c5282 100%);
            box-shadow: 0 12px 35px rgba(135, 206, 235, 0.4);
            transform: translateY(-2px);
        }

        .submit-btn:active {
            transform: translateY(0);
        }

        .alert {
            padding: 20px 24px;
            margin: 24px 32px;
            border-radius: 12px;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 12px;
            box-shadow: 0 4px 16px rgba(0, 0, 0, 0.1);
            font-size: 1.05rem;
        }

        .alert i {
            font-size: 1.2rem;
        }

        .alert-success {
            background: linear-gradient(135deg, #C6F6D5 0%, #9AE6B4 100%);
            color: #22543D;
            border: 2px solid #68D391;
        }

        .alert-error {
            background: linear-gradient(135deg, #FED7D7 0%, #FEB2B2 100%);
            color: #742A2A;
            border: 2px solid #FC8181;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 32px;
        }

        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid var(--primary-blue);
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 16px;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        .character-counter {
            text-align: right;
            font-size: 0.9rem;
            color: var(--text-light);
            margin-top: 8px;
            font-weight: 500;
        }

        .character-counter.warning {
            color: var(--error-red);
        }

        /* Responsive Design */
        @media (max-width: 768px) {
            body {
                padding: 10px;
            }

            .container {
                max-width: 100%;
                border-radius: 16px;
            }

            .header {
                padding: 32px 24px 24px;
            }

            .header h1 {
                font-size: 2rem;
                flex-direction: column;
                gap: 8px;
            }

            .form-container {
                padding: 24px 20px 32px;
            }

            .role-info {
                margin: 16px 20px;
                padding: 20px;
            }

            .drag-drop-area {
                padding: 32px 16px;
            }

            .alert {
                margin: 16px 20px;
                padding: 16px 20px;
            }
        }

        @media (max-width: 480px) {
            .header h1 {
                font-size: 1.75rem;
            }

            .form-container {
                padding: 20px 16px 24px;
            }

            input[type="email"],
            input[type="text"],
            textarea {
                padding: 14px 16px;
            }

            .submit-btn {
                padding: 16px 24px;
                font-size: 1.1rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-content">
                <h1>
                    <i class="fas fa-clipboard-list"></i>
                    Send Report
                </h1>
                <p>Report issues or concerns to our support team</p>
            </div>
        </div>

        <div class="role-info">
            <div class="role-info-header">
                <i class="fas fa-user-tag"></i>
                For <?php echo ucfirst($user_type); ?>s:
            </div>
            <div class="role-info-text">
                <?php echo $role_message; ?>
            </div>
        </div>

        <?php if ($message): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo htmlspecialchars($message, ENT_QUOTES); ?>
            </div>
        <?php endif; ?>

        <?php if ($error): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-triangle"></i>
                <?php echo htmlspecialchars($error, ENT_QUOTES); ?>
            </div>
        <?php endif; ?>

        <div class="form-container">
            <form method="POST" enctype="multipart/form-data" id="reportForm" autocomplete="off">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token'], ENT_QUOTES); ?>">
                
                <div class="form-group">
                    <label for="email">
                        <i class="fas fa-envelope"></i>
                        Email Address
                        <span class="required">*</span>
                    </label>
                    <input 
                        type="email" 
                        id="email" 
                        name="email" 
                        required 
                        placeholder="Enter your email address"
                        autocomplete="email"
                        value="<?php echo htmlspecialchars($_POST['email'] ?? '', ENT_QUOTES); ?>"
                    >
                </div>

                <div class="form-group">
                    <label for="title">
                        <i class="fas fa-heading"></i>
                        Title (Brief Topic)
                        <span class="required">*</span>
                    </label>
                    <input 
                        type="text" 
                        id="title" 
                        name="title" 
                        required 
                        maxlength="255"
                        placeholder="Brief description of your issue"
                        value="<?php echo htmlspecialchars($_POST['title'] ?? '', ENT_QUOTES); ?>"
                    >
                    <div class="character-counter" id="titleCounter">0/255</div>
                </div>

                <div class="form-group">
                    <label for="message">
                        <i class="fas fa-comment-alt"></i>
                        Message
                        <span class="required">*</span>
                    </label>
                    <textarea 
                        id="message" 
                        name="message" 
                        required 
                        maxlength="1000"
                        placeholder="Please describe your issue in detail..."
                    ><?php echo htmlspecialchars($_POST['message'] ?? '', ENT_QUOTES); ?></textarea>
                    <div class="character-counter" id="messageCounter">0/1000</div>
                </div>

                <div class="form-group">
                    <label for="attachment">
                        <i class="fas fa-paperclip"></i>
                        Attachment (Optional)
                    </label>
                    <div class="drag-drop-area" id="dragDropArea">
                        <input 
                            type="file" 
                            id="attachment" 
                            name="attachment" 
                            accept=".jpg,.jpeg,.png,.gif,.pdf,.txt" 
                            class="file-input-hidden"
                        >
                        <div class="drag-drop-content">
                            <i class="fas fa-cloud-upload-alt drag-drop-icon"></i>
                            <div class="drag-drop-text">Drag & drop your file here</div>
                            <div class="drag-drop-subtext">or click to browse</div>
                        </div>
                    </div>
                    
                    <div class="file-preview" id="filePreview" style="display:none;">
                        <div class="file-preview-info">
                            <i class="fas fa-file"></i>
                            <span id="fileName"></span>
                        </div>
                        <button type="button" class="remove-file" id="removeFile" title="Remove file">
                            <i class="fas fa-times"></i>
                        </button>
                    </div>
                    
                    <div class="file-requirements">
                        <i class="fas fa-info-circle"></i>
                        Supported: JPEG, PNG, GIF, PDF, TXT (Max: 5MB)
                    </div>
                </div>

                <div class="loading" id="loading">
                    <div class="spinner"></div>
                    <p>Submitting your report...</p>
                </div>

                <button type="submit" class="submit-btn" id="submitBtn">
                    <i class="fas fa-paper-plane"></i>
                    Submit Report
                </button>
            </form>
        </div>
    </div>

    <script>
        // Enhanced drag & drop functionality
        const dragDropArea = document.getElementById('dragDropArea');
        const fileInput = document.getElementById('attachment');
        const filePreview = document.getElementById('filePreview');
        const fileName = document.getElementById('fileName');
        const removeFileBtn = document.getElementById('removeFile');

        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dragDropArea.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        // Highlight drop area when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            dragDropArea.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dragDropArea.addEventListener(eventName, unhighlight, false);
        });

        function highlight() {
            dragDropArea.classList.add('dragover');
        }

        function unhighlight() {
            dragDropArea.classList.remove('dragover');
        }

        // Handle dropped files
        dragDropArea.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        }

        // Handle click to browse
        dragDropArea.addEventListener('click', () => fileInput.click());

        // Handle file selection
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });

        // Remove file
        removeFileBtn.addEventListener('click', () => {
            fileInput.value = '';
            filePreview.style.display = 'none';
            dragDropArea.style.display = 'block';
        });

        function handleFile(file) {
            const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain'];
            const maxSize = 5 * 1024 * 1024; // 5MB

            if (!allowedTypes.includes(file.type)) {
                showAlert('Invalid file type. Only JPEG, PNG, GIF, PDF, and TXT files are allowed.', 'error');
                fileInput.value = '';
                return;
            }

            if (file.size > maxSize) {
                showAlert('File size must be less than 5MB.', 'error');
                fileInput.value = '';
                return;
            }

            fileName.textContent = file.name;
            filePreview.style.display = 'flex';
            dragDropArea.style.display = 'none';
        }

        // Character counters
        function setupCharacterCounter(element, counterId, maxLength) {
            const counter = document.getElementById(counterId);
            
            element.addEventListener('input', () => {
                const length = element.value.length;
                counter.textContent = `${length}/${maxLength}`;
                
                if (length > maxLength * 0.9) {
                    counter.classList.add('warning');
                } else {
                    counter.classList.remove('warning');
                }
            });

            // Initialize counter on page load
            const length = element.value.length;
            counter.textContent = `${length}/${maxLength}`;
        }

        setupCharacterCounter(document.getElementById('title'), 'titleCounter', 255);
        setupCharacterCounter(document.getElementById('message'), 'messageCounter', 1000);

        // Form validation and submission
        document.getElementById('reportForm').addEventListener('submit', function(e) {
            const title = document.getElementById('title').value.trim();
            const message = document.getElementById('message').value.trim();
            const email = document.getElementById('email').value.trim();
            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');

            // Validation
            if (title.length < 5) {
                showAlert('Title must be at least 5 characters long.', 'error');
                e.preventDefault();
                return;
            }

            if (message.length < 10) {
                showAlert('Message must be at least 10 characters long.', 'error');
                e.preventDefault();
                return;
            }

            if (!email || !isValidEmail(email)) {
                showAlert('Please enter a valid email address.', 'error');
                e.preventDefault();
                return;
            }

            // Show loading state
            submitBtn.style.display = 'none';
            loading.style.display = 'block';
        });

        function isValidEmail(email) {
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
            return emailRegex.test(email);
        }

        function showAlert(message, type) {
            // Remove existing temporary alerts
            const existingAlerts = document.querySelectorAll('.temp-alert');
            existingAlerts.forEach(alert => alert.remove());

            const alertDiv = document.createElement('div');
            alertDiv.className = `alert alert-${type} temp-alert`;
            alertDiv.innerHTML = `
                <i class="fas fa-${type === 'success' ? 'check-circle' : 'exclamation-triangle'}"></i>
                ${message}
            `;

            const container = document.querySelector('.container');
            const roleInfo = document.querySelector('.role-info');
            container.insertBefore(alertDiv, roleInfo.nextSibling);

            // Auto-remove after 5 seconds
            setTimeout(() => {
                alertDiv.remove();
            }, 5000);

            // Smooth scroll to alert
            alertDiv.scrollIntoView({ 
                behavior: 'smooth', 
                block: 'center' 
            });
        }

        // Enhanced focus effects
        const inputs = document.querySelectorAll('input, textarea');
        inputs.forEach(input => {
            input.addEventListener('focus', () => {
                input.parentElement.classList.add('focused');
            });

            input.addEventListener('blur', () => {
                input.parentElement.classList.remove('focused');
            });
        });

        // Add smooth animations on page load
        window.addEventListener('load', () => {
            const container = document.querySelector('.container');
            container.style.opacity = '0';
            container.style.transform = 'translateY(20px)';
            
            setTimeout(() => {
                container.style.transition = 'all 0.6s cubic-bezier(0.4, 0, 0.2, 1)';
                container.style.opacity = '1';
                container.style.transform = 'translateY(0)';
            }, 100);
        });
    </script>
</body>
</html>
