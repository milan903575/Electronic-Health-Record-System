<?php
session_start();

// Include database connection
include 'connection.php';

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; frame-src https://www.google.com;");

// Handle AJAX hospital search
if (isset($_POST['action']) && $_POST['action'] === 'search_hospitals') {
    header('Content-Type: application/json');
    
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        echo json_encode(['error' => 'Invalid CSRF token']);
        exit();
    }

    $query = isset($_POST['query']) ? trim($_POST['query']) : '';

    if (strlen($query) < 2) {
        echo json_encode([]);
        exit();
    }

    try {
        $searchTerm = '%' . $query . '%';
        $stmt = $conn->prepare("SELECT id, hospital_name, city, zipcode 
                               FROM hospitals 
                               WHERE hospital_name LIKE ? OR city LIKE ? OR zipcode LIKE ? 
                               ORDER BY hospital_name ASC 
                               LIMIT 10");

        if (!$stmt) {
            throw new Exception("Prepare failed: " . $conn->error);
        }

        $stmt->bind_param("sss", $searchTerm, $searchTerm, $searchTerm);
        
        if (!$stmt->execute()) {
            throw new Exception("Execute failed: " . $stmt->error);
        }
        
        $result = $stmt->get_result();
        $hospitals = [];
        
        while ($row = $result->fetch_assoc()) {
            $hospitals[] = [
                'id' => (int)$row['id'],
                'hospital_name' => htmlspecialchars($row['hospital_name'], ENT_QUOTES, 'UTF-8'),
                'city' => htmlspecialchars($row['city'], ENT_QUOTES, 'UTF-8'),
                'zipcode' => htmlspecialchars($row['zipcode'], ENT_QUOTES, 'UTF-8')
            ];
        }
        
        echo json_encode($hospitals);
        
    } catch (Exception $e) {
        error_log("Hospital search error: " . $e->getMessage());
        http_response_code(500);
        echo json_encode(['error' => 'Search failed']);
    }
    exit();
}

// Check CSRF token and user authentication
if (!isset($_SESSION['csrf_token']) || !isset($_SESSION['user_id'])) {
    header("Location: login.php?error=csrf_token_missing_or_session_expired");
    exit();
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token mismatch. Please refresh the page and try again.");
    }
    
    $user_id = $_SESSION['user_id'];
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $subject = htmlspecialchars($_POST['subject'], ENT_QUOTES, 'UTF-8');
    $message = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');
    $hospital_id = intval($_POST['hospital_id']);
    
    if (empty($email) || empty($subject) || empty($message) || empty($hospital_id)) {
        $error = "All fields are required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $error = "Invalid email format.";
    } else {
        $stmt = $conn->prepare("SELECT patient_id, hospital_id, registration_status 
                              FROM patient_hospital 
                              WHERE patient_id = ? AND hospital_id = ? AND registration_status = 'Completed'");
        $stmt->bind_param("ii", $user_id, $hospital_id);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            $stmt2 = $conn->prepare("SELECT patient_id, hospital_id, registration_status 
                                   FROM patient_hospital 
                                   WHERE patient_id = ? AND hospital_id = ?");
            $stmt2->bind_param("ii", $user_id, $hospital_id);
            $stmt2->execute();
            $result2 = $stmt2->get_result();
            
            if ($result2->num_rows > 0) {
                $row = $result2->fetch_assoc();
                if ($row['registration_status'] === 'Pending') {
                    $error = "Your registration with this hospital is still pending. Please wait for approval or contact the hospital directly.";
                } else {
                    $error = "You cannot contact this hospital as your registration is not completed. Please complete your registration first.";
                }
            } else {
                $error = "You cannot contact this hospital as you haven't registered with them. Please register first.";
            }
            $show_register_link = true;
        } else {
            $attachment_path = null;
            if (isset($_FILES['attachments']) && $_FILES['attachments']['error'] === UPLOAD_ERR_OK) {
                $upload_dir = 'uploads/contacts/';
                if (!is_dir($upload_dir)) {
                    mkdir($upload_dir, 0755, true);
                }
                
                $file_extension = strtolower(pathinfo($_FILES['attachments']['name'], PATHINFO_EXTENSION));
                $allowed_extensions = ['jpg', 'jpeg', 'png', 'pdf', 'doc', 'docx', 'txt'];
                
                if (in_array($file_extension, $allowed_extensions) && $_FILES['attachments']['size'] <= 5000000) {
                    $filename = uniqid() . '_' . basename($_FILES['attachments']['name']);
                    $attachment_path = $upload_dir . $filename;
                    
                    if (!move_uploaded_file($_FILES['attachments']['tmp_name'], $attachment_path)) {
                        $error = "Failed to upload attachment.";
                    }
                } else {
                    $error = "Invalid file type or file too large (max 5MB).";
                }
            }
            
            if (!isset($error)) {
                $stmt = $conn->prepare("INSERT INTO contacts_reports (email, title, message, attachment, contact_type, hospital_id, created_at) 
                                      VALUES (?, ?, ?, ?, 'contact', ?, NOW())");
                $stmt->bind_param("ssssi", $email, $subject, $message, $attachment_path, $hospital_id);
                
                if ($stmt->execute()) {
                    $success = "Your message has been sent successfully!";
                } else {
                    $error = "Failed to send message. Please try again.";
                }
            }
        }
    }
}

// Get user's contact requests for the grid
$user_requests = [];
if (isset($_SESSION['user_id'])) {
    $user_id = $_SESSION['user_id'];
    
    // Get user's email first
    $user_stmt = $conn->prepare("SELECT email FROM patients WHERE id = ?");
    $user_stmt->bind_param("i", $user_id);
    $user_stmt->execute();
    $user_result = $user_stmt->get_result();
    $user_email = '';
    
    if ($user_result->num_rows > 0) {
        $user_data = $user_result->fetch_assoc();
        $user_email = $user_data['email'];
        
        // UPDATED: Get contact requests with hospital information and replied_at
        $requests_stmt = $conn->prepare("SELECT cr.*, h.hospital_name 
                                       FROM contacts_reports cr 
                                       INNER JOIN hospitals h ON cr.hospital_id = h.id 
                                       WHERE cr.email = ? 
                                       ORDER BY cr.created_at DESC");
        $requests_stmt->bind_param("s", $user_email);
        $requests_stmt->execute();
        $requests_result = $requests_stmt->get_result();
        
        while ($row = $requests_result->fetch_assoc()) {
            $user_requests[] = $row;
        }
    }
}

// Generate new CSRF token for the form
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Hospital</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2b6777;
            --primary-light: #c8d8e4;
            --primary-dark: #1a4c5d;
            --accent-color: #52ab98;
            --light-color: #f2f2f2;
            --dark-color: #333;
            --success-color: #4caf50;
            --error-color: #f44336;
            --warning-color: #ff9800;
            --gray-100: #f8f9fa;
            --gray-200: #e9ecef;
            --gray-300: #dee2e6;
            --gray-400: #ced4da;
            --gray-500: #adb5bd;
            --gray-600: #6c757d;
            --gray-700: #495057;
            --gray-800: #343a40;
            --gray-900: #212529;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, var(--primary-light) 0%, #f4f4f9 100%);
            color: var(--dark-color);
            line-height: 1.6;
            min-height: 100vh;
            padding: 20px;
        }

        .main-container {
            max-width: 1400px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            min-height: calc(100vh - 40px);
        }

        .form-container {
            background: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.1);
            display: flex;
            flex-direction: column;
            height: fit-content;
        }

        .requests-container {
            background: white;
            border-radius: 16px;
            padding: 30px;
            box-shadow: 0 15px 30px rgba(0, 0, 0, 0.1);
            overflow-y: auto;
            max-height: calc(100vh - 40px);
        }

        .contact-header {
            background-color: var(--primary-color);
            color: white;
            padding: 30px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }

        .contact-header::before {
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(255,255,255,0.1) 0%, rgba(255,255,255,0) 70%);
            transform: rotate(30deg);
        }

        .contact-header h1 {
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 10px;
            position: relative;
        }

        .contact-header p {
            font-size: 1rem;
            opacity: 0.9;
            position: relative;
        }

        .form-section {
            padding: 30px;
            background-color: white;
        }

        .section-title {
            font-size: 1.5rem;
            color: var(--primary-color);
            margin-bottom: 25px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--primary-light);
            position: relative;
        }

        .section-title::after {
            content: '';
            position: absolute;
            bottom: -2px;
            left: 0;
            width: 60px;
            height: 2px;
            background-color: var(--primary-color);
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--gray-700);
        }

        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            font-family: 'Poppins', sans-serif;
            font-size: 1rem;
            transition: all 0.3s ease;
        }

        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(43, 103, 119, 0.2);
            outline: none;
        }

        textarea.form-control {
            resize: vertical;
            min-height: 100px;
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
            gap: 8px;
            text-decoration: none;
        }

        .btn:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
        }

        .btn:disabled {
            background-color: var(--gray-400);
            cursor: not-allowed;
            transform: none;
        }

        .btn-secondary {
            background-color: var(--gray-600);
        }

        .btn-secondary:hover {
            background-color: var(--gray-700);
        }

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-success {
            background-color: rgba(76, 175, 80, 0.1);
            border: 1px solid rgba(76, 175, 80, 0.3);
            color: var(--success-color);
        }

        .alert-error {
            background-color: rgba(244, 67, 54, 0.1);
            border: 1px solid rgba(244, 67, 54, 0.3);
            color: var(--error-color);
        }

        .hospital-search {
            margin-bottom: 25px;
        }

        .search-input {
            position: relative;
            margin-bottom: 15px;
        }

        .search-results {
            max-height: 200px;
            overflow-y: auto;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            background: white;
            display: none;
            position: absolute;
            width: 100%;
            z-index: 1000;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            top: 100%;
        }

        .search-results.show {
            display: block;
        }

        .search-result-item {
            padding: 12px 15px;
            border-bottom: 1px solid var(--gray-200);
            cursor: pointer;
            transition: background-color 0.2s;
        }

        .search-result-item:hover {
            background-color: var(--gray-100);
        }

        .search-result-item:last-child {
            border-bottom: none;
        }

        .hospital-name {
            font-weight: 500;
            color: var(--primary-color);
        }

        .hospital-details {
            font-size: 0.9rem;
            color: var(--gray-600);
            margin-top: 2px;
        }

        .selected-hospital {
            background-color: var(--primary-light);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .selected-hospital h4 {
            color: var(--primary-color);
            margin-bottom: 5px;
        }

        .selected-hospital p {
            color: var(--gray-600);
            margin: 0;
        }

        .loading {
            display: none;
            text-align: center;
            padding: 10px;
            color: var(--gray-500);
        }

        /* Grid Cards Styles */
        .requests-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .request-card {
            background: white;
            border: 1px solid var(--gray-200);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .request-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 15px rgba(0, 0, 0, 0.15);
        }

        .request-card::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary-color), var(--accent-color));
        }

        .card-header {
            margin-bottom: 15px;
        }

        .card-hospital {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 5px;
        }

        .card-title {
            font-size: 1rem;
            font-weight: 500;
            color: var(--gray-800);
            margin-bottom: 10px;
        }

        .card-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            font-size: 0.8rem;
            color: var(--gray-600);
        }

        .card-status {
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.7rem;
            font-weight: 500;
            text-transform: uppercase;
        }

        .status-resolved {
            background-color: rgba(76, 175, 80, 0.1);
            color: var(--success-color);
        }

        .status-pending {
            background-color: rgba(255, 152, 0, 0.1);
            color: var(--warning-color);
        }

        .card-message {
            font-size: 0.9rem;
            color: var(--gray-700);
            line-height: 1.5;
            margin-bottom: 15px;
            display: -webkit-box;
            -webkit-line-clamp: 3;
            -webkit-box-orient: vertical;
            overflow: hidden;
        }

        .card-reply {
            background: rgba(76, 175, 80, 0.1);
            padding: 12px;
            border-radius: 8px;
            border-left: 4px solid var(--success-color);
            margin-top: 15px;
        }

        .reply-label {
            font-size: 0.8rem;
            font-weight: 600;
            color: var(--success-color);
            margin-bottom: 5px;
        }

        .reply-text {
            font-size: 0.9rem;
            color: var(--gray-700);
            line-height: 1.4;
        }

        /* NEW: Reply timestamp styling */
        .reply-timestamp {
            font-size: 0.75rem;
            color: var(--gray-500);
            margin-top: 8px;
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .no-requests {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-500);
        }

        .no-requests i {
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        @media (max-width: 1200px) {
            .main-container {
                grid-template-columns: 1fr;
                gap: 20px;
            }
            
            .requests-container {
                max-height: none;
            }
        }

        @media (max-width: 768px) {
            .contact-header h1 {
                font-size: 1.5rem;
            }
            
            .form-section {
                padding: 20px;
            }
            
            .requests-container {
                padding: 20px;
            }
            
            .requests-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="main-container">
        <!-- Form Section (50%) -->
        <div class="form-container">
            <div class="contact-header">
                <h1><i class="fas fa-envelope"></i> Contact Hospital</h1>
                <p>Search for a hospital and send your message or inquiry directly to them.</p>
            </div>
            
            <div class="form-section">
                <?php if (isset($success)): ?>
                    <div class="alert alert-success">
                        <i class="fas fa-check-circle"></i>
                        <?php echo $success; ?>
                    </div>
                <?php endif; ?>
                
                <?php if (isset($error)): ?>
                    <div class="alert alert-error">
                        <i class="fas fa-exclamation-circle"></i>
                        <?php echo $error; ?>
                        <?php if (isset($show_register_link)): ?>
                            <br><a href="/patient/patient_registration.php" class="btn btn-secondary" style="margin-top: 10px;">
                                <i class="fas fa-user-plus"></i> Register Now
                            </a>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>

                <div class="hospital-search">
                    <h3 style="color: var(--primary-color); margin-bottom: 15px;">
                        <i class="fas fa-search"></i> Search Hospital
                    </h3>
                    <div class="search-input">
                        <input type="text" id="hospital-search" class="form-control" placeholder="Search by hospital name, city, or zipcode..." autocomplete="off">
                        <div class="loading" id="search-loading">
                            <i class="fas fa-spinner fa-spin"></i> Searching...
                        </div>
                        <div id="search-results" class="search-results"></div>
                    </div>
                    
                    <div id="selected-hospital" class="selected-hospital" style="display: none;">
                        <h4 id="selected-name"></h4>
                        <p id="selected-details"></p>
                        <button type="button" class="btn btn-secondary" onclick="clearSelection()">
                            <i class="fas fa-times"></i> Clear Selection
                        </button>
                    </div>
                </div>
                
                <form method="POST" enctype="multipart/form-data" id="contact-form">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                    <input type="hidden" name="hospital_id" id="hospital_id" value="">
                    
                    <div class="form-group">
                        <label for="email">Email Address</label>
                        <input type="email" id="email" name="email" class="form-control" placeholder="Enter your email address" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="subject">Subject</label>
                        <input type="text" id="subject" name="subject" class="form-control" placeholder="What is this regarding?" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="message">Your Message</label>
                        <textarea id="message" name="message" class="form-control" placeholder="Write your message here..." required></textarea>
                    </div>
                    
                    <div class="form-group">
                        <label for="attachments">Attachment (Optional)</label>
                        <input type="file" id="attachments" name="attachments" class="form-control" accept=".jpg,.jpeg,.png,.pdf,.doc,.docx,.txt">
                        <small style="color: var(--gray-600); font-size: 0.8rem; margin-top: 5px; display: block;">Max file size: 5MB. Allowed: JPG, PNG, PDF, DOC, DOCX, TXT</small>
                    </div>
                    
                    <button type="submit" class="btn" id="submit-btn" disabled>
                        <i class="fas fa-paper-plane"></i>
                        Send Message
                    </button>
                </form>
            </div>
        </div>

        <!-- Requests Grid Section (50%) -->
        <div class="requests-container">
            <h2 class="section-title">
                <i class="fas fa-history"></i> Your Contact Requests
            </h2>
            
            <?php if (count($user_requests) > 0): ?>
                <div class="requests-grid">
                    <?php foreach ($user_requests as $request): ?>
                        <div class="request-card">
                            <div class="card-header">
                                <div class="card-hospital">
                                    <i class="fas fa-hospital"></i> <?php echo htmlspecialchars($request['hospital_name']); ?>
                                </div>
                                <div class="card-title"><?php echo htmlspecialchars($request['title']); ?></div>
                                <div class="card-meta">
                                    <span><i class="fas fa-calendar"></i> <?php echo date('M d, Y', strtotime($request['created_at'])); ?></span>
                                    <span class="card-status <?php echo $request['resolved'] ? 'status-resolved' : 'status-pending'; ?>">
                                        <?php echo $request['resolved'] ? 'Resolved' : 'Pending'; ?>
                                    </span>
                                </div>
                            </div>
                            
                            <div class="card-message">
                                <?php echo nl2br(htmlspecialchars($request['message'])); ?>
                            </div>
                            
                            <?php if ($request['reply_message']): ?>
                                <div class="card-reply">
                                    <div class="reply-label">
                                        <i class="fas fa-reply"></i> Hospital Reply:
                                    </div>
                                    <div class="reply-text">
                                        <?php echo nl2br(htmlspecialchars($request['reply_message'])); ?>
                                    </div>
                                    <!-- NEW: Added replied_at timestamp display -->
                                    <?php if ($request['replied_at']): ?>
                                        <div class="reply-timestamp">
                                            <i class="fas fa-clock"></i>
                                            Replied on: <?php echo date('M d, Y \a\t g:i A', strtotime($request['replied_at'])); ?>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php else: ?>
                <div class="no-requests">
                    <i class="fas fa-inbox"></i>
                    <h3>No Contact Requests</h3>
                    <p>You haven't sent any contact requests yet. Use the form on the left to send your first message to a hospital.</p>
                </div>
            <?php endif; ?>
        </div>
    </div>

    <script>
        // Hospital Search Functionality
        const searchInput = document.getElementById('hospital-search');
        const searchResults = document.getElementById('search-results');
        const searchLoading = document.getElementById('search-loading');
        const selectedHospital = document.getElementById('selected-hospital');
        const hospitalIdInput = document.getElementById('hospital_id');
        const submitBtn = document.getElementById('submit-btn');
        
        let searchTimeout;
        
        searchInput.addEventListener('input', function() {
            clearTimeout(searchTimeout);
            const query = this.value.trim();
            
            if (query.length < 2) {
                searchResults.classList.remove('show');
                searchLoading.style.display = 'none';
                return;
            }
            
            searchLoading.style.display = 'block';
            searchResults.classList.remove('show');
            
            searchTimeout = setTimeout(() => {
                searchHospitals(query);
            }, 300);
        });
        
        function searchHospitals(query) {
            const formData = new FormData();
            formData.append('action', 'search_hospitals');
            formData.append('query', query);
            formData.append('csrf_token', '<?php echo $_SESSION['csrf_token']; ?>');
            
            fetch('', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                searchLoading.style.display = 'none';
                
                if (data.error) {
                    console.error('Search error:', data.error);
                    return;
                }
                
                displaySearchResults(data);
            })
            .catch(error => {
                console.error('Error:', error);
                searchLoading.style.display = 'none';
            });
        }
        
        function displaySearchResults(hospitals) {
            searchResults.innerHTML = '';
            
            if (hospitals.length === 0) {
                searchResults.innerHTML = '<div class="search-result-item">No hospitals found</div>';
            } else {
                hospitals.forEach(hospital => {
                    const item = document.createElement('div');
                    item.className = 'search-result-item';
                    item.innerHTML = `
                        <div class="hospital-name">${hospital.hospital_name}</div>
                        <div class="hospital-details">${hospital.city}, ${hospital.zipcode}</div>
                    `;
                    item.addEventListener('click', () => selectHospital(hospital));
                    searchResults.appendChild(item);
                });
            }
            
            searchResults.classList.add('show');
        }
        
        function selectHospital(hospital) {
            document.getElementById('selected-name').textContent = hospital.hospital_name;
            document.getElementById('selected-details').textContent = `${hospital.city}, ${hospital.zipcode}`;
            hospitalIdInput.value = hospital.id;
            
            selectedHospital.style.display = 'block';
            searchResults.classList.remove('show');
            searchInput.value = hospital.hospital_name;
            
            submitBtn.disabled = false;
        }
        
        function clearSelection() {
            selectedHospital.style.display = 'none';
            hospitalIdInput.value = '';
            searchInput.value = '';
            searchResults.classList.remove('show');
            submitBtn.disabled = true;
        }
        
        // Hide search results when clicking outside
        document.addEventListener('click', function(event) {
            if (!event.target.closest('.search-input')) {
                searchResults.classList.remove('show');
            }
        });
        
        // Form validation
        document.getElementById('contact-form').addEventListener('submit', function(e) {
            if (!hospitalIdInput.value) {
                e.preventDefault();
                alert('Please select a hospital before submitting.');
                return false;
            }
        });
        
        // Auto-hide alerts after 5 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.transition = 'opacity 0.5s ease';
                alert.style.opacity = '0';
                setTimeout(() => {
                    if (alert.parentNode) {
                        alert.parentNode.removeChild(alert);
                    }
                }, 500);
            });
        }, 5000);
        
        // Smooth scroll for better UX
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const target = document.querySelector(this.getAttribute('href'));
                if (target) {
                    target.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        });
        
        // Enhanced card interactions
        document.querySelectorAll('.request-card').forEach(card => {
            card.addEventListener('mouseenter', function() {
                this.style.borderColor = 'var(--primary-color)';
            });
            
            card.addEventListener('mouseleave', function() {
                this.style.borderColor = 'var(--gray-200)';
            });
        });
        
        // Auto-expand message textarea
        const messageTextarea = document.getElementById('message');
        messageTextarea.addEventListener('input', function() {
            this.style.height = 'auto';
            this.style.height = Math.min(this.scrollHeight, 200) + 'px';
        });
        
        // File upload validation
        document.getElementById('attachments').addEventListener('change', function() {
            const file = this.files[0];
            if (file) {
                const maxSize = 5 * 1024 * 1024; // 5MB
                const allowedTypes = ['image/jpeg', 'image/jpg', 'image/png', 'application/pdf', 
                                    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 
                                    'text/plain'];
                
                if (file.size > maxSize) {
                    alert('File size must be less than 5MB');
                    this.value = '';
                    return;
                }
                
                if (!allowedTypes.includes(file.type)) {
                    alert('Invalid file type. Please upload JPG, PNG, PDF, DOC, DOCX, or TXT files only.');
                    this.value = '';
                    return;
                }
            }
        });
        
        // Real-time form validation
        const formInputs = document.querySelectorAll('#contact-form input, #contact-form textarea');
        formInputs.forEach(input => {
            input.addEventListener('blur', function() {
                validateField(this);
            });
            
            input.addEventListener('input', function() {
                if (this.classList.contains('error')) {
                    validateField(this);
                }
            });
        });
        
        function validateField(field) {
            const value = field.value.trim();
            let isValid = true;
            let errorMessage = '';
            
            // Remove existing error styling
            field.classList.remove('error');
            const existingError = field.parentNode.querySelector('.error-message');
            if (existingError) {
                existingError.remove();
            }
            
            // Validate based on field type
            if (field.hasAttribute('required') && !value) {
                isValid = false;
                errorMessage = 'This field is required';
            } else if (field.type === 'email' && value) {
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                if (!emailRegex.test(value)) {
                    isValid = false;
                    errorMessage = 'Please enter a valid email address';
                }
            }
            
            if (!isValid) {
                field.classList.add('error');
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                errorDiv.style.color = 'var(--error-color)';
                errorDiv.style.fontSize = '0.8rem';
                errorDiv.style.marginTop = '5px';
                errorDiv.textContent = errorMessage;
                field.parentNode.appendChild(errorDiv);
            }
            
            return isValid;
        }
        
        // Add error styling to CSS
        const style = document.createElement('style');
        style.textContent = `
            .form-control.error {
                border-color: var(--error-color) !important;
                box-shadow: 0 0 0 3px rgba(244, 67, 54, 0.2) !important;
            }
            
            .request-card {
                animation: fadeInUp 0.6s ease forwards;
            }
            
            @keyframes fadeInUp {
                from {
                    opacity: 0;
                    transform: translateY(30px);
                }
                to {
                    opacity: 1;
                    transform: translateY(0);
                }
            }
            
            .request-card:nth-child(even) {
                animation-delay: 0.1s;
            }
            
            .request-card:nth-child(3n) {
                animation-delay: 0.2s;
            }
            
            .search-result-item:hover {
                background-color: var(--primary-light) !important;
            }
            
            .btn:active {
                transform: translateY(0) !important;
            }
            
            .loading {
                animation: pulse 1.5s infinite;
            }
            
            @keyframes pulse {
                0% { opacity: 1; }
                50% { opacity: 0.5; }
                100% { opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    </script>
</body>
</html>
