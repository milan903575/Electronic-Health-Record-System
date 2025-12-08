<?php
session_start();
include '../connection.php';

// Check if hospital_id is set in the session
if (!isset($_SESSION['hospital_id'])) {
    // Redirect to login page if not set
    header("Location: ../login.php");
    exit();
}

// Retrieve hospital_id from session
$hospital_id = $_SESSION['hospital_id'];

// Fetch hospital details from hospitals table
$hospital_query = "SELECT hospital_name, state, city FROM hospitals WHERE id = ?";
$hospital_stmt = $conn->prepare($hospital_query);
$hospital_stmt->bind_param("i", $hospital_id);
$hospital_stmt->execute();
$hospital_result = $hospital_stmt->get_result();
$hospital_data = $hospital_result->fetch_assoc();
$hospital_stmt->close();

// If hospital not found, redirect to login
if (!$hospital_data) {
    header("Location: ../login.php");
    exit();
}

$hospital_name = $hospital_data['hospital_name'];
$hospital_state = $hospital_data['state'];
$hospital_city = $hospital_data['city'];

// CSRF token generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$message = '';
$message_type = '';

// Handle delete post request
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_post'])) {
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $message = 'Security token mismatch. Please try again.';
        $message_type = 'error';
    } else {
        $post_id = intval($_POST['post_id']);
        
        // Verify the post belongs to current hospital
        $verify_stmt = $conn->prepare("SELECT id FROM events_news WHERE id = ? AND hospital_id = ?");
        $verify_stmt->bind_param("ii", $post_id, $hospital_id);
        $verify_stmt->execute();
        $verify_result = $verify_stmt->get_result();
        
        if ($verify_result->num_rows > 0) {
            $delete_stmt = $conn->prepare("DELETE FROM events_news WHERE id = ? AND hospital_id = ?");
            $delete_stmt->bind_param("ii", $post_id, $hospital_id);
            
            if ($delete_stmt->execute()) {
                $message = 'Post deleted successfully!';
                $message_type = 'success';
            } else {
                $message = 'Failed to delete post.';
                $message_type = 'error';
            }
            $delete_stmt->close();
        } else {
            $message = 'Post not found or you do not have permission to delete it.';
            $message_type = 'error';
        }
        $verify_stmt->close();
    }
}

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_event'])) {
    // CSRF token validation
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        $message = 'Security token mismatch. Please try again.';
        $message_type = 'error';
    } else {
        $title = trim($_POST['title']);
        $description = trim($_POST['description']);
        
        // Validate inputs
        if (empty($title) || empty($description)) {
            $message = 'Please fill in all required fields.';
            $message_type = 'error';
        } else {
            $image_path = '';
            $video_path = '';
            
            // Handle file uploads
            $upload_dir = '../uploads/events/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0755, true);
            }
            
            // Handle image upload
            if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
                $image_tmp = $_FILES['image']['tmp_name'];
                $image_name = $_FILES['image']['name'];
                $image_ext = strtolower(pathinfo($image_name, PATHINFO_EXTENSION));
                $allowed_image_types = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
                
                if (in_array($image_ext, $allowed_image_types)) {
                    $image_filename = 'event_' . time() . '_' . rand(1000, 9999) . '.' . $image_ext;
                    $image_path = $upload_dir . $image_filename;
                    
                    if (!move_uploaded_file($image_tmp, $image_path)) {
                        $message = 'Failed to upload image.';
                        $message_type = 'error';
                    }
                } else {
                    $message = 'Invalid image format. Please use JPG, PNG, GIF, or WebP.';
                    $message_type = 'error';
                }
            }
            
            // Handle video upload
            if (isset($_FILES['video']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
                $video_tmp = $_FILES['video']['tmp_name'];
                $video_name = $_FILES['video']['name'];
                $video_ext = strtolower(pathinfo($video_name, PATHINFO_EXTENSION));
                $allowed_video_types = ['mp4', 'webm', 'ogg', 'avi', 'mov'];
                
                if (in_array($video_ext, $allowed_video_types)) {
                    $video_filename = 'event_video_' . time() . '_' . rand(1000, 9999) . '.' . $video_ext;
                    $video_path = $upload_dir . $video_filename;
                    
                    if (!move_uploaded_file($video_tmp, $video_path)) {
                        $message = 'Failed to upload video.';
                        $message_type = 'error';
                    }
                } else {
                    $message = 'Invalid video format. Please use MP4, WebM, OGG, AVI, or MOV.';
                    $message_type = 'error';
                }
            }
            
            // Insert into database if no errors
            if (empty($message)) {
                $stmt = $conn->prepare("INSERT INTO events_news (title, description, image_path, video_path, posted_by, hospital_name, state, city, hospital_id) VALUES (?, ?, ?, ?, 'hospital', ?, ?, ?, ?)");
                
                if ($stmt) {
                    $stmt->bind_param("sssssssi", $title, $description, $image_path, $video_path, $hospital_name, $hospital_state, $hospital_city, $hospital_id);
                    
                    if ($stmt->execute()) {
                        $message = 'Event/News posted successfully!';
                        $message_type = 'success';
                        
                        // Clear form data
                        $_POST = [];
                    } else {
                        $message = 'Database error: ' . $stmt->error;
                        $message_type = 'error';
                    }
                    $stmt->close();
                } else {
                    $message = 'Database preparation error: ' . $conn->error;
                    $message_type = 'error';
                }
            }
        }
    }
}

// Handle filter for recent events
$filter = $_GET['filter'] ?? 'all';
$custom_date = $_GET['custom_date'] ?? '';

// Build query based on filter
$where_clause = "WHERE hospital_id = ?";
$params = [$hospital_id];
$param_types = "i";

if ($filter === 'today') {
    $where_clause .= " AND DATE(created_at) = CURDATE()";
} elseif ($filter === 'custom' && !empty($custom_date)) {
    $where_clause .= " AND DATE(created_at) = ?";
    $params[] = $custom_date;
    $param_types .= "s";
}

// Fetch recent events for display (filter by hospital_id)
$recent_events = [];
$stmt = $conn->prepare("SELECT * FROM events_news $where_clause ORDER BY created_at DESC LIMIT 20");
if ($stmt) {
    $stmt->bind_param($param_types, ...$params);
    $stmt->execute();
    $result = $stmt->get_result();
    while ($row = $result->fetch_assoc()) {
        $recent_events[] = $row;
    }
    $stmt->close();
}

$conn->close();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin - Events & News Management</title>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #2563eb;
            --primary-light: #60a5fa;
            --primary-dark: #1e40af;
            --secondary: #10b981;
            --secondary-light: #34d399;
            --secondary-dark: #059669;
            --danger: #ef4444;
            --warning: #f59e0b;
            --success: #10b981;
            --info: #3b82f6;
            --dark: #0f172a;
            --light: #f8fafc;
            --gray: #94a3b8;
            --gray-light: #e2e8f0;
            --gray-dark: #475569;
            --sky-blue: #87CEEB;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            --radius-sm: 0.375rem;
            --radius-md: 0.75rem;
            --radius-lg: 1.5rem;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Plus Jakarta Sans', sans-serif;
        }

        body {
            background: var(--sky-blue);
            min-height: 100vh;
            color: var(--dark);
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }

        .header {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            font-size: 2.5rem;
            font-weight: 700;
            background: linear-gradient(to right, var(--primary), var(--secondary));
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 0.5rem;
        }

        .header p {
            color: var(--gray-dark);
            font-size: 1.1rem;
        }

        .hospital-info {
            background: rgba(16, 185, 129, 0.1);
            border: 1px solid rgba(16, 185, 129, 0.2);
            border-radius: var(--radius-md);
            padding: 1rem;
            margin-top: 1rem;
            color: var(--secondary-dark);
            font-weight: 500;
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 2rem;
        }

        .form-card, .events-card {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 2rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.1);
        }

        .card-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--dark);
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--dark);
        }

        .form-input, .form-textarea, .form-select {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 2px solid var(--gray-light);
            border-radius: var(--radius-md);
            font-size: 1rem;
            transition: var(--transition);
            background: white;
        }

        .form-input:focus, .form-textarea:focus, .form-select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.1);
        }

        .form-textarea {
            resize: vertical;
            min-height: 120px;
        }

        .file-input-wrapper {
            position: relative;
            display: inline-block;
            width: 100%;
        }

        .file-input {
            position: absolute;
            opacity: 0;
            width: 100%;
            height: 100%;
            cursor: pointer;
        }

        .file-input-display {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
            padding: 1rem;
            border: 2px dashed var(--gray-light);
            border-radius: var(--radius-md);
            background: var(--light);
            color: var(--gray-dark);
            font-weight: 500;
            transition: var(--transition);
            cursor: pointer;
        }

        .file-input-display:hover {
            border-color: var(--primary);
            background: rgba(37, 99, 235, 0.05);
            color: var(--primary);
        }

        .submit-btn {
            width: 100%;
            padding: 1rem 2rem;
            background: linear-gradient(to right, var(--primary), var(--primary-dark));
            color: white;
            border: none;
            border-radius: var(--radius-md);
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 0.75rem;
        }

        .submit-btn:hover {
            background: linear-gradient(to right, var(--primary-dark), var(--primary));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.3);
        }

        .alert {
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            margin-bottom: 1.5rem;
            font-weight: 500;
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .alert.success {
            background: rgba(16, 185, 129, 0.1);
            color: var(--secondary-dark);
            border: 1px solid rgba(16, 185, 129, 0.2);
        }

        .alert.error {
            background: rgba(239, 68, 68, 0.1);
            color: var(--danger);
            border: 1px solid rgba(239, 68, 68, 0.2);
        }

        .filter-section {
            margin-bottom: 1.5rem;
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }

        .filter-btn {
            padding: 0.5rem 1rem;
            border: 2px solid var(--gray-light);
            background: white;
            border-radius: var(--radius-md);
            cursor: pointer;
            transition: var(--transition);
            font-weight: 500;
            text-decoration: none;
            color: var(--gray-dark);
        }

        .filter-btn.active, .filter-btn:hover {
            border-color: var(--primary);
            background: var(--primary);
            color: white;
        }

        .custom-date-input {
            padding: 0.5rem;
            border: 2px solid var(--gray-light);
            border-radius: var(--radius-md);
            font-size: 0.9rem;
        }

        .events-list {
            max-height: 600px;
            overflow-y: auto;
        }

        .event-item {
            background: var(--light);
            border-radius: var(--radius-md);
            padding: 1.25rem;
            margin-bottom: 1rem;
            border: 1px solid var(--gray-light);
            transition: var(--transition);
            position: relative;
        }

        .event-item:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.1);
        }

        .event-title {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
            color: var(--dark);
        }

        .event-description {
            color: var(--gray-dark);
            margin-bottom: 1rem;
            line-height: 1.5;
        }

        .event-meta {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 0.875rem;
            color: var(--gray);
        }

        .event-author {
            display: flex;
            align-items: center;
            gap: 0.5rem;
            background: rgba(37, 99, 235, 0.1);
            padding: 0.25rem 0.75rem;
            border-radius: var(--radius-sm);
            color: var(--primary);
            font-weight: 500;
        }

        .event-location {
            font-size: 0.8rem;
            color: var(--gray);
            margin-top: 0.25rem;
        }

        .delete-btn {
            position: absolute;
            top: 1rem;
            right: 1rem;
            background: var(--danger);
            color: white;
            border: none;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 0.8rem;
            transition: var(--transition);
        }

        .delete-btn:hover {
            background: #dc2626;
            transform: scale(1.1);
        }

        .back-btn {
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.2);
            color: white;
            text-decoration: none;
            border-radius: var(--radius-md);
            font-weight: 500;
            transition: var(--transition);
            margin-bottom: 2rem;
        }

        .back-btn:hover {
            background: rgba(255, 255, 255, 0.3);
            transform: translateY(-2px);
        }

        /* Modal Styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            backdrop-filter: blur(5px);
        }

        .modal-content {
            background-color: white;
            margin: 15% auto;
            padding: 2rem;
            border-radius: var(--radius-lg);
            width: 90%;
            max-width: 400px;
            text-align: center;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.2);
        }

        .modal-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 1rem;
            color: var(--danger);
        }

        .modal-text {
            margin-bottom: 2rem;
            color: var(--gray-dark);
            line-height: 1.5;
        }

        .modal-buttons {
            display: flex;
            gap: 1rem;
            justify-content: center;
        }

        .modal-btn {
            padding: 0.75rem 1.5rem;
            border: none;
            border-radius: var(--radius-md);
            cursor: pointer;
            font-weight: 600;
            transition: var(--transition);
        }

        .modal-btn.confirm {
            background: var(--danger);
            color: white;
        }

        .modal-btn.confirm:hover {
            background: #dc2626;
        }

        .modal-btn.cancel {
            background: var(--gray-light);
            color: var(--gray-dark);
        }

        .modal-btn.cancel:hover {
            background: var(--gray);
            color: white;
        }

        @media (max-width: 768px) {
            .container {
                padding: 1rem;
            }

            .main-content {
                grid-template-columns: 1fr;
                gap: 1.5rem;
            }

            .header h1 {
                font-size: 2rem;
            }

            .filter-section {
                flex-direction: column;
                align-items: stretch;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <a href="admin_dashboard.php" class="back-btn">
            <i class="fas fa-arrow-left"></i>
            Back to Dashboard
        </a>

        <div class="header">
            <h1><i class="fas fa-newspaper"></i> Events & News Management</h1>
            <p>Create and manage healthcare events and news posts for the patient dashboard</p>
            <div class="hospital-info">
                <i class="fas fa-hospital"></i>
                <strong><?php echo htmlspecialchars($hospital_name); ?></strong> - 
                <?php echo htmlspecialchars($hospital_city); ?>, <?php echo htmlspecialchars($hospital_state); ?>
            </div>
        </div>

        <div class="main-content">
            <!-- Form Card -->
            <div class="form-card">
                <h2 class="card-title">
                    <i class="fas fa-plus-circle"></i>
                    Add New Event/News
                </h2>

                <?php if (!empty($message)): ?>
                    <div class="alert <?php echo $message_type; ?>">
                        <i class="fas fa-<?php echo $message_type === 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                        <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>

                <form method="POST" enctype="multipart/form-data" id="eventForm">
                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

                    <div class="form-group">
                        <label for="title" class="form-label">
                            <i class="fas fa-heading"></i> Title *
                        </label>
                        <input type="text" id="title" name="title" class="form-input" 
                               placeholder="Enter event/news title" required 
                               value="<?php echo htmlspecialchars($_POST['title'] ?? ''); ?>">
                    </div>

                    <div class="form-group">
                        <label for="description" class="form-label">
                            <i class="fas fa-align-left"></i> Description *
                        </label>
                        <textarea id="description" name="description" class="form-textarea" 
                                  placeholder="Enter detailed description" required><?php echo htmlspecialchars($_POST['description'] ?? ''); ?></textarea>
                    </div>

                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-image"></i> Event Image (Optional)
                        </label>
                        <div class="file-input-wrapper">
                            <input type="file" id="image" name="image" class="file-input" accept="image/*">
                            <div class="file-input-display">
                                <i class="fas fa-cloud-upload-alt"></i>
                                <span>Choose Image File</span>
                            </div>
                        </div>
                        <small style="color: var(--gray); margin-top: 0.5rem; display: block;">
                            Supported formats: JPG, PNG, GIF, WebP (Max 5MB)
                        </small>
                    </div>

                    <div class="form-group">
                        <label class="form-label">
                            <i class="fas fa-video"></i> Event Video (Optional)
                        </label>
                        <div class="file-input-wrapper">
                            <input type="file" id="video" name="video" class="file-input" accept="video/*">
                            <div class="file-input-display">
                                <i class="fas fa-film"></i>
                                <span>Choose Video File</span>
                            </div>
                        </div>
                        <small style="color: var(--gray); margin-top: 0.5rem; display: block;">
                            Supported formats: MP4, WebM, OGG, AVI, MOV (Max 50MB)
                        </small>
                    </div>

                    <button type="submit" name="submit_event" class="submit-btn">
                        <i class="fas fa-paper-plane"></i>
                        Publish Event/News
                    </button>
                </form>
            </div>

            <!-- Recent Events Card -->
            <div class="events-card">
                <h2 class="card-title">
                    <i class="fas fa-list"></i>
                    Recent Events & News
                </h2>

                <!-- Filter Section -->
                <div class="filter-section">
                    <a href="?filter=all" class="filter-btn <?php echo $filter === 'all' ? 'active' : ''; ?>">
                        <i class="fas fa-globe"></i> All Time
                    </a>
                    <a href="?filter=today" class="filter-btn <?php echo $filter === 'today' ? 'active' : ''; ?>">
                        <i class="fas fa-calendar-day"></i> Today
                    </a>
                    <form method="GET" style="display: flex; gap: 0.5rem; align-items: center;">
                        <input type="hidden" name="filter" value="custom">
                        <input type="date" name="custom_date" class="custom-date-input" 
                               value="<?php echo htmlspecialchars($custom_date); ?>" 
                               onchange="this.form.submit()">
                        <button type="submit" class="filter-btn <?php echo $filter === 'custom' ? 'active' : ''; ?>">
                            <i class="fas fa-calendar-alt"></i> Custom Date
                        </button>
                    </form>
                </div>

                <div class="events-list">
                    <?php if (empty($recent_events)): ?>
                        <div class="event-item">
                            <div class="event-title">No events found</div>
                            <div class="event-description">No events or news have been posted yet for the selected filter.</div>
                        </div>
                    <?php else: ?>
                        <?php foreach ($recent_events as $event): ?>
                            <div class="event-item">
                                <button class="delete-btn" onclick="showDeleteModal(<?php echo $event['id']; ?>)">
                                    <i class="fas fa-trash"></i>
                                </button>
                                <div class="event-title"><?php echo htmlspecialchars($event['title']); ?></div>
                                <div class="event-description">
                                    <?php echo htmlspecialchars(substr($event['description'], 0, 150)); ?>
                                    <?php if (strlen($event['description']) > 150): ?>...<?php endif; ?>
                                </div>
                                <div class="event-meta">
                                    <div>
                                        <div class="event-author">
                                            <i class="fas fa-hospital"></i> <?php echo htmlspecialchars($event['hospital_name']); ?>
                                        </div>
                                        <?php if (!empty($event['city']) && !empty($event['state'])): ?>
                                            <div class="event-location">
                                                <i class="fas fa-map-marker-alt"></i> 
                                                <?php echo htmlspecialchars($event['city'] . ', ' . $event['state']); ?>
                                            </div>
                                        <?php endif; ?>
                                    </div>
                                    <div class="event-date">
                                        <?php echo date('M j, Y g:i A', strtotime($event['created_at'])); ?>
                                    </div>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>

    <!-- Delete Confirmation Modal -->
    <div id="deleteModal" class="modal">
        <div class="modal-content">
            <div class="modal-title">
                <i class="fas fa-exclamation-triangle"></i>
                Confirm Delete
            </div>
            <div class="modal-text">
                Are you sure you want to delete this post? This action cannot be undone.
            </div>
            <div class="modal-buttons">
                <button class="modal-btn cancel" onclick="hideDeleteModal()">Cancel</button>
                <button class="modal-btn confirm" onclick="confirmDelete()">Delete</button>
            </div>
        </div>
    </div>

    <!-- Hidden form for delete -->
    <form id="deleteForm" method="POST" style="display: none;">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <input type="hidden" name="delete_post" value="1">
        <input type="hidden" name="post_id" id="deletePostId">
    </form>

    <script>
        let currentDeleteId = null;

        function showDeleteModal(postId) {
            currentDeleteId = postId;
            document.getElementById('deleteModal').style.display = 'block';
        }

        function hideDeleteModal() {
            document.getElementById('deleteModal').style.display = 'none';
            currentDeleteId = null;
        }

        function confirmDelete() {
            if (currentDeleteId) {
                document.getElementById('deletePostId').value = currentDeleteId;
                document.getElementById('deleteForm').submit();
            }
        }

        // Close modal when clicking outside
        window.onclick = function(event) {
            const modal = document.getElementById('deleteModal');
            if (event.target === modal) {
                hideDeleteModal();
            }
        }

        // Handle file input display
        const imageInput = document.getElementById('image');
        const videoInput = document.getElementById('video');

        imageInput.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'Choose Image File';
            this.nextElementSibling.querySelector('span').textContent = fileName;
        });

        videoInput.addEventListener('change', function() {
            const fileName = this.files[0]?.name || 'Choose Video File';
            this.nextElementSibling.querySelector('span').textContent = fileName;
        });

        // Form validation
        document.getElementById('eventForm').addEventListener('submit', function(e) {
            const title = document.getElementById('title').value.trim();
            const description = document.getElementById('description').value.trim();

            if (!title || !description) {
                e.preventDefault();
                alert('Please fill in all required fields.');
                return;
            }

            // File size validation
            const imageFile = imageInput.files[0];
            const videoFile = videoInput.files[0];

            if (imageFile && imageFile.size > 5 * 1024 * 1024) { // 5MB
                e.preventDefault();
                alert('Image file size must be less than 5MB.');
                return;
            }

            if (videoFile && videoFile.size > 50 * 1024 * 1024) { // 50MB
                e.preventDefault();
                alert('Video file size must be less than 50MB.');
                return;
            }
        });

        // Auto-hide success message after 5 seconds
        const successAlert = document.querySelector('.alert.success');
        if (successAlert) {
            setTimeout(() => {
                successAlert.style.opacity = '0';
                setTimeout(() => {
                    successAlert.remove();
                }, 300);
            }, 5000);
        }
    </script>
</body>
</html>
