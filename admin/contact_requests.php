<?php
session_start();

// Include database connection
include '../connection.php';

// Security headers
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src 'self' data:; frame-src https://www.google.com;");

// Check if hospital is logged in and hospital_id exists in session
if (!isset($_SESSION['hospital_id']) || !isset($_SESSION['csrf_token'])) {
    header("Location: hospital_login.php?error=session_expired");
    exit();
}

$hospital_id = $_SESSION['hospital_id'];

// Handle status update and reply submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // Verify CSRF token
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF token mismatch. Please refresh the page and try again.");
    }
    
    if ($_POST['action'] === 'update_status') {
        $contact_id = intval($_POST['contact_id']);
        $resolved = intval($_POST['resolved']);
        
        // Update contact status
        $stmt = $conn->prepare("UPDATE contacts_reports SET resolved = ? WHERE id = ? AND hospital_id = ?");
        $stmt->bind_param("iii", $resolved, $contact_id, $hospital_id);
        
        if ($stmt->execute()) {
            $success_message = $resolved ? "Contact marked as resolved!" : "Contact marked as unresolved!";
        } else {
            $error_message = "Failed to update contact status.";
        }
    }
    
    // NEW: Handle reply submission
    if ($_POST['action'] === 'reply_message') {
        $contact_id = intval($_POST['contact_id']);
        $reply_message = htmlspecialchars($_POST['reply_message'], ENT_QUOTES, 'UTF-8');
        
        if (!empty($reply_message)) {
            // Update contact with reply message and mark as resolved
            $stmt = $conn->prepare("UPDATE contacts_reports SET reply_message = ?, resolved = 1, replied_at = NOW() WHERE id = ? AND hospital_id = ?");
            $stmt->bind_param("sii", $reply_message, $contact_id, $hospital_id);
            
            if ($stmt->execute()) {
                $success_message = "Reply sent successfully!";
            } else {
                $error_message = "Failed to send reply.";
            }
        } else {
            $error_message = "Reply message cannot be empty.";
        }
    }
}

// Get hospital information
$stmt = $conn->prepare("SELECT hospital_name FROM hospitals WHERE id = ?");
$stmt->bind_param("i", $hospital_id);
$stmt->execute();
$hospital_result = $stmt->get_result();
$hospital_info = $hospital_result->fetch_assoc();

if (!$hospital_info) {
    header("Location: hospital_login.php?error=invalid_hospital");
    exit();
}

// Pagination setup
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 10;
$offset = ($page - 1) * $limit;

// Filter setup
$status_filter = isset($_GET['status']) ? $_GET['status'] : 'all';
$search_filter = isset($_GET['search']) ? trim($_GET['search']) : '';

// Build WHERE clause
$where_conditions = ["cr.hospital_id = ?"];
$params = [$hospital_id];
$param_types = "i";

if ($status_filter === 'resolved') {
    $where_conditions[] = "cr.resolved = 1";
} elseif ($status_filter === 'unresolved') {
    $where_conditions[] = "cr.resolved = 0";
}

if (!empty($search_filter)) {
    $where_conditions[] = "(cr.email LIKE ? OR cr.title LIKE ? OR cr.message LIKE ?)";
    $search_param = '%' . $search_filter . '%';
    $params = array_merge($params, [$search_param, $search_param, $search_param]);
    $param_types .= "sss";
}

$where_clause = "WHERE " . implode(" AND ", $where_conditions);

// Get total count for pagination
$count_query = "SELECT COUNT(*) as total FROM contacts_reports cr $where_clause";
$stmt = $conn->prepare($count_query);
if (!empty($params)) {
    $stmt->bind_param($param_types, ...$params);
}
$stmt->execute();
$total_result = $stmt->get_result();
$total_contacts = $total_result->fetch_assoc()['total'];
$total_pages = ceil($total_contacts / $limit);

// CORRECTED QUERY: Fixed the JOIN to avoid duplicates
$query = "SELECT DISTINCT cr.*, 
                 (SELECT p.first_name FROM patients p 
                  INNER JOIN patient_hospital ph ON p.id = ph.patient_id 
                  WHERE ph.hospital_id = cr.hospital_id 
                  AND cr.email = p.email 
                  LIMIT 1) as first_name,
                 (SELECT p.last_name FROM patients p 
                  INNER JOIN patient_hospital ph ON p.id = ph.patient_id 
                  WHERE ph.hospital_id = cr.hospital_id 
                  AND cr.email = p.email 
                  LIMIT 1) as last_name,
                 (SELECT p.phone FROM patients p 
                  INNER JOIN patient_hospital ph ON p.id = ph.patient_id 
                  WHERE ph.hospital_id = cr.hospital_id 
                  AND cr.email = p.email 
                  LIMIT 1) as patient_phone
          FROM contacts_reports cr 
          $where_clause 
          ORDER BY cr.created_at DESC 
          LIMIT ? OFFSET ?";

$params[] = $limit;
$params[] = $offset;
$param_types .= "ii";

$stmt = $conn->prepare($query);
$stmt->bind_param($param_types, ...$params);
$stmt->execute();
$contacts_result = $stmt->get_result();

// Generate new CSRF token
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Contact Requests - <?php echo htmlspecialchars($hospital_info['hospital_name']); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #2b6777;
            --primary-light: #c8d8e4;
            --primary-dark: #1a4c5d;
            --accent-color: #52ab98;
            --success-color: #4caf50;
            --error-color: #f44336;
            --warning-color: #ff9800;
            --info-color: #2196f3;
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
            color: var(--gray-800);
            line-height: 1.6;
            min-height: 100vh;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }

        .header {
            background: white;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .header h1 {
            color: var(--primary-color);
            font-size: 2rem;
            margin-bottom: 10px;
        }

        .header p {
            color: var(--gray-600);
            font-size: 1.1rem;
        }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .stat-card {
            background: white;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .stat-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
        }

        .stat-icon.total { color: var(--info-color); }
        .stat-icon.resolved { color: var(--success-color); }
        .stat-icon.unresolved { color: var(--warning-color); }

        .stat-number {
            font-size: 2rem;
            font-weight: 700;
            color: var(--gray-800);
            margin-bottom: 5px;
        }

        .stat-label {
            color: var(--gray-600);
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .filters-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .filters-grid {
            display: grid;
            grid-template-columns: 1fr 200px 120px;
            gap: 20px;
            align-items: end;
        }

        .form-group {
            display: flex;
            flex-direction: column;
        }

        .form-group label {
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--gray-700);
        }

        .form-control {
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

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 12px 20px;
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

        .btn-sm {
            padding: 8px 16px;
            font-size: 0.9rem;
        }

        .btn-success {
            background-color: var(--success-color);
        }

        .btn-success:hover {
            background-color: #45a049;
        }

        .btn-warning {
            background-color: var(--warning-color);
        }

        .btn-warning:hover {
            background-color: #e68900;
        }

        .contacts-section {
            background: white;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
        }

        .contacts-header {
            background: var(--primary-color);
            color: white;
            padding: 20px 25px;
        }

        .contacts-header h2 {
            font-size: 1.5rem;
            margin-bottom: 5px;
        }

        .contact-card {
            border-bottom: 1px solid var(--gray-200);
            padding: 25px;
            transition: background-color 0.3s ease;
        }

        .contact-card:hover {
            background-color: var(--gray-100);
        }

        .contact-card:last-child {
            border-bottom: none;
        }

        .contact-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 15px;
        }

        .contact-info {
            flex: 1;
            min-width: 300px;
        }

        .contact-title {
            font-size: 1.2rem;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 8px;
        }

        .contact-meta {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            color: var(--gray-600);
            font-size: 0.9rem;
            margin-bottom: 10px;
        }

        .contact-meta span {
            display: flex;
            align-items: center;
            gap: 5px;
        }

        .contact-actions {
            display: flex;
            gap: 10px;
            align-items: center;
            flex-wrap: wrap;
        }

        .status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        .status-resolved {
            background-color: rgba(76, 175, 80, 0.1);
            color: var(--success-color);
            border: 1px solid rgba(76, 175, 80, 0.3);
        }

        .status-unresolved {
            background-color: rgba(255, 152, 0, 0.1);
            color: var(--warning-color);
            border: 1px solid rgba(255, 152, 0, 0.3);
        }

        .contact-message {
            background: var(--gray-100);
            padding: 15px;
            border-radius: 8px;
            margin: 15px 0;
            border-left: 4px solid var(--primary-color);
        }

        /* NEW: Reply Section Styles */
        .reply-section {
            margin-top: 20px;
            padding: 20px;
            background: var(--gray-50);
            border-radius: 8px;
            border: 1px solid var(--gray-200);
        }

        .reply-form {
            display: none;
        }

        .reply-form.show {
            display: block;
        }

        .reply-textarea {
            width: 100%;
            min-height: 100px;
            padding: 12px;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            resize: vertical;
            font-family: 'Poppins', sans-serif;
            margin-bottom: 15px;
        }

        .reply-message {
            background: rgba(76, 175, 80, 0.1);
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid var(--success-color);
            margin-top: 15px;
        }

        .reply-meta {
            font-size: 0.8rem;
            color: var(--gray-600);
            margin-top: 10px;
        }

        .attachment-section {
            margin-top: 15px;
        }

        .attachment-link {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            color: var(--primary-color);
            text-decoration: none;
            padding: 8px 12px;
            background: var(--primary-light);
            border-radius: 6px;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }

        .attachment-link:hover {
            background: var(--primary-color);
            color: white;
        }

        .attachment-viewer {
            margin-top: 15px;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            overflow: hidden;
            display: none;
            background: white;
        }

        .attachment-viewer.show {
            display: block;
        }

        .attachment-header {
            background: var(--gray-100);
            padding: 10px 15px;
            border-bottom: 1px solid var(--gray-300);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .attachment-content {
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
        }

        .attachment-content img {
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
        }

        .attachment-content iframe {
            width: 100%;
            height: 400px;
            border: none;
            border-radius: 8px;
        }

        .attachment-content .text-content {
            background: var(--gray-100);
            padding: 15px;
            border-radius: 8px;
            font-family: monospace;
            white-space: pre-wrap;
            max-height: 300px;
            overflow-y: auto;
        }

        .attachment-content .unsupported {
            text-align: center;
            padding: 40px;
            color: var(--gray-500);
        }

        .close-viewer {
            background: var(--error-color);
            color: white;
            border: none;
            border-radius: 4px;
            padding: 5px 10px;
            cursor: pointer;
            font-size: 0.8rem;
        }

        .close-viewer:hover {
            background: #d32f2f;
        }

        .pagination {
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 10px;
            margin-top: 30px;
        }

        .pagination a, .pagination span {
            padding: 10px 15px;
            border: 1px solid var(--gray-300);
            border-radius: 6px;
            text-decoration: none;
            color: var(--gray-700);
            transition: all 0.3s ease;
        }

        .pagination a:hover {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        .pagination .current {
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }

        .alert {
            padding: 15px 20px;
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

        .no-contacts {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray-500);
        }

        .no-contacts i {
            font-size: 4rem;
            margin-bottom: 20px;
            opacity: 0.5;
        }

        @media (max-width: 768px) {
            .filters-grid {
                grid-template-columns: 1fr;
            }
            
            .contact-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .contact-actions {
                width: 100%;
                justify-content: flex-start;
            }
            
            .contact-meta {
                flex-direction: column;
                gap: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1><i class="fas fa-envelope"></i> Contact Requests</h1>
            <p>Manage contact requests for <strong><?php echo htmlspecialchars($hospital_info['hospital_name']); ?></strong></p>
        </div>

        <?php if (isset($success_message)): ?>
            <div class="alert alert-success">
                <i class="fas fa-check-circle"></i>
                <?php echo $success_message; ?>
            </div>
        <?php endif; ?>

        <?php if (isset($error_message)): ?>
            <div class="alert alert-error">
                <i class="fas fa-exclamation-circle"></i>
                <?php echo $error_message; ?>
            </div>
        <?php endif; ?>

        <!-- Statistics -->
        <?php
        // Get statistics
        $stats_query = "SELECT 
                          COUNT(*) as total,
                          SUM(CASE WHEN resolved = 1 THEN 1 ELSE 0 END) as resolved,
                          SUM(CASE WHEN resolved = 0 THEN 1 ELSE 0 END) as unresolved
                        FROM contacts_reports 
                        WHERE hospital_id = ?";
        $stmt = $conn->prepare($stats_query);
        $stmt->bind_param("i", $hospital_id);
        $stmt->execute();
        $stats = $stmt->get_result()->fetch_assoc();
        ?>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-icon total">
                    <i class="fas fa-envelope"></i>
                </div>
                <div class="stat-number"><?php echo $stats['total']; ?></div>
                <div class="stat-label">Total Requests</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon resolved">
                    <i class="fas fa-check-circle"></i>
                </div>
                <div class="stat-number"><?php echo $stats['resolved']; ?></div>
                <div class="stat-label">Resolved</div>
            </div>
            <div class="stat-card">
                <div class="stat-icon unresolved">
                    <i class="fas fa-clock"></i>
                </div>
                <div class="stat-number"><?php echo $stats['unresolved']; ?></div>
                <div class="stat-label">Pending</div>
            </div>
        </div>

        <!-- Filters -->
        <div class="filters-section">
            <form method="GET" action="">
                <div class="filters-grid">
                    <div class="form-group">
                        <label for="search">Search</label>
                        <input type="text" id="search" name="search" class="form-control" 
                               placeholder="Search by email, subject, or message..." 
                               value="<?php echo htmlspecialchars($search_filter); ?>">
                    </div>
                    <div class="form-group">
                        <label for="status">Status</label>
                        <select id="status" name="status" class="form-control">
                            <option value="all" <?php echo $status_filter === 'all' ? 'selected' : ''; ?>>All Requests</option>
                            <option value="unresolved" <?php echo $status_filter === 'unresolved' ? 'selected' : ''; ?>>Pending</option>
                            <option value="resolved" <?php echo $status_filter === 'resolved' ? 'selected' : ''; ?>>Resolved</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn">
                            <i class="fas fa-search"></i> Filter
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Contact Requests -->
        <div class="contacts-section">
            <div class="contacts-header">
                <h2><i class="fas fa-list"></i> Contact Requests</h2>
                <p>Showing <?php echo $contacts_result->num_rows; ?> of <?php echo $total_contacts; ?> requests</p>
            </div>

            <?php if ($contacts_result->num_rows > 0): ?>
                <?php $contact_counter = 0; ?>
                <?php while ($contact = $contacts_result->fetch_assoc()): ?>
                    <?php $contact_counter++; ?>
                    <div class="contact-card">
                        <div class="contact-header">
                            <div class="contact-info">
                                <div class="contact-title"><?php echo htmlspecialchars($contact['title']); ?></div>
                                <div class="contact-meta">
                                    <span><i class="fas fa-envelope"></i> <?php echo htmlspecialchars($contact['email']); ?></span>
                                    <?php if ($contact['first_name'] && $contact['last_name']): ?>
                                        <span><i class="fas fa-user"></i> <?php echo htmlspecialchars($contact['first_name'] . ' ' . $contact['last_name']); ?></span>
                                    <?php endif; ?>
                                    <?php if ($contact['patient_phone']): ?>
                                        <span><i class="fas fa-phone"></i> <?php echo htmlspecialchars($contact['patient_phone']); ?></span>
                                    <?php endif; ?>
                                    <span><i class="fas fa-calendar"></i> <?php echo date('M d, Y H:i', strtotime($contact['created_at'])); ?></span>
                                </div>
                            </div>
                            <div class="contact-actions">
                                <span class="status-badge <?php echo $contact['resolved'] ? 'status-resolved' : 'status-unresolved'; ?>">
                                    <?php echo $contact['resolved'] ? 'Resolved' : 'Pending'; ?>
                                </span>
                                <?php if (!$contact['resolved']): ?>
                                    <button type="button" class="btn btn-sm" onclick="toggleReplyForm(<?php echo $contact['id']; ?>)">
                                        <i class="fas fa-reply"></i> Reply
                                    </button>
                                <?php endif; ?>
                                <form method="POST" style="display: inline;">
                                    <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                    <input type="hidden" name="action" value="update_status">
                                    <input type="hidden" name="contact_id" value="<?php echo $contact['id']; ?>">
                                    <input type="hidden" name="resolved" value="<?php echo $contact['resolved'] ? 0 : 1; ?>">
                                    <button type="submit" class="btn btn-sm <?php echo $contact['resolved'] ? 'btn-warning' : 'btn-success'; ?>">
                                        <i class="fas <?php echo $contact['resolved'] ? 'fa-undo' : 'fa-check'; ?>"></i>
                                        <?php echo $contact['resolved'] ? 'Mark Pending' : 'Mark Resolved'; ?>
                                    </button>
                                </form>
                            </div>
                        </div>

                        <div class="contact-message">
                            <?php echo nl2br(htmlspecialchars($contact['message'])); ?>
                        </div>

                        <?php if ($contact['attachment']): ?>
                            <?php
                            $attachment_path = "../" . $contact['attachment'];
                            $file_extension = strtolower(pathinfo($contact['attachment'], PATHINFO_EXTENSION));
                            $filename = basename($contact['attachment']);
                            ?>
                            <div class="attachment-section">
                                <div class="attachment-link" onclick="toggleAttachmentViewer(<?php echo $contact_counter; ?>, '<?php echo htmlspecialchars($attachment_path); ?>', '<?php echo $file_extension; ?>', '<?php echo htmlspecialchars($filename); ?>')">
                                    <i class="fas fa-paperclip"></i>
                                    View Attachment: <?php echo htmlspecialchars($filename); ?>
                                </div>
                                
                                <div class="attachment-viewer" id="viewer-<?php echo $contact_counter; ?>">
                                    <div class="attachment-header">
                                        <span><i class="fas fa-file"></i> <?php echo htmlspecialchars($filename); ?></span>
                                        <button class="close-viewer" onclick="closeAttachmentViewer(<?php echo $contact_counter; ?>)">
                                            <i class="fas fa-times"></i> Close
                                        </button>
                                    </div>
                                    <div class="attachment-content" id="content-<?php echo $contact_counter; ?>">
                                        <!-- Content will be loaded here -->
                                    </div>
                                </div>
                            </div>
                        <?php endif; ?>

                        <!-- NEW: Reply Section -->
                        <div class="reply-section">
                            <?php if ($contact['reply_message']): ?>
                                <div class="reply-message">
                                    <strong><i class="fas fa-reply"></i> Hospital Reply:</strong>
                                    <p><?php echo nl2br(htmlspecialchars($contact['reply_message'])); ?></p>
                                    <div class="reply-meta">
                                        Replied on: <?php echo $contact['replied_at'] ? date('M d, Y H:i', strtotime($contact['replied_at'])) : 'N/A'; ?>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <?php if (!$contact['resolved']): ?>
                                <div class="reply-form" id="reply-form-<?php echo $contact['id']; ?>">
                                    <form method="POST">
                                        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                                        <input type="hidden" name="action" value="reply_message">
                                        <input type="hidden" name="contact_id" value="<?php echo $contact['id']; ?>">
                                        <textarea name="reply_message" class="reply-textarea" placeholder="Type your reply here..." required></textarea>
                                        <div style="display: flex; gap: 10px;">
                                            <button type="submit" class="btn btn-sm btn-success">
                                                <i class="fas fa-paper-plane"></i> Send Reply
                                            </button>
                                            <button type="button" class="btn btn-sm btn-warning" onclick="toggleReplyForm(<?php echo $contact['id']; ?>)">
                                                <i class="fas fa-times"></i> Cancel
                                            </button>
                                        </div>
                                    </form>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>
                <?php endwhile; ?>
            <?php else: ?>
                <div class="no-contacts">
                    <i class="fas fa-inbox"></i>
                    <h3>No contact requests found</h3>
                    <p>There are no contact requests matching your current filters.</p>
                </div>
            <?php endif; ?>
        </div>

        <!-- Pagination -->
        <?php if ($total_pages > 1): ?>
            <div class="pagination">
                <?php if ($page > 1): ?>
                    <a href="?page=<?php echo $page - 1; ?>&status=<?php echo $status_filter; ?>&search=<?php echo urlencode($search_filter); ?>">
                        <i class="fas fa-chevron-left"></i> Previous
                    </a>
                <?php endif; ?>

                <?php for ($i = max(1, $page - 2); $i <= min($total_pages, $page + 2); $i++): ?>
                    <?php if ($i == $page): ?>
                        <span class="current"><?php echo $i; ?></span>
                    <?php else: ?>
                        <a href="?page=<?php echo $i; ?>&status=<?php echo $status_filter; ?>&search=<?php echo urlencode($search_filter); ?>"><?php echo $i; ?></a>
                    <?php endif; ?>
                <?php endfor; ?>

                <?php if ($page < $total_pages): ?>
                    <a href="?page=<?php echo $page + 1; ?>&status=<?php echo $status_filter; ?>&search=<?php echo urlencode($search_filter); ?>">
                        Next <i class="fas fa-chevron-right"></i>
                    </a>
                <?php endif; ?>
            </div>
        <?php endif; ?>
    </div>

    <script>
        // NEW: Reply form toggle function
        function toggleReplyForm(contactId) {
            const replyForm = document.getElementById('reply-form-' + contactId);
            if (replyForm.classList.contains('show')) {
                replyForm.classList.remove('show');
            } else {
                // Hide all other reply forms
                document.querySelectorAll('.reply-form').forEach(form => {
                    form.classList.remove('show');
                });
                // Show this reply form
                replyForm.classList.add('show');
            }
        }

        function toggleAttachmentViewer(contactId, filePath, fileExtension, fileName) {
            const viewer = document.getElementById('viewer-' + contactId);
            const content = document.getElementById('content-' + contactId);
            
            if (viewer.classList.contains('show')) {
                viewer.classList.remove('show');
                return;
            }
            
            // Show viewer
            viewer.classList.add('show');
            
            // Load content based on file type
            loadAttachmentContent(content, filePath, fileExtension, fileName);
        }
        
        function closeAttachmentViewer(contactId) {
            const viewer = document.getElementById('viewer-' + contactId);
            viewer.classList.remove('show');
        }
        
        function loadAttachmentContent(contentElement, filePath, fileExtension, fileName) {
            contentElement.innerHTML = '<div style="text-align: center; padding: 20px;"><i class="fas fa-spinner fa-spin"></i> Loading...</div>';
            
            switch (fileExtension) {
                case 'jpg':
                case 'jpeg':
                case 'png':
                case 'gif':
                    // FIXED: Proper error handling for images
                    const img = new Image();
                    img.onload = function() {
                        contentElement.innerHTML = `<img src="${filePath}" alt="${fileName}">`;
                    };
                    img.onerror = function() {
                        contentElement.innerHTML = `
                            <div class="unsupported">
                                <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: #f44336; margin-bottom: 15px;"></i>
                                <h3>Error Loading Image</h3>
                                <p>The image file could not be loaded or is corrupted.</p>
                                <a href="${filePath}" download="${fileName}" class="btn" style="margin-top: 15px;">
                                    <i class="fas fa-download"></i> Download File
                                </a>
                            </div>
                        `;
                    };
                    img.src = filePath;
                    break;
                    
                case 'pdf':
                    contentElement.innerHTML = `<iframe src="${filePath}" type="application/pdf"></iframe>`;
                    break;
                    
                case 'txt':
                    fetch(filePath)
                        .then(response => {
                            if (!response.ok) throw new Error('File not found');
                            return response.text();
                        })
                        .then(text => {
                            contentElement.innerHTML = `<div class="text-content">${escapeHtml(text)}</div>`;
                        })
                        .catch(error => {
                            contentElement.innerHTML = `
                                <div class="unsupported">
                                    <i class="fas fa-exclamation-triangle" style="font-size: 3rem; color: #f44336; margin-bottom: 15px;"></i>
                                    <h3>Error Loading Text File</h3>
                                    <p>The text file could not be loaded.</p>
                                    <a href="${filePath}" download="${fileName}" class="btn" style="margin-top: 15px;">
                                        <i class="fas fa-download"></i> Download File
                                    </a>
                                </div>
                            `;
                        });
                    break;
                    
                case 'doc':
                case 'docx':
                    contentElement.innerHTML = `
                        <div class="unsupported">
                            <i class="fas fa-file-word" style="font-size: 3rem; color: #2b579a; margin-bottom: 15px;"></i>
                            <h3>Word Document</h3>
                            <p>Preview not available for Word documents.</p>
                            <a href="${filePath}" download="${fileName}" class="btn" style="margin-top: 15px;">
                                <i class="fas fa-download"></i> Download File
                            </a>
                        </div>
                    `;
                    break;
                    
                default:
                    contentElement.innerHTML = `
                        <div class="unsupported">
                            <i class="fas fa-file" style="font-size: 3rem; color: #666; margin-bottom: 15px;"></i>
                            <h3>File Preview Not Available</h3>
                            <p>This file type (${fileExtension.toUpperCase()}) cannot be previewed.</p>
                            <a href="${filePath}" download="${fileName}" class="btn" style="margin-top: 15px;">
                                <i class="fas fa-download"></i> Download File
                            </a>
                        </div>
                    `;
            }
        }
        
        function escapeHtml(text) {
            const map = {
                '&': '&amp;',
                '<': '&lt;',
                '>': '&gt;',
                '"': '&quot;',
                "'": '&#039;'
            };
            return text.replace(/[&<>"']/g, function(m) { return map[m]; });
        }
        
        // Close viewer when clicking outside
        document.addEventListener('click', function(e) {
            if (e.target.classList.contains('attachment-viewer')) {
                e.target.classList.remove('show');
            }
        });
    </script>
</body>
</html>
