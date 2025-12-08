<?php
include '../connection.php';
session_start();

if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'patient') {
    header("Location: ../login.php");
    exit;
}

$patient_id = $_SESSION['user_id'];
$first_name = "Unknown";
$last_name = "Patient";
$success_message = "";
$error_message = "";

// Fetch patient information
$sql_patient = "SELECT first_name, last_name, profile_picture FROM patients WHERE id = ?";
$stmt_patient = $conn->prepare($sql_patient);
$stmt_patient->bind_param("i", $patient_id);
$stmt_patient->execute();
$result_patient = $stmt_patient->get_result();
$patient = $result_patient->fetch_assoc();
$stmt_patient->close();

if ($patient) {
    $first_name = $patient['first_name'] ?? "Unknown";
    $last_name = $patient['last_name'] ?? "Patient";
    $profile_picture = $patient['profile_picture'] ?? "default-avatar.png";
}

// Handle PDF view request - MODIFIED to remove ../patient/ from path
if (isset($_GET['view_pdf']) && is_numeric($_GET['view_pdf'])) {
    $immunization_id = $_GET['view_pdf'];
    
    // Fetch the PDF file path for the specific immunization
    $sql = "SELECT pdf_file, vaccine_type, immunization_date FROM immunizations WHERE id = ? AND patient_id = ? AND status = 'completed'";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $immunization_id, $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $pdf_file_path = $row['pdf_file'];
        
        // Remove ../patient/ from the path
        $pdf_file_path = str_replace('../patient/', '', $pdf_file_path);
        
        // Check if file exists
        if (file_exists($pdf_file_path)) {
            // Read PDF file content
            $pdf_content = file_get_contents($pdf_file_path);
            
            // Output PDF content
            header('Content-Type: application/pdf');
            header('Content-Length: ' . strlen($pdf_content));
            echo $pdf_content;
            exit;
        } else {
            echo "PDF file not found on server.";
            exit;
        }
    } else {
        echo "PDF not found or you don't have permission to view it.";
        exit;
    }
}

// Handle PDF download request - MODIFIED to remove ../patient/ from path and create custom filename
if (isset($_GET['download_pdf']) && is_numeric($_GET['download_pdf'])) {
    $immunization_id = $_GET['download_pdf'];
    
    // Fetch the PDF file path, vaccine type, and immunization date for the specific immunization
    $sql = "SELECT pdf_file, vaccine_type, immunization_date FROM immunizations WHERE id = ? AND patient_id = ? AND status = 'completed'";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("ii", $immunization_id, $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows > 0) {
        $row = $result->fetch_assoc();
        $pdf_file_path = $row['pdf_file'];
        $vaccine_type = $row['vaccine_type'];
        $immunization_date = $row['immunization_date'];
        
        // Remove ../patient/ from the path
        $pdf_file_path = str_replace('../patient/', '', $pdf_file_path);
        
        // Check if file exists
        if (file_exists($pdf_file_path)) {
            // Read PDF file content
            $pdf_content = file_get_contents($pdf_file_path);
            
            // Create custom filename: vaccinetype_patientname_date.pdf
            $safe_vaccine_type = preg_replace('/[^a-zA-Z0-9_-]/', '', $vaccine_type);
            $safe_patient_name = preg_replace('/[^a-zA-Z0-9_-]/', '', $first_name . '_' . $last_name);
            $formatted_date = date('Y-m-d', strtotime($immunization_date));
            $filename = $safe_vaccine_type . '_' . $safe_patient_name . '_' . $formatted_date . '.pdf';
            
            // Output PDF content for download
            header('Content-Type: application/pdf');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            header('Content-Length: ' . strlen($pdf_content));
            echo $pdf_content;
            exit;
        } else {
            echo "PDF file not found on server.";
            exit;
        }
    } else {
        echo "PDF not found or you don't have permission to download it.";
        exit;
    }
}

// Handle immunization cancellation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cancel_immunization'])) {
    $immunization_id = $conn->real_escape_string($_POST['immunization_id']);
    $cancel_reason = $conn->real_escape_string($_POST['cancel_reason']);
    
    // Start transaction
    $conn->begin_transaction();
    
    try {
        // Update the immunization record - MODIFIED to allow canceling scheduled appointments
        $sql_cancel = "UPDATE immunizations SET 
                      status = 'canceled', 
                      canceled_date = NOW(), 
                      notes = CONCAT(IFNULL(notes, ''), '\n\nCancellation Reason: ', ?) 
                      WHERE id = ? AND patient_id = ? AND (status = 'pending' OR (schedule IS NOT NULL AND status != 'completed'))";
        
        $stmt_cancel = $conn->prepare($sql_cancel);
        $stmt_cancel->bind_param("sii", $cancel_reason, $immunization_id, $patient_id);
        $stmt_cancel->execute();
        
        if ($stmt_cancel->affected_rows > 0) {
            $success_message = "Your immunization request has been canceled successfully.";
            $conn->commit();
        } else {
            $error_message = "Unable to cancel the request. It may have already been processed.";
            $conn->rollback();
        }
        
        $stmt_cancel->close();
    } catch (Exception $e) {
        $conn->rollback();
        $error_message = "Error canceling request: " . $e->getMessage();
    }
    
    // Redirect to prevent form resubmission on refresh
    header("Location: patient_medi_report.php?cancel_success=1");
    exit;
}

// Handle immunization request submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_immunization'])) {
    $vaccine_type = $conn->real_escape_string($_POST['vaccine_type']);
    $notes = $conn->real_escape_string($_POST['notes']);
    
    // Check if hospital_id exists in the POST data
    if (isset($_POST['hospital_id']) && !empty($_POST['hospital_id'])) {
        $hospital_id = $conn->real_escape_string($_POST['hospital_id']);
        
        // Verify the hospital exists before inserting
        $check_hospital = "SELECT id FROM hospitals WHERE id = ?";
        $stmt_check = $conn->prepare($check_hospital);
        $stmt_check->bind_param("i", $hospital_id);
        $stmt_check->execute();
        $result_check = $stmt_check->get_result();
        
        if ($result_check->num_rows === 0) {
            $error_message = "The selected hospital does not exist in our database.";
        } else {
            // Check for existing pending request for the same vaccine type and hospital
            $check_duplicate = "SELECT i.id, h.hospital_name FROM immunizations i 
                               JOIN hospitals h ON i.hospital_id = h.id 
                               WHERE i.patient_id = ? AND i.vaccine_type = ? AND i.hospital_id = ? AND i.status = 'pending'";
            $stmt_duplicate = $conn->prepare($check_duplicate);
            $stmt_duplicate->bind_param("isi", $patient_id, $vaccine_type, $hospital_id);
            $stmt_duplicate->execute();
            $result_duplicate = $stmt_duplicate->get_result();
            
            if ($result_duplicate->num_rows > 0) {
                $duplicate = $result_duplicate->fetch_assoc();
                $error_message = "Your application for {$vaccine_type} vaccine is still pending at {$duplicate['hospital_name']}. Please wait for it to be processed.";
            } else {
                // Check for recently canceled requests (within 7 days)
                $check_canceled = "SELECT i.id, h.hospital_name, DATEDIFF(NOW(), i.canceled_date) as days_since_cancel 
                                  FROM immunizations i 
                                  JOIN hospitals h ON i.hospital_id = h.id 
                                  WHERE i.patient_id = ? AND i.vaccine_type = ? AND i.hospital_id = ? 
                                  AND i.status = 'canceled' AND i.canceled_date IS NOT NULL 
                                  AND DATEDIFF(NOW(), i.canceled_date) < 7
                                  ORDER BY i.canceled_date DESC LIMIT 1";
                $stmt_canceled = $conn->prepare($check_canceled);
                $stmt_canceled->bind_param("isi", $patient_id, $vaccine_type, $hospital_id);
                $stmt_canceled->execute();
                $result_canceled = $stmt_canceled->get_result();
                
                if ($result_canceled->num_rows > 0) {
                    $canceled = $result_canceled->fetch_assoc();
                    $days_remaining = 7 - $canceled['days_since_cancel'];
                    $error_message = "You recently canceled a request for {$vaccine_type} vaccine at {$canceled['hospital_name']}. You must wait {$days_remaining} more day(s) before submitting a new request for the same vaccine at this hospital.";
                } else {
                    // Start transaction
                    $conn->begin_transaction();
                    
                    try {
                        // Insert into immunizations table
                        $sql = "INSERT INTO immunizations (patient_id, vaccine_type, notes, request_date, status, hospital_id) 
                                VALUES (?, ?, ?, NOW(), 'pending', ?)";
                        
                        $stmt = $conn->prepare($sql);
                        $stmt->bind_param("issi", $patient_id, $vaccine_type, $notes, $hospital_id);
                        
                        if ($stmt->execute()) {
                            // Get the immunization_id that was just inserted
                            $immunization_id = $conn->insert_id;
                            
                            // Insert into allergies table
                            $allergy_sql = "INSERT INTO allergies (immunization_id, patient_id, hospital_id) VALUES (?, ?, ?)";
                            $stmt_allergy = $conn->prepare($allergy_sql);
                            $stmt_allergy->bind_param("iii", $immunization_id, $patient_id, $hospital_id);
                            $stmt_allergy->execute();
                            $stmt_allergy->close();
                            
                            // Insert into lab_results table
                            $lab_sql = "INSERT INTO labresults (immunization_id, patient_id, hospital_id) VALUES (?, ?, ?)";
                            $stmt_lab = $conn->prepare($lab_sql);
                            $stmt_lab->bind_param("iii", $immunization_id, $patient_id, $hospital_id);
                            $stmt_lab->execute();
                            $stmt_lab->close();
                            
                            $conn->commit();
                            // Redirect to prevent form resubmission on refresh
                            header("Location: patient_medi_report.php?success=1");
                            exit;
                        } else {
                            $conn->rollback();
                            $error_message = "Error submitting request: " . $conn->error;
                        }
                        
                        $stmt->close();
                    } catch (Exception $e) {
                        $conn->rollback();
                        $error_message = "Error submitting request: " . $e->getMessage();
                    }
                }
                $stmt_canceled->close();
            }
            $stmt_duplicate->close();
        }
        $stmt_check->close();
    } else {
        $error_message = "Please select a hospital for your request.";
    }
}

// Handle success message from redirect
if (isset($_GET['success']) && $_GET['success'] == 1) {
    $success_message = "Your immunization request has been submitted successfully. A receptionist will schedule a date and time based on doctor availability.";
}

// Handle cancel success message from redirect
if (isset($_GET['cancel_success']) && $_GET['cancel_success'] == 1) {
    $success_message = "Your immunization request has been canceled successfully.";
}

// AJAX endpoint for hospital search
if (isset($_GET['search_hospital'])) {
    $search = '%' . $conn->real_escape_string($_GET['search_hospital']) . '%';
    $sql = "SELECT id, hospital_name, city, zipcode FROM hospitals 
            WHERE hospital_name LIKE ? OR city LIKE ? OR zipcode LIKE ? 
            ORDER BY hospital_name ASC LIMIT 10";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sss", $search, $search, $search);
    $stmt->execute();
    $result = $stmt->get_result();
    
    $hospitals = [];
    while ($row = $result->fetch_assoc()) {
        $hospitals[] = $row;
    }
    
    header('Content-Type: application/json');
    echo json_encode($hospitals);
    exit;
}

// Fetch existing immunization requests with hospital information
$sql_immunizations = "SELECT i.*, h.hospital_name, h.city as hospital_city, h.zipcode as hospital_zipcode, 
                     i.comments, i.immunization_date, i.pdf_file,
                     DATEDIFF(NOW(), i.canceled_date) as days_since_cancel,
                     CASE
                         WHEN i.status = 'canceled' THEN 'canceled'
                         WHEN i.status = 'completed' THEN 'completed'
                         WHEN i.status = 'pending' THEN 'pending'
                         WHEN i.status = 'scheduled' AND i.attended = 1 THEN 'attended'
                         WHEN i.status = 'scheduled' THEN 'scheduled'
                         WHEN i.status = 'overdue' THEN 'overdue'
                         ELSE i.status
                     END as display_status

                     FROM immunizations i 
                     LEFT JOIN hospitals h ON i.hospital_id = h.id 
                     WHERE i.patient_id = ? 
                     ORDER BY i.request_date DESC";

$stmt_immunizations = $conn->prepare($sql_immunizations);
$stmt_immunizations->bind_param("i", $patient_id);
$stmt_immunizations->execute();
$result_immunizations = $stmt_immunizations->get_result();
$immunizations = [];

while ($row = $result_immunizations->fetch_assoc()) {
    $immunizations[] = $row;
}
$stmt_immunizations->close();

$conn->close();
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Medical Reports - Healthcare Portal</title>
    <!-- Google Fonts -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <!-- FontAwesome for icons -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
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

        /* Main Content Styles - Improved for 2025 */
        .main-content {
            flex: 1;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }

        /* Header Styles - Simplified */
        .header {
            background: rgba(15, 23, 42, 0.75);
            backdrop-filter: blur(12px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
            padding: 1.5rem 2rem;
            position: sticky;
            top: 0;
            z-index: 50;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .header-title {
            font-size: 1.75rem;
            font-weight: 700;
            color: var(--light);
            background: linear-gradient(to right, #fff, #60a5fa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .header-actions {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .user-info {
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }

        .user-avatar {
            width: 40px;
            height: 40px;
            border-radius: var(--radius-full);
            object-fit: cover;
            border: 2px solid var(--primary-light);
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
        }

        /* Medical Reports Content */
        .medi-reports {
            padding: 2.5rem;
            flex: 1;
            background: transparent;
            color: var(--light);
        }

        .medi-reports-title {
            margin-bottom: 2rem;
            position: relative;
            padding-left: 1.25rem;
        }

        .medi-reports-title::before {
            content: '';
            position: absolute;
            left: 0;
            top: 0.5rem;
            height: 80%;
            width: 4px;
            background: linear-gradient(to bottom, var(--primary), var(--secondary));
            border-radius: 4px;
        }

        .medi-reports-heading {
            font-size: 2.25rem;
            font-weight: 700;
            margin-bottom: 0.75rem;
            background: linear-gradient(to right, #fff, #60a5fa);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .medi-reports-subheading {
            font-size: 1.1rem;
            color: rgba(255, 255, 255, 0.8);
        }

        /* New 30/70 Split Layout */
        .reports-container {
            display: flex;
            gap: 2rem;
        }

        /* Immunization Request Form - 30% */
        .immunization-request {
            flex: 0 0 30%;
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 2rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
            height: fit-content;
        }

        .immunization-request::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--primary), var(--accent));
        }

        .immunization-request-title {
            font-size: 1.5rem;
            font-weight: 600;
            margin-bottom: 1.5rem;
            color: var(--light);
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        .form-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--light);
        }

        .form-control {
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: var(--radius-md);
            color: var(--light);
            font-size: 1rem;
            transition: var(--transition);
        }

        /* Specific styling for select dropdown */
        select.form-control {
            background-color: rgba(37, 99, 235, 0.2);
            color: white;
            border-color: rgba(96, 165, 250, 0.4);
            appearance: none;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="12" height="6"><path d="M0 0l6 6 6-6z" fill="white"/></svg>');
            background-repeat: no-repeat;
            background-position: right 1rem center;
            padding-right: 2.5rem;
        }

        select.form-control option {
            background-color: var(--dark-light);
            color: white;
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .form-control::placeholder {
            color: rgba(255, 255, 255, 0.5);
        }

        .form-textarea {
            min-height: 120px;
            resize: vertical;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            font-weight: 600;
            cursor: pointer;
            transition: var(--transition);
            border: none;
            font-size: 1rem;
        }

        .btn-primary {
            background: linear-gradient(to right, var(--primary), var(--primary-dark));
            color: var(--light);
            box-shadow: 0 4px 15px rgba(37, 99, 235, 0.3);
        }

        .btn-primary:hover {
            background: linear-gradient(to right, var(--primary-dark), var(--primary));
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(37, 99, 235, 0.4);
        }

        .btn-danger {
            background: linear-gradient(to right, var(--danger), #b91c1c);
            color: var(--light);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
            cursor: pointer !important;
        }

        .btn-danger:hover {
            background: linear-gradient(to right, #b91c1c, var(--danger));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(239, 68, 68, 0.4);
        }

        .btn-block {
            width: 100%;
        }

        /* Immunization History Cards - 70% */
        .immunization-history {
            flex: 0 0 70%;
            display: flex;
            flex-direction: column;
            gap: 1.5rem;
        }

        .immunization-card {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 1.5rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
            overflow: hidden;
            transition: var(--transition);
        }

        .immunization-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
        }

        .immunization-card::after {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.1), transparent);
            opacity: 0;
            transition: var(--transition);
        }

        .immunization-card:hover::after {
            opacity: 1;
        }

        .immunization-card.pending::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--warning), #fbbf24);
        }

        .immunization-card.completed::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--success), var(--secondary-light));
        }

        .immunization-card.canceled::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--danger), #b91c1c);
        }

        .immunization-card.overdue::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, #7c3aed, #c026d3);
        }

        .immunization-card.scheduled::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--info), var(--primary-light));
        }

        .immunization-card-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 1rem;
        }

        .immunization-type {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--light);
        }

        .immunization-status {
            padding: 0.35rem 0.75rem;
            border-radius: var(--radius-full);
            font-size: 0.875rem;
            font-weight: 500;
        }

        .status-pending {
            background: rgba(245, 158, 11, 0.15);
            color: var(--warning);
        }

        .status-completed {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
        }

        .status-canceled {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
        }

        .status-overdue {
            background: rgba(124, 58, 237, 0.15);
            color: #7c3aed;
        }

        .status-scheduled {
            background: rgba(59, 130, 246, 0.15);
            color: var(--info);
        }

        /* Two-column layout for immunization details */
        .immunization-content {
            display: flex;
            gap: 1.5rem;
        }

        .immunization-left-column {
            flex: 1;
        }

        .immunization-right-column {
            flex: 1;
            border-left: 1px solid rgba(255, 255, 255, 0.1);
            padding-left: 1.5rem;
        }

        .immunization-details {
            margin-bottom: 1rem;
        }

        .immunization-detail {
            display: flex;
            margin-bottom: 0.5rem;
        }

        .detail-label {
            width: 120px;
            color: var(--gray);
            font-size: 0.9375rem;
        }

        .detail-value {
            flex: 1;
            color: var(--light);
            font-size: 0.9375rem;
        }

        .immunization-notes {
            background: rgba(255, 255, 255, 0.05);
            padding: 1rem;
            border-radius: var(--radius-md);
            margin-top: 1rem;
        }

        .notes-title {
            font-size: 0.9375rem;
            font-weight: 600;
            color: var(--gray);
            margin-bottom: 0.5rem;
        }

        .notes-content {
            font-size: 0.9375rem;
            color: var(--light);
            line-height: 1.5;
        }

        .immunization-actions {
            display: flex;
            justify-content: flex-end;
            margin-top: 1rem;
        }

        /* Alert Messages */
        .alert {
            padding: 1rem 1.5rem;
            border-radius: var(--radius-md);
            margin-bottom: 1.5rem;
            font-weight: 500;
        }

        .alert-success {
            background: rgba(16, 185, 129, 0.15);
            color: var(--success);
            border-left: 4px solid var(--success);
        }

        .alert-error {
            background: rgba(239, 68, 68, 0.15);
            color: var(--danger);
            border-left: 4px solid var(--danger);
        }

        /* Hospital Search Styling */
        .hospital-search-container {
            position: relative;
        }

        .hospital-search-input {
            width: 100%;
            padding: 0.875rem 1rem;
            background: rgba(37, 99, 235, 0.2);
            border: 1px solid rgba(96, 165, 250, 0.4);
            border-radius: var(--radius-md);
            color: var(--light);
            font-size: 1rem;
            transition: var(--transition);
        }

        .hospital-search-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .hospital-search-results {
            position: absolute;
            top: 100%;
            left: 0;
            width: 100%;
            max-height: 250px;
            overflow-y: auto;
            background: rgba(37, 99, 235, 0.15);
            border: 1px solid rgba(96, 165, 250, 0.2);
            border-radius: var(--radius-md);
            z-index: 10;
            display: none;
        }

        .hospital-search-results.active {
            display: block;
        }

        .hospital-result-item {
            padding: 0.75rem 1rem;
            cursor: pointer;
            transition: var(--transition);
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
        }

        .hospital-result-item:last-child {
            border-bottom: none;
        }

        .hospital-result-item:hover {
            background: rgba(37, 99, 235, 0.25);
        }

        .hospital-result-name {
            font-weight: 600;
            color: var(--primary-light);
            margin-bottom: 0.25rem;
        }

        .hospital-result-details {
            font-size: 0.8125rem;
            color: var(--light);
        }

        .selected-hospital {
            margin-top: 0.75rem;
            padding: 0.75rem 1rem;
            background: rgba(37, 99, 235, 0.1);
            border: 1px solid rgba(37, 99, 235, 0.2);
            border-radius: var(--radius-md);
            display: none;
        }

        .selected-hospital.active {
            display: block;
        }

        .selected-hospital-name {
            font-weight: 600;
            color: var(--primary-light);
            margin-bottom: 0.25rem;
        }

        .selected-hospital-details {
            font-size: 0.875rem;
            color: var(--light);
        }

        .selected-hospital-remove {
            color: var(--danger);
            background: none;
            border: none;
            cursor: pointer;
            font-size: 0.875rem;
            margin-top: 0.5rem;
            padding: 0;
            display: flex;
            align-items: center;
            gap: 0.25rem;
        }

        /* Modal Styling */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(15, 23, 42, 0.8);
            backdrop-filter: blur(5px);
            z-index: 100;
            display: flex;
            justify-content: center;
            align-items: center;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s ease;
        }

        .modal-overlay.active {
            opacity: 1;
            visibility: visible;
        }

        .modal {
            background: rgba(30, 41, 59, 0.95);
            border-radius: var(--radius-lg);
            width: 90%;
            max-width: 500px;
            padding: 2rem;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            transform: translateY(20px);
            opacity: 0;
            transition: all 0.3s ease;
            border: 1px solid rgba(255, 255, 255, 0.1);
            position: relative;
        }

        .modal-overlay.active .modal {
            transform: translateY(0);
            opacity: 1;
        }

        .modal::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(to right, var(--danger), #b91c1c);
            border-radius: var(--radius-lg) var(--radius-lg) 0 0;
        }

        .modal-header {
            margin-bottom: 1.5rem;
        }

        .modal-title {
            font-size: 1.5rem;
            font-weight: 600;
            color: var(--light);
            margin-bottom: 0.5rem;
        }

        .modal-subtitle {
            color: var(--gray);
            font-size: 0.9375rem;
        }

        .modal-body {
            margin-bottom: 1.5rem;
        }

        .modal-footer {
            display: flex;
            justify-content: flex-end;
            gap: 1rem;
        }

        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: var(--light);
            border: 1px solid rgba(255, 255, 255, 0.2);
        }

        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.15);
        }

        /* Filter Styles */
        .filter-container {
            background: rgba(15, 23, 42, 0.6);
            backdrop-filter: blur(12px);
            border-radius: var(--radius-lg);
            padding: 1.25rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 8px 25px rgba(0, 0, 0, 0.15);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }

        .filter-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }

        .filter-title {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--light);
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }

        .btn-toggle-filter {
            background: none;
            border: none;
            color: var(--primary-light);
            cursor: pointer;
            font-size: 1rem;
            transition: var(--transition);
        }

        .btn-toggle-filter:hover {
            color: var(--light);
        }

        .filter-body {
            display: none;
        }

        .filter-body.active {
            display: block;
        }

        .filter-row {
            display: flex;
            gap: 1rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }

        .filter-group {
            flex: 1;
            min-width: 200px;
        }

        .filter-label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: var(--gray);
            font-size: 0.875rem;
        }

        .filter-input {
            width: 100%;
            padding: 0.75rem 1rem;
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: var(--radius-md);
            color: var(--light);
            font-size: 0.9375rem;
            transition: var(--transition);
        }

        .filter-input:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 2px rgba(37, 99, 235, 0.2);
        }

        .filter-hospital-container {
            position: relative;
        }

        .filter-selected-hospital {
            margin-top: 0.5rem;
            padding: 0.5rem 0.75rem;
            background: rgba(37, 99, 235, 0.1);
            border: 1px solid rgba(37, 99, 235, 0.2);
            border-radius: var(--radius-md);
            display: none;
        }

        .filter-selected-hospital.active {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .filter-actions {
            display: flex;
            justify-content: flex-end;
            gap: 0.75rem;
            margin-top: 1rem;
        }

        .btn-sm {
            padding: 0.5rem 1rem;
            font-size: 0.875rem;
        }

        .filter-input option {
            background-color: var(--dark-light);
            color: white;
        }

        select.filter-input {
            background-color: rgba(37, 99, 235, 0.2);
            color: white;
            border-color: rgba(96, 165, 250, 0.4);
            appearance: none;
            background-image: url('data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="12" height="6"><path d="M0 0l6 6 6-6z" fill="white"/></svg>');
            background-repeat: no-repeat;
            background-position: right 1rem center;
            padding-right: 2.5rem;
        }

        /* PDF Action Buttons */
        .pdf-actions {
            margin-top: 1.5rem;
            position: relative;
            z-index: 20;
        }

        .pdf-actions-title {
            font-size: 1rem;
            font-weight: 600;
            color: var(--light);
            margin-bottom: 0.75rem;
        }

        .pdf-actions-buttons {
            display: flex;
            gap: 1rem;
        }

        .btn-pdf {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.75rem 1.25rem;
            border-radius: var(--radius-md);
            font-weight: 600;
            font-size: 0.9375rem;
            transition: var(--transition);
            text-decoration: none;
            cursor: pointer !important;
            position: relative;
            z-index: 25;
        }

        .btn-view-pdf {
            background: linear-gradient(to right, var(--info), var(--primary-light));
            color: var(--light) !important;
            box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
            cursor: pointer !important;
        }

        .btn-view-pdf:hover {
            background: linear-gradient(to right, var(--primary-light), var(--info));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(59, 130, 246, 0.4);
        }

        .btn-download-pdf {
            background: linear-gradient(to right, var(--secondary), var(--secondary-light));
            color: var(--light) !important;
            box-shadow: 0 4px 15px rgba(16, 185, 129, 0.3);
            cursor: pointer !important;
        }

        .btn-download-pdf:hover {
            background: linear-gradient(to right, var(--secondary-light), var(--secondary));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(16, 185, 129, 0.4);
        }

        /* Responsive Design */
        @media (max-width: 1024px) {
            .reports-container {
                flex-direction: column;
            }
            
            .immunization-request,
            .immunization-history {
                flex: 0 0 100%;
            }
            
            .immunization-content {
                flex-direction: column;
            }
            
            .immunization-right-column {
                border-left: none;
                padding-left: 0;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                padding-top: 1.5rem;
                margin-top: 1rem;
            }
        }

        @media (max-width: 768px) {
            .medi-reports {
                padding: 1.5rem;
            }
            
            .header {
                flex-direction: column;
                align-items: flex-start;
                gap: 1rem;
            }
            
            .header-actions {
                width: 100%;
                justify-content: space-between;
            }
        }

        @media (max-width: 480px) {
            .header {
                padding: 1rem;
            }
            
            .medi-reports {
                padding: 1rem;
            }
            
            .medi-reports-heading {
                font-size: 1.5rem;
            }
        }

        /* Fix for cancel button */
        .cancel-btn {
            cursor: pointer !important;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 0.5rem;
            padding: 0.5rem 1rem;
            border-radius: var(--radius-md);
            font-weight: 600;
            font-size: 0.875rem;
            background: linear-gradient(to right, var(--danger), #b91c1c);
            color: var(--light);
            box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
            border: none;
            transition: var(--transition);
            pointer-events: auto !important;
            text-decoration: none !important;
            z-index: 10;
        }

        .cancel-btn:hover {
            background: linear-gradient(to right, #b91c1c, var(--danger));
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(239, 68, 68, 0.4);
        }
    </style>
</head>
<body>
    <!-- Video Background -->
    <div class="video-background">
        <video autoplay muted loop id="background-video">
            <source src="../uploads/videos/bgv.mp4" type="video/mp4">
        </video>
        <div class="video-overlay"></div>
    </div>

    <div class="app-container">
        <!-- Main Content -->
        <main class="main-content">
            <header class="header">
                <h1 class="header-title">Medical Reports</h1>
                <div class="header-actions">
                    <div class="user-info">
                        <span class="user-name"><?php echo htmlspecialchars($first_name . ' ' . $last_name); ?></span>
                    </div>
                </div>
            </header>

            <div class="medi-reports">
                <div class="medi-reports-title">
                    <h2 class="medi-reports-heading">Medical Reports & Immunizations</h2>
                    <p class="medi-reports-subheading">Request and track your medical tests and immunizations</p>
                </div>

                <?php if (!empty($success_message)): ?>
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i> <?php echo $success_message; ?>
                </div>
                <?php endif; ?>

                <?php if (!empty($error_message)): ?>
                <div class="alert alert-error">
                    <i class="fas fa-exclamation-circle"></i> <?php echo $error_message; ?>
                </div>
                <?php endif; ?>

                <div class="reports-container">
                    <!-- Immunization Request Form - 30% -->
                    <div class="immunization-request">
                        <h3 class="immunization-request-title">
                            <i class="fas fa-syringe"></i> Request Vaccine/Immunization
                        </h3>
                        <form method="POST" action="" id="immunization-form">
                            <div class="form-group">
                                <label for="vaccine_type" class="form-label">Vaccine Type</label>
                                <select id="vaccine_type" name="vaccine_type" class="form-control" required>
                                    <option value="">Select Vaccine Type</option>
                                    <option value="COVID-19">COVID-19 Vaccine</option>
                                    <option value="Influenza">Influenza (Flu) Vaccine</option>
                                    <option value="Hepatitis B">Hepatitis B Vaccine</option>
                                    <option value="Tetanus">Tetanus Vaccine</option>
                                    <option value="MMR">MMR (Measles, Mumps, Rubella)</option>
                                    <option value="HPV">HPV Vaccine</option>
                                    <option value="Pneumococcal">Pneumococcal Vaccine</option>
                                    <option value="Other">Other (Specify in Notes)</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label for="hospital_search" class="form-label">Search Hospital</label>
                                <div class="hospital-search-container">
                                    <input type="text" id="hospital_search" class="hospital-search-input" 
                                           placeholder="Search by hospital name, city, or zipcode" autocomplete="off">
                                    <div class="hospital-search-results" id="hospital_search_results"></div>
                                    <input type="hidden" id="hospital_id" name="hospital_id" required>
                                    <div class="selected-hospital" id="selected_hospital">
                                        <div class="selected-hospital-name" id="selected_hospital_name"></div>
                                        <div class="selected-hospital-details" id="selected_hospital_details"></div>
                                        <button type="button" class="selected-hospital-remove" id="remove_hospital">
                                            <i class="fas fa-times"></i> Remove selection
                                        </button>
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label for="notes" class="form-label">Additional Notes</label>
                                <textarea id="notes" name="notes" class="form-control form-textarea" placeholder="Any specific requirements or medical conditions we should know about..."></textarea>
                            </div>
                            <button type="submit" name="submit_immunization" class="btn btn-primary btn-block">
                                <i class="fas fa-paper-plane"></i> Submit Request
                            </button>
                        </form>
                    </div>

                    <!-- Immunization History - 70% -->
                    <div class="immunization-history">
                        <h3 class="immunization-request-title">
                            <i class="fas fa-clipboard-list"></i> Your Immunization Requests
                        </h3>
                        
                        <!-- Add Filter Section -->
                        <div class="filter-container">
                            <div class="filter-header">
                                <h4 class="filter-title"><i class="fas fa-filter"></i> Filter Records</h4>
                                <button type="button" id="toggle-filters" class="btn-toggle-filter">
                                    <i class="fas fa-chevron-down"></i>
                                </button>
                            </div>
                            
                            <div class="filter-body" id="filter-body">
                                <div class="filter-row">
                                    <div class="filter-group">
                                        <label for="filter-hospital" class="filter-label">Hospital</label>
                                        <div class="hospital-search-container filter-hospital-container">
                                            <input type="text" id="filter-hospital" class="filter-input hospital-search-input" 
                                                   placeholder="Search hospital...">
                                            <div class="hospital-search-results" id="filter_hospital_results"></div>
                                            <input type="hidden" id="filter_hospital_id">
                                            <div class="selected-hospital filter-selected-hospital" id="filter_selected_hospital">
                                                <div class="selected-hospital-name" id="filter_selected_hospital_name"></div>
                                                <button type="button" class="selected-hospital-remove" id="filter_remove_hospital">
                                                    <i class="fas fa-times"></i>
                                                </button>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <div class="filter-group">
                                        <label for="filter-vaccine" class="filter-label">Vaccine Type</label>
                                        <select id="filter-vaccine" class="filter-input">
                                            <option value="">All Vaccines</option>
                                            <option value="COVID-19">COVID-19</option>
                                            <option value="Influenza">Influenza</option>
                                            <option value="Hepatitis B">Hepatitis B</option>
                                            <option value="Tetanus">Tetanus</option>
                                            <option value="MMR">MMR</option>
                                            <option value="HPV">HPV</option>
                                            <option value="Pneumococcal">Pneumococcal</option>
                                            <option value="Other">Other</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div class="filter-row">
                                    <div class="filter-group">
                                        <label for="filter-request-date" class="filter-label">Request Date</label>
                                        <input type="date" id="filter-request-date" class="filter-input">
                                    </div>
                                    
                                    <div class="filter-group">
                                        <label for="filter-schedule-date" class="filter-label">Schedule Date</label>
                                        <input type="date" id="filter-schedule-date" class="filter-input">
                                    </div>
                                    
                                    <div class="filter-group">
                                        <label for="filter-status" class="filter-label">Status</label>
                                        <select id="filter-status" class="filter-input">
                                            <option value="">All Statuses</option>
                                            <option value="pending">Pending</option>
                                            <option value="scheduled">Scheduled</option>
                                            <option value="completed">Completed</option>
                                            <option value="canceled">Canceled</option>
                                            <option value="overdue">Overdue</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div class="filter-actions">
                                    <button type="button" id="apply-filters" class="btn btn-primary btn-sm">
                                        <i class="fas fa-check"></i> Apply Filters
                                    </button>
                                    <button type="button" id="clear-filters" class="btn btn-secondary btn-sm">
                                        <i class="fas fa-undo"></i> Clear Filters
                                    </button>
                                </div>
                            </div>
                        </div>

                        <?php if (empty($immunizations)): ?>
                            <div class="immunization-card pending">
                                <div class="immunization-type">No immunization requests yet</div>
                                <p style="color: var(--gray); margin-top: 1rem;">Your immunization request history will appear here once you submit a request.</p>
                            </div>
                        <?php else: ?>
                            <?php foreach ($immunizations as $immunization): ?>
                                <div class="immunization-card <?php echo $immunization['display_status']; ?>"
                                     data-hospital-id="<?php echo $immunization['hospital_id']; ?>"
                                     data-vaccine-type="<?php echo htmlspecialchars($immunization['vaccine_type']); ?>"
                                     data-request-date="<?php echo date('Y-m-d', strtotime($immunization['request_date'])); ?>"
                                     data-schedule-date="<?php echo $immunization['schedule'] ? date('Y-m-d', strtotime($immunization['schedule'])) : ''; ?>"
                                     data-status="<?php echo $immunization['display_status']; ?>">
                                    <div class="immunization-card-header">
                                        <h4 class="immunization-type"><?php echo htmlspecialchars($immunization['vaccine_type']); ?></h4>
                                        <span class="immunization-status status-<?php echo $immunization['display_status']; ?>">
                                            <?php 
                                            $status_text = ucfirst($immunization['display_status']);
                                            if ($immunization['display_status'] === 'scheduled') {
                                                echo '<i class="fas fa-calendar-check"></i> ' . $status_text;
                                            } elseif ($immunization['display_status'] === 'pending') {
                                                echo '<i class="fas fa-hourglass-half"></i> ' . $status_text;
                                            } elseif ($immunization['display_status'] === 'completed') {
                                                echo '<i class="fas fa-check-circle"></i> ' . $status_text;
                                            } elseif ($immunization['display_status'] === 'canceled') {
                                                echo '<i class="fas fa-times-circle"></i> ' . $status_text;
                                            } elseif ($immunization['display_status'] === 'overdue') {
                                                echo '<i class="fas fa-exclamation-triangle"></i> ' . $status_text;
                                            }
                                            ?>
                                        </span>
                                    </div>
                                    
                                    <?php if ($immunization['display_status'] === 'completed'): ?>
                                    <!-- Special layout for completed immunizations with two columns -->
                                    <div class="immunization-content">
                                        <div class="immunization-left-column">
                                            <div class="immunization-details">
                                                <div class="immunization-detail">
                                                    <div class="detail-label">Hospital:</div>
                                                    <div class="detail-value"><?php echo htmlspecialchars($immunization['hospital_name'] ?? 'Not specified'); ?></div>
                                                </div>
                                                <div class="immunization-detail">
                                                    <div class="detail-label">Location:</div>
                                                    <div class="detail-value">
                                                        <?php 
                                                        if (!empty($immunization['hospital_city']) || !empty($immunization['hospital_zipcode'])) {
                                                            echo htmlspecialchars($immunization['hospital_city'] ?? '') . 
                                                                (!empty($immunization['hospital_city']) && !empty($immunization['hospital_zipcode']) ? ', ' : '') . 
                                                                htmlspecialchars($immunization['hospital_zipcode'] ?? '');
                                                        } else {
                                                            echo 'Not specified';
                                                        }
                                                        ?>
                                                    </div>
                                                </div>
                                                <div class="immunization-detail">
                                                    <div class="detail-label">Requested On:</div>
                                                    <div class="detail-value"><?php echo date('F j, Y', strtotime($immunization['request_date'])); ?></div>
                                                </div>
                                                <?php if (!empty($immunization['schedule'])): ?>
                                                <div class="immunization-detail">
                                                    <div class="detail-label">Scheduled:</div>
                                                    <div class="detail-value"><?php echo date('F j, Y g:i A', strtotime($immunization['schedule'])); ?></div>
                                                </div>
                                                <?php endif; ?>
                                                <?php if (!empty($immunization['immunization_date'])): ?>
                                                <div class="immunization-detail">
                                                    <div class="detail-label">Completed:</div>
                                                    <div class="detail-value"><?php echo date('F j, Y', strtotime($immunization['immunization_date'])); ?></div>
                                                </div>
                                                <?php endif; ?>
                                            </div>
                                            
                                            <!-- Always show "Your Notes" for completed cards -->
                                            <?php if (!empty($immunization['notes'])): ?>
                                            <div class="immunization-notes">
                                                <div class="notes-title">Your Notes:</div>
                                                <div class="notes-content"><?php echo nl2br(htmlspecialchars($immunization['notes'])); ?></div>
                                            </div>
                                            <?php endif; ?>
                                        </div>
                                        
                                        <div class="immunization-right-column">
                                            <?php if (!empty($immunization['pdf_file'])): ?>
                                            <div class="pdf-actions">
                                                <h5 class="pdf-actions-title">Medical Report</h5>
                                                <div class="pdf-actions-buttons">
                                                    <a href="?view_pdf=<?php echo $immunization['id']; ?>" 
                                                       target="_blank" 
                                                       class="btn-pdf btn-view-pdf">
                                                        <i class="fas fa-eye"></i> View PDF
                                                    </a>
                                                    <a href="?download_pdf=<?php echo $immunization['id']; ?>" 
                                                       class="btn-pdf btn-download-pdf">
                                                        <i class="fas fa-download"></i> Download
                                                    </a>
                                                </div>
                                            </div>
                                            <?php endif; ?>
                                            
                                            <?php if (!empty($immunization['comments'])): ?>
                                            <div class="immunization-notes">
                                                <div class="notes-title">Receptionist Comments:</div>
                                                <div class="notes-content"><?php echo nl2br(htmlspecialchars($immunization['comments'])); ?></div>
                                            </div>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                    <?php else: ?>
                                    <!-- Standard layout for non-completed immunizations -->
                                    <div class="immunization-details">
                                        <div class="immunization-detail">
                                            <div class="detail-label">Hospital:</div>
                                            <div class="detail-value"><?php echo htmlspecialchars($immunization['hospital_name'] ?? 'Not specified'); ?></div>
                                        </div>
                                        <div class="immunization-detail">
                                            <div class="detail-label">Location:</div>
                                            <div class="detail-value">
                                                <?php 
                                                if (!empty($immunization['hospital_city']) || !empty($immunization['hospital_zipcode'])) {
                                                    echo htmlspecialchars($immunization['hospital_city'] ?? '') . 
                                                        (!empty($immunization['hospital_city']) && !empty($immunization['hospital_zipcode']) ? ', ' : '') . 
                                                        htmlspecialchars($immunization['hospital_zipcode'] ?? '');
                                                } else {
                                                    echo 'Not specified';
                                                }
                                                ?>
                                            </div>
                                        </div>
                                        <div class="immunization-detail">
                                            <div class="detail-label">Requested On:</div>
                                            <div class="detail-value"><?php echo date('F j, Y', strtotime($immunization['request_date'])); ?></div>
                                        </div>
                                        <?php if (!empty($immunization['schedule'])): ?>
                                        <div class="immunization-detail">
                                            <div class="detail-label">Scheduled:</div>
                                            <div class="detail-value"><?php echo date('F j, Y g:i A', strtotime($immunization['schedule'])); ?></div>
                                        </div>
                                        <?php endif; ?>
                                        <?php if ($immunization['display_status'] === 'canceled' && !empty($immunization['canceled_date'])): ?>
                                        <div class="immunization-detail">
                                            <div class="detail-label">Canceled On:</div>
                                            <div class="detail-value"><?php echo date('F j, Y', strtotime($immunization['canceled_date'])); ?></div>
                                        </div>
                                        <?php endif; ?>
                                    </div>
                                    
                                    <?php if (!empty($immunization['notes'])): ?>
                                    <div class="immunization-notes">
                                        <div class="notes-title">Your Notes:</div>
                                        <div class="notes-content"><?php echo nl2br(htmlspecialchars($immunization['notes'])); ?></div>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php if (!empty($immunization['comments']) && $immunization['display_status'] !== 'completed'): ?>
                                    <div class="immunization-notes">
                                        <div class="notes-title">Hospital Comments:</div>
                                        <div class="notes-content"><?php echo nl2br(htmlspecialchars($immunization['comments'])); ?></div>
                                    </div>
                                    <?php endif; ?>
                                    
                                    <?php if ($immunization['display_status'] === 'pending' || ($immunization['display_status'] === 'scheduled' && $immunization['attended'] != 1)): ?>
                                    <div class="immunization-actions">
                                        <button type="button" class="cancel-btn" onclick="showCancelModal(<?php echo $immunization['id']; ?>, '<?php echo htmlspecialchars($immunization['vaccine_type']); ?>')">
                                            <i class="fas fa-times"></i> Cancel Request
                                        </button>
                                    </div>
                                    <?php endif; ?>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Cancel Modal -->
    <div class="modal-overlay" id="cancel-modal">
        <div class="modal">
            <div class="modal-header">
                <h3 class="modal-title">Cancel Immunization Request</h3>
                <p class="modal-subtitle">Are you sure you want to cancel this request?</p>
            </div>
            <form method="POST" action="">
                <div class="modal-body">
                    <input type="hidden" id="cancel-immunization-id" name="immunization_id">
                    <div class="form-group">
                        <label for="cancel-reason" class="form-label">Reason for Cancellation</label>
                        <textarea id="cancel-reason" name="cancel_reason" class="form-control form-textarea" 
                                  placeholder="Please provide a reason for canceling this request..." required></textarea>
                    </div>
                </div>
                <div class="modal-footer">
                    <button type="button" class="btn btn-secondary" onclick="hideCancelModal()">
                        <i class="fas fa-arrow-left"></i> Keep Request
                    </button>
                    <button type="submit" name="cancel_immunization" class="btn btn-danger">
                        <i class="fas fa-times"></i> Cancel Request
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Hospital search functionality for main form
        let hospitalSearchTimeout;
        const hospitalSearchInput = document.getElementById('hospital_search');
        const hospitalSearchResults = document.getElementById('hospital_search_results');
        const hospitalIdInput = document.getElementById('hospital_id');
        const selectedHospitalDiv = document.getElementById('selected_hospital');
        const selectedHospitalName = document.getElementById('selected_hospital_name');
        const selectedHospitalDetails = document.getElementById('selected_hospital_details');
        const removeHospitalBtn = document.getElementById('remove_hospital');

        hospitalSearchInput.addEventListener('input', function() {
            clearTimeout(hospitalSearchTimeout);
            const query = this.value.trim();
            
            if (query.length < 2) {
                hospitalSearchResults.classList.remove('active');
                return;
            }
            
            hospitalSearchTimeout = setTimeout(() => {
                fetch(`?search_hospital=${encodeURIComponent(query)}`)
                    .then(response => response.json())
                    .then(hospitals => {
                        hospitalSearchResults.innerHTML = '';
                        
                        if (hospitals.length === 0) {
                            hospitalSearchResults.innerHTML = '<div class="hospital-result-item">No hospitals found</div>';
                        } else {
                            hospitals.forEach(hospital => {
                                const item = document.createElement('div');
                                item.className = 'hospital-result-item';
                                item.innerHTML = `
                                    <div class="hospital-result-name">${hospital.hospital_name}</div>
                                    <div class="hospital-result-details">${hospital.city}, ${hospital.zipcode}</div>
                                `;
                                item.addEventListener('click', () => selectHospital(hospital));
                                hospitalSearchResults.appendChild(item);
                            });
                        }
                        
                        hospitalSearchResults.classList.add('active');
                    })
                    .catch(error => {
                        console.error('Error searching hospitals:', error);
                    });
            }, 300);
        });

        function selectHospital(hospital) {
            hospitalIdInput.value = hospital.id;
            selectedHospitalName.textContent = hospital.hospital_name;
            selectedHospitalDetails.textContent = `${hospital.city}, ${hospital.zipcode}`;
            selectedHospitalDiv.classList.add('active');
            hospitalSearchInput.value = '';
            hospitalSearchResults.classList.remove('active');
        }

        removeHospitalBtn.addEventListener('click', function() {
            hospitalIdInput.value = '';
            selectedHospitalDiv.classList.remove('active');
            hospitalSearchInput.value = '';
        });

        // Hide search results when clicking outside
        document.addEventListener('click', function(e) {
            if (!hospitalSearchInput.contains(e.target) && !hospitalSearchResults.contains(e.target)) {
                hospitalSearchResults.classList.remove('active');
            }
        });

        // Filter functionality
        const toggleFiltersBtn = document.getElementById('toggle-filters');
        const filterBody = document.getElementById('filter-body');
        const applyFiltersBtn = document.getElementById('apply-filters');
        const clearFiltersBtn = document.getElementById('clear-filters');

        toggleFiltersBtn.addEventListener('click', function() {
            filterBody.classList.toggle('active');
            const icon = this.querySelector('i');
            if (filterBody.classList.contains('active')) {
                icon.className = 'fas fa-chevron-up';
            } else {
                icon.className = 'fas fa-chevron-down';
            }
        });

        // Filter hospital search functionality
        let filterHospitalSearchTimeout;
        const filterHospitalInput = document.getElementById('filter-hospital');
        const filterHospitalResults = document.getElementById('filter_hospital_results');
        const filterHospitalIdInput = document.getElementById('filter_hospital_id');
        const filterSelectedHospitalDiv = document.getElementById('filter_selected_hospital');
        const filterSelectedHospitalName = document.getElementById('filter_selected_hospital_name');
        const filterRemoveHospitalBtn = document.getElementById('filter_remove_hospital');

        filterHospitalInput.addEventListener('input', function() {
            clearTimeout(filterHospitalSearchTimeout);
            const query = this.value.trim();
            
            if (query.length < 2) {
                filterHospitalResults.classList.remove('active');
                return;
            }
            
            filterHospitalSearchTimeout = setTimeout(() => {
                fetch(`?search_hospital=${encodeURIComponent(query)}`)
                    .then(response => response.json())
                    .then(hospitals => {
                        filterHospitalResults.innerHTML = '';
                        
                        if (hospitals.length === 0) {
                            filterHospitalResults.innerHTML = '<div class="hospital-result-item">No hospitals found</div>';
                        } else {
                            hospitals.forEach(hospital => {
                                const item = document.createElement('div');
                                item.className = 'hospital-result-item';
                                item.innerHTML = `
                                    <div class="hospital-result-name">${hospital.hospital_name}</div>
                                    <div class="hospital-result-details">${hospital.city}, ${hospital.zipcode}</div>
                                `;
                                item.addEventListener('click', () => selectFilterHospital(hospital));
                                filterHospitalResults.appendChild(item);
                            });
                        }
                        
                        filterHospitalResults.classList.add('active');
                    })
                    .catch(error => {
                        console.error('Error searching hospitals:', error);
                    });
            }, 300);
        });

        function selectFilterHospital(hospital) {
            filterHospitalIdInput.value = hospital.id;
            filterSelectedHospitalName.textContent = hospital.hospital_name;
            filterSelectedHospitalDiv.classList.add('active');
            filterHospitalInput.value = '';
            filterHospitalResults.classList.remove('active');
        }

        filterRemoveHospitalBtn.addEventListener('click', function() {
            filterHospitalIdInput.value = '';
            filterSelectedHospitalDiv.classList.remove('active');
            filterHospitalInput.value = '';
        });

        // Hide filter search results when clicking outside
        document.addEventListener('click', function(e) {
            if (!filterHospitalInput.contains(e.target) && !filterHospitalResults.contains(e.target)) {
                filterHospitalResults.classList.remove('active');
            }
        });

        // Apply filters
        applyFiltersBtn.addEventListener('click', function() {
            const hospitalId = filterHospitalIdInput.value;
            const vaccineType = document.getElementById('filter-vaccine').value;
            const requestDate = document.getElementById('filter-request-date').value;
            const scheduleDate = document.getElementById('filter-schedule-date').value;
            const status = document.getElementById('filter-status').value;

            const cards = document.querySelectorAll('.immunization-card');
            
            cards.forEach(card => {
                let show = true;
                
                if (hospitalId && card.dataset.hospitalId !== hospitalId) {
                    show = false;
                }
                
                if (vaccineType && card.dataset.vaccineType !== vaccineType) {
                    show = false;
                }
                
                if (requestDate && card.dataset.requestDate !== requestDate) {
                    show = false;
                }
                
                if (scheduleDate && card.dataset.scheduleDate !== scheduleDate) {
                    show = false;
                }
                
                if (status && card.dataset.status !== status) {
                    show = false;
                }
                
                card.style.display = show ? 'block' : 'none';
            });
        });

        // Clear filters
        clearFiltersBtn.addEventListener('click', function() {
            document.getElementById('filter-vaccine').value = '';
            document.getElementById('filter-request-date').value = '';
            document.getElementById('filter-schedule-date').value = '';
            document.getElementById('filter-status').value = '';
            filterHospitalIdInput.value = '';
            filterSelectedHospitalDiv.classList.remove('active');
            filterHospitalInput.value = '';
            
            const cards = document.querySelectorAll('.immunization-card');
            cards.forEach(card => {
                card.style.display = 'block';
            });
        });

        // Cancel modal functionality
        function showCancelModal(immunizationId, vaccineType) {
            document.getElementById('cancel-immunization-id').value = immunizationId;
            document.querySelector('.modal-subtitle').textContent = `Are you sure you want to cancel your ${vaccineType} vaccine request?`;
            document.getElementById('cancel-modal').classList.add('active');
        }

        function hideCancelModal() {
            document.getElementById('cancel-modal').classList.remove('active');
            document.getElementById('cancel-reason').value = '';
        }

        // Close modal when clicking outside
        document.getElementById('cancel-modal').addEventListener('click', function(e) {
            if (e.target === this) {
                hideCancelModal();
            }
        });

        // Form validation
        document.getElementById('immunization-form').addEventListener('submit', function(e) {
            const hospitalId = document.getElementById('hospital_id').value;
            if (!hospitalId) {
                e.preventDefault();
                alert('Please select a hospital for your immunization request.');
                return false;
            }
        });

        // Auto-hide alerts after 5 seconds
        setTimeout(function() {
            const alerts = document.querySelectorAll('.alert');
            alerts.forEach(alert => {
                alert.style.opacity = '0';
                alert.style.transform = 'translateY(-20px)';
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 300);
            });
        }, 5000);
    </script>
</body>
</html>
