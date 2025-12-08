<?php
require_once '../connection.php';
session_start();

// Check if the patient is logged in
if (!isset($_SESSION['user_id'])) {
    echo "<script>alert('Please log in to continue.'); window.location.href='../login.html';</script>";
    exit;
}


    // Retrieve the encryption key
    $key_path = '../../encryption_key.key';
    $encryption_key = trim(file_get_contents($key_path));
    if (!$encryption_key) {
        http_response_code(500); // Internal Server Error
        die('Encryption key is missing');
    }
// Check if this is a request to stream the video
if (isset($_GET['stream']) && isset($_GET['id'])) {
    $history_id = intval($_GET['id']);

    // Fetch video details from the database
    $query = "SELECT video_file, video_iv, video_auth_tag FROM patient_history WHERE id = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("i", $history_id);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows === 0) {
        http_response_code(404); // Not Found
        die('Video not found');
    }

    $data = $result->fetch_assoc();


    $video_path = '../patient/' . $data['video_file']; // Changed from 'video' to 'video_file'
    if (!file_exists($video_path)) {
        http_response_code(404); // Not Found
        die('Encrypted video file not found');
    }

    // Decrypt the video
    $encrypted_video = file_get_contents($video_path);
    $decrypted_video = openssl_decrypt(
        $encrypted_video,
        'aes-256-gcm',
        $encryption_key,
        0,
        $data['video_iv'],
        $data['video_auth_tag']
    );

    if ($decrypted_video === false) {
        http_response_code(500); // Internal Server Error
        die('Failed to decrypt the video');
    }

    // Stream the video
    header('Content-Type: video/mp4');
    header('Content-Length: ' . strlen($decrypted_video));
    header('Accept-Ranges: bytes');
    echo $decrypted_video;
    exit;
}

// Check if the history ID is provided
if (!isset($_GET['id'])) {
    echo "<script>alert('No history ID provided!'); window.location.href='patient_history.php';</script>";
    exit;
}
$history_id = intval($_GET['id']);

// Fetch patient_id associated with the history_id
$query = "SELECT patient_id FROM patient_history WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $history_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo "<script>alert('No record found!'); window.location.href='patient_history.php';</script>";
    exit;
}

$data = $result->fetch_assoc();
$patient_id = $data['patient_id'];

// Retrieve the patient's first name and last name
$query_patient = "SELECT first_name, last_name FROM patients WHERE id = ?";
$stmt_patient = $conn->prepare($query_patient);
$stmt_patient->bind_param("i", $patient_id);
$stmt_patient->execute();
$result_patient = $stmt_patient->get_result();

if ($result_patient->num_rows === 0) {
    echo "<script>alert('No patient found!'); window.location.href='patient_history.php';</script>";
    exit;
}

$data_patient = $result_patient->fetch_assoc(); // Store patient's first and last name

// Fetch encrypted data from the database
$query = "SELECT 
              problem_description, 
              problem_iv, 
              problem_auth_tag, 
              current_medication, 
              medication_iv, 
              medication_auth_tag, 
              video_file, 
              video_iv, 
              video_auth_tag 
          FROM patient_history 
          WHERE id = ? AND patient_id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("ii", $history_id, $patient_id);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows === 0) {
    echo "<script>alert('No record found!'); window.location.href='patient_history.php';</script>";
    exit;
}

$data = $result->fetch_assoc();

// Decrypt problem description
$decrypted_description = openssl_decrypt(
    $data['problem_description'],
    'aes-256-gcm',
    $encryption_key,
    0,
    $data['problem_iv'],
    $data['problem_auth_tag']
);

// Decrypt current medication
$decrypted_medication = openssl_decrypt(
    $data['current_medication'],
    'aes-256-gcm',
    $encryption_key,
    0,
    $data['medication_iv'],
    $data['medication_auth_tag']
);
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Solution Portal</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary: #3a86ff;
            --primary-dark: #2667cc;
            --secondary: #43e97b;
            --secondary-dark: #32c964;
            --accent: #ff6b6b;
            --text-dark: #2d3748;
            --text-light: #718096;
            --bg-light: #f7fafc;
            --bg-white: #ffffff;
            --shadow-sm: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.08);
            --shadow-md: 0 4px 6px rgba(0,0,0,0.1), 0 2px 4px rgba(0,0,0,0.06);
            --shadow-lg: 0 10px 15px rgba(0,0,0,0.1), 0 4px 6px rgba(0,0,0,0.05);
            --radius-sm: 8px;
            --radius-md: 12px;
            --radius-lg: 20px;
            --transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Inter', sans-serif;
            background: linear-gradient(135deg, #f6f9fc 0%, #edf2f7 100%);
            color: var(--text-dark);
            line-height: 1.6;
            min-height: 100vh;
            padding: 0;
            margin: 0;
        }

        .app-container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem 1.5rem;
        }

        .header {
            background: linear-gradient(135deg, var(--primary) 0%, #6c63ff 100%);
            border-radius: var(--radius-lg);
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: var(--shadow-lg);
            position: relative;
            overflow: hidden;
            color: white;
        }

        .header::before {
            content: "";
            position: absolute;
            top: -50px;
            right: -50px;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            z-index: 0;
        }

        .header::after {
            content: "";
            position: absolute;
            bottom: -80px;
            left: -80px;
            width: 250px;
            height: 250px;
            border-radius: 50%;
            background: rgba(255,255,255,0.08);
            z-index: 0;
        }

        .header-content {
            position: relative;
            z-index: 1;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin: 0;
        }

        .patient-badge {
            display: inline-flex;
            align-items: center;
            background: rgba(255,255,255,0.2);
            padding: 0.5rem 1rem;
            border-radius: 50px;
            font-size: 0.9rem;
            margin-top: 0.5rem;
        }

        .patient-badge i {
            margin-right: 0.5rem;
        }

        .card {
            background: var(--bg-white);
            border-radius: var(--radius-md);
            box-shadow: var(--shadow-md);
            padding: 2rem;
            margin-bottom: 2rem;
            transition: var(--transition);
            border: 1px solid rgba(0,0,0,0.05);
        }

        .card:hover {
            box-shadow: var(--shadow-lg);
            transform: translateY(-5px);
        }

        .card-title {
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 1.5rem;
            display: flex;
            align-items: center;
        }

        .card-title i {
            margin-right: 0.75rem;
            font-size: 1.4rem;
            opacity: 0.9;
        }

        .form-group {
            margin-bottom: 1.5rem;
        }

        label {
            display: block;
            font-weight: 500;
            margin-bottom: 0.75rem;
            color: var(--text-dark);
        }

        textarea, 
        input[type="text"],
        input[type="date"],
        input[type="time"],
        select {
            width: 100%;
            padding: 0.875rem 1rem;
            border: 1px solid #e2e8f0;
            border-radius: var(--radius-sm);
            font-size: 1rem;
            background: var(--bg-light);
            color: var(--text-dark);
            font-family: 'Inter', sans-serif;
            transition: var(--transition);
        }

        textarea:focus, 
        input[type="text"]:focus,
        input[type="date"]:focus,
        input[type="time"]:focus,
        select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(58, 134, 255, 0.15);
        }

        textarea {
            resize: vertical;
            min-height: 120px;
        }

        textarea:disabled {
            background-color: #f1f5f9;
            color: #64748b;
            cursor: not-allowed;
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.75rem 1.5rem;
            border-radius: var(--radius-sm);
            font-weight: 500;
            font-size: 1rem;
            cursor: pointer;
            transition: var(--transition);
            border: none;
        }

        .btn-primary {
            background: var(--primary);
            color: white;
        }

        .btn-primary:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
        }

        .btn-secondary {
            background: var(--secondary);
            color: white;
        }

        .btn-secondary:hover {
            background: var(--secondary-dark);
            transform: translateY(-2px);
        }

        .btn-outline {
            background: transparent;
            color: var(--primary);
            border: 1px solid var(--primary);
        }

        .btn-outline:hover {
            background: var(--primary);
            color: white;
        }

        .btn i {
            margin-right: 0.5rem;
        }

        .btn-link {
            text-decoration: none;
            color: var(--primary);
            font-weight: 500;
            display: inline-flex;
            align-items: center;
        }

        .btn-link i {
            margin-right: 0.5rem;
        }

        .btn-link:hover {
            text-decoration: underline;
        }

        .actions {
            display: flex;
            justify-content: space-between;
            margin-top: 2rem;
        }

        .video-container {
            background: var(--bg-white);
            border-radius: var(--radius-md);
            overflow: hidden;
            box-shadow: var(--shadow-md);
            margin: 2rem 0;
        }

        .video-wrapper {
            position: relative;
            width: 100%;
            padding-top: 56.25%; /* 16:9 Aspect Ratio */
            overflow: hidden;
        }

        video {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            object-fit: cover;
            border-radius: var(--radius-sm);
        }

        .video-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(255, 255, 255, 0.01);
            pointer-events: none;
        }

            .video-security-overlay {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: transparent;
            pointer-events: none;
            z-index: 1;
        }



        .video-security-text {
            position: absolute;
            bottom: 10px;
            right: 10px;
            color: white;
            font-size: 14px;
            text-shadow: 0 0 8px rgba(0,0,0,0.5);
            z-index: 2;
            pointer-events: none;
        }

        .medication-container {
            margin-top: 2rem;
        }

        .medication-entry {
            background: var(--bg-white);
            border-radius: var(--radius-md);
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: var(--shadow-sm);
            border: 1px solid rgba(0,0,0,0.05);
            transition: var(--transition);
        }

        .medication-entry:hover {
            box-shadow: var(--shadow-md);
        }

        .medication-header {
            display: flex;
            align-items: center;
            margin-bottom: 1.5rem;
            padding-bottom: 0.75rem;
            border-bottom: 2px solid #e2e8f0;
        }

        .medication-header h3 {
            font-size: 1.1rem;
            font-weight: 600;
            color: var(--text-dark);
            margin: 0;
        }

        .medication-header .pill-icon {
            background: var(--primary);
            color: white;
            width: 32px;
            height: 32px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-right: 1rem;
        }

        .medication-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .date-row {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin-bottom: 1.5rem;
        }

        .hidden {
            display: none;
        }

        .treatment-toggle {
            display: flex;
            background: var(--bg-light);
            border-radius: var(--radius-lg);
            padding: 0.25rem;
            margin-bottom: 1.5rem;
            border: 1px solid #e2e8f0;
        }

        .treatment-toggle label {
            flex: 1;
            text-align: center;
            padding: 0.75rem 1rem;
            margin: 0;
            cursor: pointer;
            border-radius: var(--radius-md);
            transition: var(--transition);
        }

        .treatment-toggle input[type="radio"] {
            display: none;
        }

        .treatment-toggle input[type="radio"]:checked + label {
            background: var(--primary);
            color: white;
            font-weight: 500;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .fade-in {
            animation: fadeIn 0.5s ease forwards;
        }

        @media (max-width: 768px) {
            .app-container {
                padding: 1rem;
            }
            
            .header {
                padding: 1.5rem;
            }
            
            .header-title {
                font-size: 1.5rem;
            }
            
            .card {
                padding: 1.5rem;
            }
            
            .medication-row {
                grid-template-columns: 1fr;
            }
            
            .date-row {
                grid-template-columns: 1fr;
            }
            
            .actions {
                flex-direction: column;
                gap: 1rem;
            }
            
            .actions .btn {
                width: 100%;
            }
        }
    </style>
</head>
<body>
    <div class="app-container">
        <div class="header">
            <div class="header-content">
                <div>
                    <h1 class="header-title">Provide Solution</h1>
                    <div class="patient-badge">
                        <i class="fas fa-user-circle"></i>
                        <span><?= htmlspecialchars($data_patient['first_name'] . ' ' . $data_patient['last_name']); ?></span>
                    </div>
                </div>
            </div>
        </div>

        <form action="process_problem.php" method="POST">
            <input type="hidden" name="form_action" value="solution_form">
            <input type="hidden" name="history_id" value="<?= htmlspecialchars($history_id); ?>">
            
            <div class="card fade-in" style="animation-delay: 0.1s">
                <h2 class="card-title"><i class="fas fa-clipboard-list"></i>Patient Information</h2>
                
                <div class="form-group">
                    <label for="problem_description">Problem Description:</label>
                    <textarea id="problem_description" class="essential" disabled><?= htmlspecialchars($decrypted_description); ?></textarea>
                </div>
                
                <div class="form-group">
                    <label for="current_medication">Current Medication:</label>
                    <textarea id="current_medication" class="essential" disabled><?= htmlspecialchars($decrypted_medication); ?></textarea>
                </div>
            </div>
            
            <?php if (!empty($data['video_file'])): ?>
            <div class="card fade-in" style="animation-delay: 0.2s">
                <h2 class="card-title"><i class="fas fa-video"></i>Patient Video</h2>
                
                <div class="video-container essential">
                    <div class="video-wrapper">
                        <video id="custom-video" controls autoplay muted
                            oncontextmenu="return false;" ondragstart="return false;" 
                            controlsList="nodownload nofullscreen" disablepictureinpicture playsinline>
                            <source src="?stream=1&id=<?= htmlspecialchars($history_id); ?>" type="video/mp4">
                            Your browser does not support the video tag.
                        </video>
                        <div class="video-security-overlay"></div>
                        <div class="video-security-text">SECURE PATIENT VIDEO - <?= date('Y') ?></div>
                    </div>
                </div>
            </div>
            <?php endif; ?>
            
            <div class="card fade-in" style="animation-delay: 0.3s">
                <h2 class="card-title"><i class="fas fa-stethoscope"></i>Doctor's Solution</h2>
                
                <div class="form-group essential" id="doctor_solution_section">
                    <label for="doctor_solution">Solution & Recommendations:</label>
                    <textarea id="doctor_solution" name="doctor_solution" required placeholder="Enter your detailed diagnosis and recommendations..."></textarea>
                </div>
                
                <div class="form-group essential">
                    <label>Treatment Type:</label>
                    <div class="treatment-toggle">
                        <input type="radio" id="remote" name="treatment_type" value="remote" checked>
                        <label for="remote"><i class="fas fa-laptop-medical"></i> Remote</label>
                        
                        <input type="radio" id="in_person" name="treatment_type" value="in_person">
                        <label for="in_person"><i class="fas fa-hospital"></i> In-Person</label>
                    </div>
                </div>
                
                <div id="appointment_date" class="form-group hidden essential">
                    <label for="appointment_date_input">Appointment Date:</label>
                    <input type="date" id="appointment_date_input" name="appointment_date">
                </div>
            </div>
            
            <div class="card fade-in" id="medication_section" style="animation-delay: 0.4s">
                <h2 class="card-title"><i class="fas fa-pills"></i>Prescribed Medications</h2>
                
                <div class="medication-container">
                    <div class="medication-entry">
                        <div class="medication-header">
                            <div class="pill-icon"><i class="fas fa-capsules"></i></div>
                            <h3>Medication #1</h3>
                        </div>
                        
                        <div class="medication-row">
                            <div class="form-group">
                                <label for="medication_name_1">Medication Name:</label>
                                <input type="text" id="medication_name_1" name="medication_name_1" placeholder="Enter medication name">
                            </div>
                            
                            <div class="form-group">
                                <label for="medication_type_1">Medication Type:</label>
                                <select id="medication_type_1" name="medication_type_1">
                                    <option value="tablet">Tablet</option>
                                    <option value="syrup">Syrup</option>
                                    <option value="eye_drop">Eye Drop</option>
                                    <option value="cream">Cream</option>
                                    <option value="other">Other</option>
                                </select>
                            </div>
                            
                            <div class="form-group">
                                <label for="dosage_quantity_1">Dosage & Quantity:</label>
                                <input type="text" id="dosage_quantity_1" name="dosage_quantity_1" placeholder="e.g., 500mg, 30 tablets">
                            </div>
                        </div>
                        
                        <div class="medication-row">
                            <div class="form-group">
                                <label for="morning_time_1">Morning Time:</label>
                                <input type="time" id="morning_time_1" name="morning_time_1">
                            </div>
                            
                            <div class="form-group">
                                <label for="afternoon_time_1">Afternoon Time:</label>
                                <input type="time" id="afternoon_time_1" name="afternoon_time_1">
                            </div>
                            
                            <div class="form-group">
                                <label for="evening_time_1">Evening Time:</label>
                                <input type="time" id="evening_time_1" name="evening_time_1">
                            </div>
                            
                            <div class="form-group">
                                <label for="night_time_1">Night Time:</label>
                                <input type="time" id="night_time_1" name="night_time_1">
                            </div>
                        </div>
                        
                        <div class="date-row">
                            <div class="form-group">
                                <label for="start_date_1">Start Date:</label>
                                <input type="date" id="start_date_1" name="start_date_1">
                            </div>
                            
                            <div class="form-group">
                                <label for="end_date_1">End Date:</label>
                                <input type="date" id="end_date_1" name="end_date_1">
                            </div>
                        </div>
                        
                        <div class="form-group">
                            <label for="additional_instructions_1">Additional Instructions:</label>
                            <textarea id="additional_instructions_1" name="additional_instructions_1" placeholder="Special instructions (e.g., take with food)"></textarea>
                        </div>
                    </div>
                </div>
                
                <div id="medication-entries"></div>
                <input type="hidden" id="medication_count" name="medication_count" value="1">
                
                <button type="button" class="btn btn-outline" onclick="addMedication()">
                    <i class="fas fa-plus-circle"></i> Add Another Medication
                </button>
            </div>
            
            <div class="actions">
                <a href="patient_list.php?id=<?= urlencode($history_id); ?>" class="btn btn-outline">
                    <i class="fas fa-arrow-left"></i> Back to History
                </a>
                
                <button type="submit" class="btn btn-primary">
                    <i class="fas fa-paper-plane"></i> Submit Solution
                </button>
            </div>
        </form>
    </div>

    <script>
        let medicationCount = 1;

        // Function to add a medication entry dynamically
        function addMedication() {
            medicationCount++;
            const medicationContainer = document.getElementById('medication-entries');
            const medicationEntry = document.createElement('div');
            medicationEntry.className = 'medication-entry fade-in';
            medicationEntry.innerHTML = `
                <div class="medication-header">
                    <div class="pill-icon"><i class="fas fa-capsules"></i></div>
                    <h3>Medication #${medicationCount}</h3>
                </div>
                
                <div class="medication-row">
                    <div class="form-group">
                        <label for="medication_name_${medicationCount}">Medication Name:</label>
                        <input type="text" id="medication_name_${medicationCount}" name="medication_name_${medicationCount}" placeholder="Enter medication name">
                    </div>
                    
                    <div class="form-group">
                        <label for="medication_type_${medicationCount}">Medication Type:</label>
                        <select id="medication_type_${medicationCount}" name="medication_type_${medicationCount}">
                            <option value="tablet">Tablet</option>
                            <option value="syrup">Syrup</option>
                            <option value="eye_drop">Eye Drop</option>
                            <option value="cream">Cream</option>
                            <option value="other">Other</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="dosage_quantity_${medicationCount}">Dosage & Quantity:</label>
                        <input type="text" id="dosage_quantity_${medicationCount}" name="dosage_quantity_${medicationCount}" placeholder="e.g., 500mg, 30 tablets">
                    </div>
                </div>
                
                <div class="medication-row">
                    <div class="form-group">
                        <label for="morning_time_${medicationCount}">Morning Time:</label>
                        <input type="time" id="morning_time_${medicationCount}" name="morning_time_${medicationCount}">
                    </div>
                    
                    <div class="form-group">
                        <label for="afternoon_time_${medicationCount}">Afternoon Time:</label>
                        <input type="time" id="afternoon_time_${medicationCount}" name="afternoon_time_${medicationCount}">
                    </div>
                    
                    <div class="form-group">
                        <label for="evening_time_${medicationCount}">Evening Time:</label>
                        <input type="time" id="evening_time_${medicationCount}" name="evening_time_${medicationCount}">
                    </div>
                    
                    <div class="form-group">
                        <label for="night_time_${medicationCount}">Night Time:</label>
                        <input type="time" id="night_time_${medicationCount}" name="night_time_${medicationCount}">
                    </div>
                </div>
                
                <div class="date-row">
                    <div class="form-group">
                        <label for="start_date_${medicationCount}">Start Date:</label>
                        <input type="date" id="start_date_${medicationCount}" name="start_date_${medicationCount}">
                    </div>
                    
                    <div class="form-group">
                        <label for="end_date_${medicationCount}">End Date:</label>
                        <input type="date" id="end_date_${medicationCount}" name="end_date_${medicationCount}">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="additional_instructions_${medicationCount}">Additional Instructions:</label>
                    <textarea id="additional_instructions_${medicationCount}" name="additional_instructions_${medicationCount}" placeholder="Special instructions (e.g., take with food)"></textarea>
                </div>
            `;
            medicationContainer.appendChild(medicationEntry);
            document.getElementById('medication_count').value = medicationCount; // Update the hidden field with the new count
        }

        // Add event listeners for treatment type toggle
        document.getElementById('remote').addEventListener('change', function() {
            document.getElementById('appointment_date').classList.add('hidden');
            document.getElementById('doctor_solution_section').classList.remove('hidden');
            document.getElementById('medication_section').classList.remove('hidden');
            document.getElementById('doctor_solution').required = true;
        });

        document.getElementById('in_person').addEventListener('change', function() {
            document.getElementById('appointment_date').classList.remove('hidden');
            document.getElementById('doctor_solution_section').classList.add('hidden');
            document.getElementById('medication_section').classList.add('hidden');
            document.getElementById('doctor_solution').required = false;
        });

        // Fix video playback issues
        document.addEventListener('DOMContentLoaded', function() {
            const video = document.getElementById('custom-video');
            if (video) {
                // Add autoplay with muted to ensure it starts playing
                video.muted = true;
                
                // Attempt to play the video after a short delay
                setTimeout(() => {
                    video.play().catch(e => {
                        console.log('Video playback failed:', e);
                        // If autoplay fails, show a play button or message
                        video.controls = true;
                    });
                    
                    // After 1 second, unmute if the user interacts with the page
                    document.addEventListener('click', function() {
                        video.muted = false;
                    }, { once: true });
                }, 500);
            }
        });

        // Prevent right-click globally
        document.addEventListener("contextmenu", function(e) {
            e.preventDefault();
        });

        // Prevent keyboard shortcuts for downloading
        document.addEventListener("keydown", function(e) {
            if (e.key === "F12" || 
                (e.ctrlKey && e.shiftKey && e.key === "I") || 
                (e.ctrlKey && e.key === "s") || 
                (e.ctrlKey && e.key === "u")) {
                e.preventDefault();
            }
        });
    </script>
</body>
</html>
