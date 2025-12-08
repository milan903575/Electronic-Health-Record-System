<?php
include '../connection.php';

// Handle email check AJAX request
if (isset($_POST['email_check'])) {
    $email = mysqli_real_escape_string($conn, $_POST['email_check']);
    
    // Check if email exists in doctors table
    $query_doctor = "SELECT doctors.id, doctors.hospital_id, hospitals.hospital_name 
                     FROM doctors 
                     LEFT JOIN hospitals ON doctors.hospital_id = hospitals.id 
                     WHERE doctors.email = ?";
    $stmt_doctor = $conn->prepare($query_doctor);
    $stmt_doctor->bind_param("s", $email);
    $stmt_doctor->execute();
    $result_doctor = $stmt_doctor->get_result();
    
    if ($result_doctor->num_rows > 0) {
        $row = $result_doctor->fetch_assoc();
        if ($row['hospital_id'] !== null) {
            echo json_encode([
                'exists' => true, 
                'role' => 'doctor',
                'hospital_name' => $row['hospital_name'],
                'has_hospital' => true
            ]);
        } else {
            echo json_encode([
                'exists' => true,
                'role' => 'doctor', 
                'has_hospital' => false
            ]);
        }
        $stmt_doctor->close();
        exit;
    }
    $stmt_doctor->close();
    
    // Check if email exists in patients table
    $query_patient = "SELECT id FROM patients WHERE email = ?";
    $stmt_patient = $conn->prepare($query_patient);
    $stmt_patient->bind_param("s", $email);
    $stmt_patient->execute();
    $result_patient = $stmt_patient->get_result();
    
    if ($result_patient->num_rows > 0) {
        echo json_encode([
            'exists' => true,
            'role' => 'patient'
        ]);
        $stmt_patient->close();
        exit;
    }
    $stmt_patient->close();
    
    // Check if email exists in receptionists table
    $query_receptionist = "SELECT id FROM receptionists WHERE email = ?";
    $stmt_receptionist = $conn->prepare($query_receptionist);
    $stmt_receptionist->bind_param("s", $email);
    $stmt_receptionist->execute();
    $result_receptionist = $stmt_receptionist->get_result();
    
    if ($result_receptionist->num_rows > 0) {
        echo json_encode([
            'exists' => true,
            'role' => 'receptionist'
        ]);
        $stmt_receptionist->close();
        exit;
    }
    $stmt_receptionist->close();
    
    echo json_encode(['exists' => false]);
    exit;
}

// Handle hospital search AJAX request
if (isset($_GET['query'])) {
    $query = mysqli_real_escape_string($conn, $_GET['query']);
    $sql = "SELECT id, hospital_name FROM hospitals WHERE hospital_name LIKE ? OR zipcode LIKE ?";
    $stmt = $conn->prepare($sql);
    $search_query = "%" . $query . "%";
    $stmt->bind_param("ss", $search_query, $search_query);
    $stmt->execute();
    $result = $stmt->get_result();

    $output = '';
    while ($row = $result->fetch_assoc()) {
        $output .= '<div class="hospital-option" data-id="' . $row['id'] . '">' . htmlspecialchars($row['hospital_name']) . '</div>';
    }

    echo $output;
    $stmt->close();
    $conn->close();
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Registration</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary-color: #4361ee;
            --primary-light: #a0c4ff;
            --primary-dark: #3a0ca3;
            --secondary-color: #4cc9f0;
            --success-color: #06d6a0;
            --warning-color: #ffd166;
            --error-color: #ef476f;
            --text-color: #2b2d42;
            --text-light: #6c757d;
            --bg-color: #f8f9fa;
            --card-bg: #ffffff;
            --border-radius: 12px;
            --input-radius: 8px;
            --shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            --transition: all 0.3s ease;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: 'Outfit', sans-serif;
        }

        body {
            background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 40px 20px;
            color: var(--text-color);
        }

        .container {
            width: 100%;
            max-width: 800px;
            margin: 0 auto;
        }

        .form-container {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            overflow: hidden;
            position: relative;
            animation: fadeIn 0.5s ease;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(20px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .form-header {
            background: linear-gradient(to right, var(--primary-color), var(--primary-dark));
            padding: 30px;
            color: white;
            text-align: center;
            position: relative;
        }

        .form-header h1 {
            font-size: 28px;
            font-weight: 600;
            margin-bottom: 10px;
        }

        .form-header p {
            font-size: 16px;
            opacity: 0.9;
        }

        .form-body {
            padding: 40px 30px;
        }

        .form-section {
            margin-bottom: 30px;
        }

        .section-title {
            font-size: 18px;
            font-weight: 600;
            color: var(--primary-color);
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #f1f1f1;
        }

        .form-group {
            margin-bottom: 25px;
            position: relative;
        }

        .form-label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: var(--text-color);
        }

        .form-control {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid #e0e0e0;
            border-radius: var(--input-radius);
            background-color: #f9fafb;
            font-size: 16px;
            transition: var(--transition);
        }

        .form-control:focus {
            outline: none;
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
        }

        .input-group {
            position: relative;
        }

        .input-icon {
            position: absolute;
            left: 14px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-light);
            transition: var(--transition);
        }

        .input-group .form-control {
            padding-left: 45px;
        }

        .input-group .form-control:focus + .input-icon {
            color: var(--primary-color);
        }

        .form-row {
            display: flex;
            flex-wrap: wrap;
            margin: 0 -10px;
        }

        .form-col {
            flex: 1;
            padding: 0 10px;
            min-width: 250px;
        }

        .hospital-results {
            position: absolute;
            top: 100%;
            left: 0;
            width: 100%;
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 0 0 var(--input-radius) var(--input-radius);
            max-height: 200px;
            overflow-y: auto;
            z-index: 10;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
            display: none;
        }

        .hospital-option {
            padding: 12px 16px;
            cursor: pointer;
            transition: var(--transition);
        }

        .hospital-option:hover {
            background: #f5f7fa;
        }

        .alert {
            padding: 15px;
            border-radius: var(--input-radius);
            margin-bottom: 20px;
            animation: fadeIn 0.5s ease;
        }

        .alert-warning {
            background-color: rgba(255, 209, 102, 0.2);
            border: 1px solid var(--warning-color);
            color: #856404;
        }

        .alert-danger {
            background-color: rgba(239, 71, 111, 0.1);
            border: 1px solid var(--error-color);
            color: var(--error-color);
        }

        .alert-info {
            background-color: rgba(76, 201, 240, 0.1);
            border: 1px solid var(--secondary-color);
            color: var(--secondary-color);
        }

        .help-block {
            color: var(--error-color);
            font-size: 14px;
            margin-top: 5px;
        }

        .camera-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            margin-top: 15px;
            border: 2px dashed #e0e0e0;
            border-radius: var(--input-radius);
            padding: 20px;
            transition: var(--transition);
        }

        .camera-container:hover {
            border-color: var(--primary-light);
        }

        .video-container {
            width: 100%;
            max-width: 300px;
            margin: 15px 0;
            border-radius: var(--input-radius);
            overflow: hidden;
            display: none;
        }

        #video, #canvas {
            width: 100%;
            height: auto;
            border-radius: var(--input-radius);
            background-color: #f1f1f1;
        }

        .photo-options {
            display: flex;
            gap: 15px;
            margin-bottom: 15px;
        }

        .btn {
            display: inline-block;
            padding: 12px 24px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 30px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
            text-decoration: none;
        }

        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(67, 97, 238, 0.3);
        }

        .btn-secondary {
            background: #f1f1f1;
            color: var(--text-color);
        }

        .btn-secondary:hover {
            background: #e1e1e1;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.1);
        }

        .btn-sm {
            padding: 8px 16px;
            font-size: 14px;
        }

        .btn-login {
            background: var(--success-color);
            margin-top: 15px;
        }

        .btn-login:hover {
            background: #05b589;
        }

        .checkbox-group {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
        }

        .checkbox-group input[type="checkbox"] {
            position: absolute;
            opacity: 0;
            cursor: pointer;
            height: 0;
            width: 0;
        }

        .checkbox-label {
            position: relative;
            padding-left: 35px;
            cursor: pointer;
            font-size: 15px;
            user-select: none;
            display: inline-block;
        }

        .checkmark {
            position: absolute;
            top: 0;
            left: 0;
            height: 20px;
            width: 20px;
            background-color: #f1f5f9;
            border: 1px solid #cbd5e1;
            border-radius: 4px;
            transition: var(--transition);
        }

        .checkbox-group input[type="checkbox"]:checked ~ .checkmark {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }

        .checkmark:after {
            content: "";
            position: absolute;
            display: none;
        }

        .checkbox-group input[type="checkbox"]:checked ~ .checkmark:after {
            display: block;
        }

        .checkbox-label .checkmark:after {
            left: 7px;
            top: 3px;
            width: 5px;
            height: 10px;
            border: solid white;
            border-width: 0 2px 2px 0;
            transform: rotate(45deg);
        }

        .file-input-wrapper {
            position: relative;
            margin-top: 8px;
        }

        .file-input {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            opacity: 0;
            cursor: pointer;
        }

        .file-input-btn {
            display: flex;
            align-items: center;
            padding: 12px 16px;
            background-color: #f1f5f9;
            border: 1px dashed #cbd5e1;
            border-radius: var(--input-radius);
            color: var(--text-color);
            font-size: 15px;
            transition: var(--transition);
        }

        .file-input-btn i {
            margin-right: 10px;
            color: var(--primary-color);
        }

        .file-input-wrapper:hover .file-input-btn {
            background-color: #e2e8f0;
            border-color: var(--primary-color);
        }

        .file-name {
            margin-top: 8px;
            font-size: 14px;
            color: var(--text-light);
            word-break: break-all;
        }

        .photo-actions {
            display: flex;
            gap: 10px;
            margin-top: 15px;
            justify-content: center;
        }

        .preview-container {
            display: none;
            margin-top: 15px;
            text-align: center;
        }

        .photo-preview {
            max-width: 200px;
            border-radius: 8px;
            margin-bottom: 10px;
        }

        .form-footer {
            margin-top: 30px;
            text-align: center;
        }

        .login-redirect {
            text-align: center;
            margin-top: 20px;
        }

        .login-redirect p {
            margin-bottom: 15px;
            color: var(--text-light);
        }

        #registration-fields {
            transition: opacity 0.3s, height 0.3s;
        }

        @media (max-width: 768px) {
            .form-row {
                flex-direction: column;
            }
            
            .form-col {
                min-width: 100%;
            }
            
            .form-body {
                padding: 30px 20px;
            }
            
            .photo-options {
                flex-direction: column;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="form-container">
            <div class="form-header">
                <h1>Doctor Registration</h1>
                <p>Join our healthcare network as a medical professional</p>
            </div>
            
            <div class="form-body">
                <div id="email-message-container"></div>
                
                <form id="doctor_form" action="register_doctor.php" method="POST" enctype="multipart/form-data">
                    <!-- Email Section (Always Visible) -->
                    <div class="form-section">
                        <div class="form-group">
                            <label class="form-label" for="email">Email Address</label>
                            <div class="input-group">
                                <input type="email" name="email" id="email" class="form-control" placeholder="Enter your email address" required>
                                <i class="input-icon fas fa-envelope"></i>
                            </div>
                            <div id="email-feedback"></div>
                        </div>
                    </div>
                    
                    <!-- Login Redirect (Hidden by default, shown when email exists with hospital) -->
                    <div id="login-redirect" class="login-redirect" style="display: none;">
                        <p>Please login to access your dashboard</p>
                        <a href="../login.html" class="btn btn-login">
                            <i class="fas fa-sign-in-alt"></i> Go to Login
                        </a>
                    </div>
                    
                    <!-- Registration Fields (Hidden when email exists with hospital) -->
                    <div id="registration-fields">
                        <!-- Hospital Search -->
                        <div class="form-section">
                            <div class="form-group" id="hospital-group">
                                <label class="form-label" for="hospital_search">Select Hospital</label>
                                <div class="input-group" style="position: relative;">
                                    <input type="text" id="hospital_search" class="form-control" placeholder="Search by name or zip code">
                                    <i class="input-icon fas fa-hospital"></i>
                                    <input type="hidden" name="hospital_id" id="hospital_id">
                                    <div id="hospital_list" class="hospital-results"></div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Account Information -->
                        <div class="form-section">
                            <div class="section-title">Account Information</div>
                            
                            <div class="form-row">
                                <div class="form-col">
                                    <!-- Password -->
                                    <div class="form-group">
                                        <label class="form-label" for="password">Password</label>
                                        <div class="input-group">
                                            <input type="password" name="password" id="password" class="form-control" placeholder="Create a secure password" required>
                                            <i class="input-icon fas fa-lock"></i>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-col">
                                    <!-- Confirm Password -->
                                    <div class="form-group">
                                        <label class="form-label" for="confirm_password">Confirm Password</label>
                                        <div class="input-group">
                                            <input type="password" name="confirm_password" id="confirm_password" class="form-control" placeholder="Confirm your password" required>
                                            <i class="input-icon fas fa-lock"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Personal Information -->
                        <div class="form-section">
                            <div class="section-title">Personal Information</div>
                            
                            <div class="form-row">
                                <div class="form-col">
                                    <!-- First Name -->
                                    <div class="form-group">
                                        <label class="form-label" for="first_name">First Name</label>
                                        <div class="input-group">
                                            <input type="text" name="first_name" id="first_name" class="form-control" placeholder="Enter your first name" required>
                                            <i class="input-icon fas fa-user"></i>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-col">
                                    <!-- Last Name -->
                                    <div class="form-group">
                                        <label class="form-label" for="last_name">Last Name</label>
                                        <div class="input-group">
                                            <input type="text" name="last_name" id="last_name" class="form-control" placeholder="Enter your last name" required>
                                            <i class="input-icon fas fa-user"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="form-row">
                                <div class="form-col">
                                    <!-- Date of Birth -->
                                    <div class="form-group">
                                        <label class="form-label" for="dob">Date of Birth</label>
                                        <div class="input-group">
                                            <input type="date" name="dob" id="dob" class="form-control" required>
                                            <i class="input-icon fas fa-calendar"></i>
                                        </div>
                                    </div>
                                </div>
                                
                                <div class="form-col">
                                    <!-- Gender -->
                                    <div class="form-group">
                                        <label class="form-label" for="gender">Gender</label>
                                        <div class="input-group">
                                            <select name="gender" id="gender" class="form-control" required>
                                                <option value="">Select Gender</option>
                                                <option value="Male">Male</option>
                                                <option value="Female">Female</option>
                                                <option value="Other">Other</option>
                                            </select>
                                            <i class="input-icon fas fa-venus-mars"></i>
                                        </div>
                                    </div>
                                </div>
                            </div>
                            
                            <!-- Specialization -->
                            <div class="form-group">
                                <label class="form-label" for="specialization">Specialization</label>
                                <div class="input-group">
                                    <select name="specialization" id="specialization" class="form-control" required>
                                        <option value="" disabled selected>Select Specialization</option>
                                        <option value="General Physician">General Physician</option>
                                        <option value="Cardiologist">Cardiologist</option>
                                        <option value="Pulmonologist">Pulmonologist</option>
                                        <option value="Asthma Specialist">Asthma Specialist</option>
                                        <option value="Dermatologist">Dermatologist</option>
                                        <option value="Neurologist">Neurologist</option>
                                        <option value="Pediatrician">Pediatrician</option>
                                        <option value="Orthopedist">Orthopedist</option>
                                        <option value="Gastroenterologist">Gastroenterologist</option>
                                        <option value="Endocrinologist">Endocrinologist</option>
                                        <option value="Urologist">Urologist</option>
                                        <option value="Oncologist">Oncologist</option>
                                        <option value="Psychiatrist">Psychiatrist</option>
                                        <option value="Rheumatologist">Rheumatologist</option>
                                        <option value="Ophthalmologist">Ophthalmologist</option>
                                        <option value="ENT Specialist">ENT Specialist</option>
                                        <option value="Nephrologist">Nephrologist</option>
                                        <option value="Surgeon">Surgeon</option>
                                        <option value="Gynecologist">Gynecologist</option>
                                    </select>
                                    <i class="input-icon fas fa-stethoscope"></i>
                                </div>
                            </div>
                            
                            <!-- Location -->
                            <div class="form-group">
                                <label class="form-label" for="location">Location</label>
                                <div class="input-group">
                                    <input type="text" name="location" id="location" class="form-control" placeholder="Enter your location" required>
                                    <i class="input-icon fas fa-map-marker-alt"></i>
                                </div>
                            </div>
                            
                            <!-- Photo Upload with Camera Option -->
                            <div class="form-group">
                                <label class="form-label">Your Photo</label>
                                <div class="photo-options">
                                    <button type="button" id="camera-option" class="btn btn-secondary btn-sm">
                                        <i class="fas fa-camera"></i> Take Photo
                                    </button>
                                    <div class="file-input-wrapper">
                                        <div class="file-input-btn">
                                            <i class="fas fa-upload"></i>
                                            <span>Upload Photo</span>
                                        </div>
                                        <input type="file" name="photo_file" id="photo_file" class="file-input" accept="image/*">
                                    </div>
                                </div>
                                
                                <div class="camera-container" id="camera-container" style="display:none;">
                                    <div class="video-container" id="video-container">
                                        <video id="video" autoplay></video>
                                        <div class="photo-actions">
                                            <button type="button" id="capture-btn" class="btn btn-primary btn-sm">
                                                <i class="fas fa-camera"></i> Capture Photo
                                            </button>
                                        </div>
                                    </div>
                                    
                                    <canvas id="canvas" style="display:none;"></canvas>
                                    <input type="hidden" name="camera_photo" id="camera_photo">
                                    
                                    <div id="preview-container" class="preview-container">
                                        <img id="photo-preview" class="photo-preview">
                                        <div class="photo-actions">
                                            <button type="button" id="retake-photo-btn" class="btn btn-secondary btn-sm">
                                                <i class="fas fa-redo"></i> Retake Photo
                                            </button>
                                        </div>
                                    </div>
                                </div>
                                <div class="file-name" id="photo_file_name"></div>
                            </div>
                        </div>
                        
                        <!-- Document Information -->
                        <div class="form-section">
                            <div class="section-title">Document Information</div>
                            
                            <!-- Hospital ID Upload -->
                            <div class="form-group">
                                <label class="form-label" for="hospital_id_proof">Hospital ID</label>
                                <div class="file-input-wrapper">
                                    <div class="file-input-btn">
                                        <i class="fas fa-id-badge"></i>
                                        <span id="hospital_id_label">Upload Hospital ID</span>
                                    </div>
                                    <input type="file" name="hospital_id_proof" id="hospital_id_proof" class="file-input" required>
                                </div>
                                <div class="file-name" id="hospital_id_proof_name"></div>
                            </div>
                            
                            <!-- Government ID Upload -->
                            <div class="form-group">
                                <label class="form-label" for="gov_id_proof">Government ID</label>
                                <div class="file-input-wrapper">
                                    <div class="file-input-btn">
                                        <i class="fas fa-id-card"></i>
                                        <span id="gov_id_label">Upload Government ID</span>
                                    </div>
                                    <input type="file" name="gov_id_proof" id="gov_id_proof" class="file-input" required>
                                </div>
                                <div class="file-name" id="gov_id_proof_name"></div>
                            </div>

                            <!-- Signature upload -->
                            <div class="form-group">
                                <label class="form-label" for="signature">Signature</label>
                                <div class="file-input-wrapper">
                                    <div class="file-input-btn">
                                        <i class="fas fa-signature"></i>
                                        <span id="signature_label">Upload Signature</span>
                                    </div>
                                    <input type="file" name="signature" id="signature" class="file-input" required>
                                </div>
                                <div class="file-name" id="signature_name"></div>
                            </div>

                        </div>
                        
                        <!-- Terms and Consent -->
                        <div class="form-section">
                            <div class="checkbox-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" name="terms" id="terms" required>
                                    <span class="checkmark"></span>
                                    I agree to the terms and conditions
                                </label>
                            </div>
                            
                            <div class="checkbox-group">
                                <label class="checkbox-label">
                                    <input type="checkbox" name="consent" id="consent" required>
                                    <span class="checkmark"></span>
                                    I consent to data processing
                                </label>
                            </div>
                        </div>
                        
                        <!-- Submit Button -->
                        <div class="form-footer">
                            <button type="submit" class="btn">Register <i class="fas fa-user-md"></i></button>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>
    <script>
        $(document).ready(function() {
            // Set the minimum date of birth to 21 years ago
            var today = new Date();
            var minAgeDate = new Date(today.setFullYear(today.getFullYear() - 21));
            var minDate = minAgeDate.toISOString().split('T')[0];
            $('#dob').attr('max', minDate);
            
            // Variables for AJAX control
            let activeRequest = null;
                        
            // Email check with improved error handling
            $('#email').on('input', function() {
                const email = $(this).val().trim();
                
                // Clear feedback messages
                $('#email-feedback').html('');
                $('#email-message-container').html('');
                
                // Always show registration fields by default
                $('#registration-fields').show();
                $('#login-redirect').hide();
                
                // Cancel any pending request
                if (activeRequest) {
                    activeRequest.abort();
                    activeRequest = null;
                }
                
                if (email && isValidEmail(email)) {
                    // Show loading indicator
                    $('#email-feedback').html(`
                        <div style="color: var(--text-light); margin-top: 5px;">
                            <i class="fas fa-spinner fa-spin"></i> Checking email...
                        </div>
                    `);
                    
                    activeRequest = $.ajax({
                        url: '',
                        type: 'POST',
                        data: { email_check: email },
                        dataType: 'json',
                        success: function(response) {
                            if (response.exists) {
                                if (response.role === 'doctor') {
                                    if (response.has_hospital) {
                                        // Doctor with hospital
                                        $('#email-message-container').html(`
                                            <div class="alert alert-warning">
                                                <i class="fas fa-exclamation-triangle"></i> You have already registered with ${response.hospital_name}. Please contact your hospital through your dashboard if you need to resign.
                                            </div>
                                        `);
                                        $('#registration-fields').hide();
                                        $('#login-redirect').show();
                                    } else {
                                        // Doctor without hospital
                                        $('#email-message-container').html(`
                                            <div class="alert alert-info">
                                                <i class="fas fa-info-circle"></i> Your email exists but you haven't registered with any hospital. You can proceed with your registration.
                                            </div>
                                        `);
                                        $('#registration-fields').show();
                                    }
                                } else if (response.role === 'patient') {
                                    // Patient
                                    $('#email-message-container').html(`
                                        <div class="alert alert-danger">
                                            <i class="fas fa-exclamation-circle"></i> This email is already registered as a patient. Please use a different email address.
                                        </div>
                                    `);
                                    $('#registration-fields').hide();
                                    $('#login-redirect').show();
                                } else if (response.role === 'receptionist') {
                                    // Receptionist
                                    $('#email-message-container').html(`
                                        <div class="alert alert-danger">
                                            <i class="fas fa-exclamation-circle"></i> This email is already registered as a receptionist. Please use a different email address.
                                        </div>
                                    `);
                                    $('#registration-fields').hide();
                                    $('#login-redirect').show();
                                }
                            } else {
                                // Email doesn't exist
                                $('#email-feedback').html(`
                                    <div style="color: var(--success-color); margin-top: 5px;">
                                        <i class="fas fa-check-circle"></i> Email is available
                                    </div>
                                `);
                                $('#registration-fields').show();
                            }
                        },
                        error: function(xhr, status) {
                            // For any error, just clear the loading indicator and show the form
                            // No error message will be displayed
                            $('#email-feedback').html('');
                            $('#registration-fields').show();
                            $('#login-redirect').hide();
                        }
                    });
                }
            });

            // Hospital search functionality
            $('#hospital_search').on('input', function() {
                let query = $(this).val().trim();
                
                if (query.length > 0) {
                    $.ajax({
                        url: '',
                        type: 'GET',
                        data: { query: query },
                        success: function(response) {
                            if (response.trim()) {
                                $('#hospital_list').html(response).show();
                            } else {
                                $('#hospital_list').html('<div class="hospital-option">No hospitals found</div>').show();
                            }
                        },
                        error: function() {
                            $('#hospital_list').html('<div class="hospital-option">Error retrieving hospitals</div>').show();
                        }
                    });
                } else {
                    $('#hospital_list').hide();
                }
            });
            
            // Hospital selection
            $(document).on('click', '.hospital-option', function() {
                const hospitalId = $(this).data('id');
                const hospitalName = $(this).text();
                
                $('#hospital_search').val(hospitalName);
                $('#hospital_id').val(hospitalId);
                $('#hospital_list').hide();
            });
            
            // Hide hospital list when clicking outside
            $(document).on('click', function(e) {
                if (!$(e.target).closest('#hospital_search, #hospital_list').length) {
                    $('#hospital_list').hide();
                }
            });
            
            // File input display
            document.querySelectorAll('.file-input').forEach(input => {
                input.addEventListener('change', function() {
                    const fileName = this.files[0]?.name || 'No file chosen';
                    const fileNameElement = document.getElementById(this.id + '_name');
                    
                    if (this.files[0]) {
                        fileNameElement.textContent = fileName;
                    } else {
                        fileNameElement.textContent = '';
                    }
                });
            });
            
            // Camera functionality
            const cameraOption = document.getElementById('camera-option');
            const cameraContainer = document.getElementById('camera-container');
            const videoContainer = document.getElementById('video-container');
            const video = document.getElementById('video');
            const canvas = document.getElementById('canvas');
            const captureButton = document.getElementById('capture-btn');
            const cameraPhotoInput = document.getElementById('camera_photo');
            const previewContainer = document.getElementById('preview-container');
            const photoPreview = document.getElementById('photo-preview');
            const retakePhotoButton = document.getElementById('retake-photo-btn');
            
            let stream = null;
            
            cameraOption.addEventListener('click', function() {
                cameraContainer.style.display = 'block';
                openCamera();
            });
            
            function openCamera() {
                navigator.mediaDevices.getUserMedia({ video: true })
                    .then((mediaStream) => {
                        stream = mediaStream;
                        video.srcObject = stream;
                        videoContainer.style.display = 'block';
                        previewContainer.style.display = 'none';
                    })
                    .catch((err) => {
                        console.error("Error accessing the webcam: ", err);
                        alert("Webcam access is required to capture your profile picture.");
                    });
            }
            
            captureButton.addEventListener('click', function() {
                const context = canvas.getContext('2d');
                canvas.width = video.videoWidth;
                canvas.height = video.videoHeight;
                context.drawImage(video, 0, 0, canvas.width, canvas.height);
                
                // Convert to base64
                const imageData = canvas.toDataURL('image/png');
                cameraPhotoInput.value = imageData;
                
                // Show preview
                photoPreview.src = imageData;
                previewContainer.style.display = 'block';
                videoContainer.style.display = 'none';
                
                // Stop camera stream
                stopCamera();
                
                // Clear file input since we're using camera
                $('#photo_file').val('');
                $('#photo_file_name').text('');
            });
            
            // Add retake photo functionality
            retakePhotoButton.addEventListener('click', function() {
                // Clear the current photo
                cameraPhotoInput.value = '';
                
                // Hide preview and show camera again
                previewContainer.style.display = 'none';
                
                // Restart camera
                openCamera();
            });
            
            // Clear camera photo when file is uploaded
            $('#photo_file').on('change', function() {
                if (this.files.length > 0) {
                    // Clear camera photo
                    $('#camera_photo').val('');
                    previewContainer.style.display = 'none';
                    
                    // Stop camera if running
                    stopCamera();
                    cameraContainer.style.display = 'none';
                }
            });
            
            function stopCamera() {
                if (stream) {
                    const tracks = stream.getTracks();
                    tracks.forEach(track => track.stop());
                    stream = null;
                }
            }
            
            // Form validation
            $('#doctor_form').on('submit', function(e) {
                // If login redirect is visible, don't submit the form
                if ($('#login-redirect').is(':visible')) {
                    e.preventDefault();
                    return false;
                }
                
                // Check if there's an error message for patient or receptionist
                if ($('#email-message-container .alert-danger').length > 0) {
                    e.preventDefault();
                    $('html, body').animate({
                        scrollTop: $('#email').offset().top - 100
                    }, 200);
                    return false;
                }
                
                let isValid = true;
                
                // Validate photo (either uploaded or taken with camera)
                if (!$('#photo_file').val() && !$('#camera_photo').val()) {
                    e.preventDefault();
                    alert('Please upload or take a photo');
                    isValid = false;
                }
                
                // Validate hospital selection
                if (!$('#hospital_id').val()) {
                    e.preventDefault();
                    alert('Please select a hospital');
                    isValid = false;
                }
                
                // Validate password match
                if ($('#password').val() !== $('#confirm_password').val()) {
                    e.preventDefault();
                    alert('Passwords do not match');
                    isValid = false;
                }
                
                return isValid;
            });
            
            function isValidEmail(email) {
                const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                return regex.test(email);
            }
        });
    </script>
</body>
</html>
