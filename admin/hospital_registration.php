<?php
// Include database connection
include '../connection.php';

// Initialize variables
$hospital_name = $country = $state = $city = $zip_code = $email = $password = $confirm_password = "";
$hospital_name_err = $country_err = $state_err = $city_err = $zip_code_err = $email_err = $password_err = $confirm_password_err = "";
$licence_file_err = $hospital_seal_err = $gov_id_proof_err = $director_approve_err = $reg_fee_err = $duration_err = $hospital_logo_err = "";
$registration_fee = $registration_duration = "";

// Process form data when form is submitted
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Validate hospital name
    if (empty(trim($_POST["hospital_name"]))) {
        $hospital_name_err = "Please enter hospital name";
    } else {
        $hospital_name = trim($_POST["hospital_name"]);
    }
    
    // Validate country
    if (empty(trim($_POST["country"]))) {
        $country_err = "Please enter country";
    } else {
        $country = trim($_POST["country"]);
    }
    
    // Validate state
    if (empty(trim($_POST["state"]))) {
        $state_err = "Please enter state";
    } else {
        $state = trim($_POST["state"]);
    }
    
    // Validate city
    if (empty(trim($_POST["city"]))) {
        $city_err = "Please enter city";
    } else {
        $city = trim($_POST["city"]);
    }
    
    // Validate zip code
    if (empty(trim($_POST["zip_code"]))) {
        $zip_code_err = "Please enter zip code";
    } else {
        $zip_code = trim($_POST["zip_code"]);
    }
    
    // Validate email
    if (empty(trim($_POST["email"]))) {
        $email_err = "Please enter email";
    } else {
        // Prepare a select statement
        $sql = "SELECT id FROM hospitals WHERE email = ?";
        
        if ($stmt = $conn->prepare($sql)) {
            // Bind variables to the prepared statement as parameters
            $stmt->bind_param("s", $param_email);
            
            // Set parameters
            $param_email = trim($_POST["email"]);
            
            // Attempt to execute the prepared statement
            if ($stmt->execute()) {
                // Store result
                $stmt->store_result();
                
                if ($stmt->num_rows == 1) {
                    $email_err = "This email is already taken";
                } else {
                    $email = trim($_POST["email"]);
                }
            }

            // Close statement
            $stmt->close();
        }
    }
    
    // Validate password
    if (empty(trim($_POST["password"]))) {
        $password_err = "Please enter a password";     
    } elseif (strlen(trim($_POST["password"])) < 6) {
        $password_err = "Password must have at least 6 characters";
    } else {
        $password = trim($_POST["password"]);
    }
    
    // Validate confirm password
    if (empty(trim($_POST["confirm_password"]))) {
        $confirm_password_err = "Please confirm password";     
    } else {
        $confirm_password = trim($_POST["confirm_password"]);
        if (empty($password_err) && ($password != $confirm_password)) {
            $confirm_password_err = "Password did not match";
        }
    }
    
    // Validate file uploads
    if (!isset($_FILES["licence_file"]) || $_FILES["licence_file"]["error"] > 0) {
        $licence_file_err = "Please upload hospital license";
    }
    
    if (!isset($_FILES["hospital_seal"]) || $_FILES["hospital_seal"]["error"] > 0) {
        $hospital_seal_err = "Please upload hospital seal";
    }
    
    // Validate hospital logo
    if (!isset($_FILES["hospital_logo"]) || $_FILES["hospital_logo"]["error"] > 0) {
        $hospital_logo_err = "Please upload hospital logo";
    }
    
    if (!isset($_FILES["gov_id_proof"]) || $_FILES["gov_id_proof"]["error"] > 0) {
        $gov_id_proof_err = "Please upload government ID proof";
    }
    
    if (!isset($_FILES["director_approve"]) || $_FILES["director_approve"]["error"] > 0) {
        $director_approve_err = "Please upload director approval letter";
    }
    
    // Check if collect fee is checked
    if (isset($_POST["collect_fee"]) && $_POST["collect_fee"] == "on") {
        // Validate registration fee
        if (empty(trim($_POST["registration_fee"]))) {
            $reg_fee_err = "Please enter registration fee";
        } else {
            $registration_fee = trim($_POST["registration_fee"]);
        }
        
        // Validate duration
        if (empty(trim($_POST["registration_duration"]))) {
            $duration_err = "Please enter registration duration";
        } else {
            $registration_duration = trim($_POST["registration_duration"]);
        }
    }
    
    // Check input errors before inserting in database
    if (empty($hospital_name_err) && empty($country_err) && empty($state_err) && empty($city_err) && 
        empty($zip_code_err) && empty($email_err) && empty($password_err) && empty($confirm_password_err) && 
        empty($licence_file_err) && empty($hospital_seal_err) && empty($hospital_logo_err) && 
        empty($gov_id_proof_err) && empty($director_approve_err) && empty($reg_fee_err) && empty($duration_err)) {
        
        // Read uploaded files as BLOB data
        $licence_file_blob = file_get_contents($_FILES["licence_file"]["tmp_name"]);
        $hospital_seal_blob = file_get_contents($_FILES["hospital_seal"]["tmp_name"]);
        $hospital_logo_blob = file_get_contents($_FILES["hospital_logo"]["tmp_name"]);
        $gov_id_proof_blob = file_get_contents($_FILES["gov_id_proof"]["tmp_name"]);
        $director_approve_blob = file_get_contents($_FILES["director_approve"]["tmp_name"]);
        
        $registration_fee = isset($_POST["registration_fee"]) ? $_POST["registration_fee"] : 0;
        $registration_duration = isset($_POST["registration_duration"]) ? $_POST["registration_duration"] : 0;
        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        
        // Prepare an insert statement with BLOB data
        $sql = "INSERT INTO hospitals (hospital_name, country, state, city, zipcode, email, password, 
                license_file, hospital_seal, hospital_logo, gov_id_proof, director_approve, registration_fee, registration_duration) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

        if ($stmt = $conn->prepare($sql)) {
            // Bind all parameters directly
            $stmt->bind_param("ssssssssssssdd", 
                $hospital_name,
                $country,
                $state,
                $city,
                $zip_code,
                $email,
                $hashed_password,
                $licence_file_blob,
                $hospital_seal_blob,
                $hospital_logo_blob,
                $gov_id_proof_blob,
                $director_approve_blob,
                $registration_fee,
                $registration_duration
            );
            
            // Attempt to execute the prepared statement
            if ($stmt->execute()) {
                // Redirect to login page after successful registration
                header("location: Admin_login.php");
                exit();
            }

            // Close statement
            $stmt->close();
        }
    }
    
    // Close connection
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hospital Registration</title>
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

        .form-container {
            background: var(--card-bg);
            border-radius: var(--border-radius);
            box-shadow: var(--shadow);
            width: 100%;
            max-width: 800px;
            margin: 0 auto;
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
            color: white;
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

        .fee-fields {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: var(--input-radius);
            margin-top: 10px;
            display: none;
            animation: fadeIn 0.3s ease;
        }

        .btn {
            display: inline-block;
            padding: 14px 24px;
            background: var(--primary-color);
            color: white;
            border: none;
            border-radius: 30px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: var(--transition);
            text-align: center;
            width: 100%;
        }

        .btn:hover {
            background: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(67, 97, 238, 0.3);
        }

        .btn-login {
            background: var(--success-color);
            margin-top: 15px;
        }

        .btn-login:hover {
            background: #05b589;
            box-shadow: 0 5px 15px rgba(6, 214, 160, 0.3);
        }

        .help-block {
            color: var(--error-color);
            font-size: 14px;
            margin-top: 5px;
        }

        .form-group.has-error .form-control {
            border-color: var(--error-color);
        }

        .form-footer {
            text-align: center;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #f1f1f1;
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
        }
    </style>
</head>
<body>
    <div class="form-container">
        <div class="form-header">
            <h1>Hospital Registration</h1>
            <p>Register your hospital to join our healthcare network</p>
        </div>
        
        <div class="form-body">
            <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" enctype="multipart/form-data">
                <!-- Hospital Information Section -->
                <div class="form-section">
                    <div class="section-title">Hospital Information</div>
                    
                    <div class="form-group <?php echo (!empty($hospital_name_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="hospital_name">Hospital Name</label>
                        <div class="input-group">
                            <input type="text" name="hospital_name" id="hospital_name" class="form-control" value="<?php echo $hospital_name; ?>" placeholder="Enter hospital name" required>
                            <i class="input-icon fas fa-hospital"></i>
                        </div>
                        <span class="help-block"><?php echo $hospital_name_err; ?></span>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($country_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="country">Country</label>
                                <div class="input-group">
                                    <input type="text" name="country" id="country" class="form-control" value="<?php echo $country; ?>" placeholder="Enter country" required>
                                    <i class="input-icon fas fa-globe"></i>
                                </div>
                                <span class="help-block"><?php echo $country_err; ?></span>
                            </div>
                        </div>
                        
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($state_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="state">State</label>
                                <div class="input-group">
                                    <input type="text" name="state" id="state" class="form-control" value="<?php echo $state; ?>" placeholder="Enter state" required>
                                    <i class="input-icon fas fa-map-marker-alt"></i>
                                </div>
                                <span class="help-block"><?php echo $state_err; ?></span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($city_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="city">City</label>
                                <div class="input-group">
                                    <input type="text" name="city" id="city" class="form-control" value="<?php echo $city; ?>" placeholder="Enter city" required>
                                    <i class="input-icon fas fa-city"></i>
                                </div>
                                <span class="help-block"><?php echo $city_err; ?></span>
                            </div>
                        </div>
                        
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($zip_code_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="zip_code">Zip Code</label>
                                <div class="input-group">
                                    <input type="text" name="zip_code" id="zip_code" class="form-control" value="<?php echo $zip_code; ?>" placeholder="Enter zip code" required>
                                    <i class="input-icon fas fa-map-pin"></i>
                                </div>
                                <span class="help-block"><?php echo $zip_code_err; ?></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Documents Section -->
                <div class="form-section">
                    <div class="section-title">Required Documents</div>
                    
                    <div class="form-group <?php echo (!empty($licence_file_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="licence_file">Hospital License</label>
                        <div class="file-input-wrapper">
                            <div class="file-input-btn">
                                <i class="fas fa-file-medical"></i>
                                <span id="licence_file_label">Choose license file</span>
                            </div>
                            <input type="file" name="licence_file" id="licence_file" class="file-input" required>
                        </div>
                        <div class="file-name" id="licence_file_name"></div>
                        <span class="help-block"><?php echo $licence_file_err; ?></span>
                    </div>
                    
                    <div class="form-group <?php echo (!empty($hospital_seal_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="hospital_seal">Hospital Seal</label>
                        <div class="file-input-wrapper">
                            <div class="file-input-btn">
                                <i class="fas fa-stamp"></i>
                                <span id="hospital_seal_label">Upload hospital seal</span>
                            </div>
                            <input type="file" name="hospital_seal" id="hospital_seal" class="file-input" required>
                        </div>
                        <div class="file-name" id="hospital_seal_name"></div>
                        <span class="help-block"><?php echo $hospital_seal_err; ?></span>
                    </div>
                    
                    <div class="form-group <?php echo (!empty($hospital_logo_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="hospital_logo">Hospital Logo</label>
                        <div class="file-input-wrapper">
                            <div class="file-input-btn">
                                <i class="fas fa-image"></i>
                                <span id="hospital_logo_label">Upload hospital logo</span>
                            </div>
                            <input type="file" name="hospital_logo" id="hospital_logo" class="file-input" accept="image/*" required>
                        </div>
                        <div class="file-name" id="hospital_logo_name"></div>
                        <span class="help-block"><?php echo $hospital_logo_err; ?></span>
                    </div>
                    
                    <div class="form-group <?php echo (!empty($gov_id_proof_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="gov_id_proof">Government ID Proof</label>
                        <div class="file-input-wrapper">
                            <div class="file-input-btn">
                                <i class="fas fa-id-card"></i>
                                <span id="gov_id_proof_label">Upload ID proof</span>
                            </div>
                            <input type="file" name="gov_id_proof" id="gov_id_proof" class="file-input" required>
                        </div>
                        <div class="file-name" id="gov_id_proof_name"></div>
                        <span class="help-block"><?php echo $gov_id_proof_err; ?></span>
                    </div>
                    
                    <div class="form-group <?php echo (!empty($director_approve_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="director_approve">Director Approval Letter</label>
                        <div class="file-input-wrapper">
                            <div class="file-input-btn">
                                <i class="fas fa-file-signature"></i>
                                <span id="director_approve_label">Upload approval letter</span>
                            </div>
                            <input type="file" name="director_approve" id="director_approve" class="file-input" required>
                        </div>
                        <div class="file-name" id="director_approve_name"></div>
                        <span class="help-block"><?php echo $director_approve_err; ?></span>
                    </div>
                </div>
                
                <!-- Registration Fee Section -->
                <div class="form-section">
                    <div class="section-title">Registration Fee</div>
                    
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="collect_fee" id="collect_fee" onclick="toggleFeeFields()">
                            <span class="checkmark"></span>
                            Collect Registration Fee from Patients
                        </label>
                    </div>
                    
                    <div id="fee_fields" class="fee-fields">
                        <div class="form-row">
                            <div class="form-col">
                                <div class="form-group <?php echo (!empty($reg_fee_err)) ? 'has-error' : ''; ?>">
                                    <label class="form-label" for="registration_fee">Registration Fee ($)</label>
                                    <div class="input-group">
                                        <input type="number" name="registration_fee" id="registration_fee" class="form-control" value="<?php echo $registration_fee; ?>" placeholder="0.00" step="0.01" min="0">
                                        <i class="input-icon fas fa-dollar-sign"></i>
                                    </div>
                                    <span class="help-block"><?php echo $reg_fee_err; ?></span>
                                </div>
                            </div>
                            
                            <div class="form-col">
                                <div class="form-group <?php echo (!empty($duration_err)) ? 'has-error' : ''; ?>">
                                    <label class="form-label" for="registration_duration">Duration (days)</label>
                                    <div class="input-group">
                                        <input type="number" name="registration_duration" id="registration_duration" class="form-control" value="<?php echo $registration_duration; ?>" placeholder="30" min="1">
                                        <i class="input-icon fas fa-calendar-day"></i>
                                    </div>
                                    <span class="help-block"><?php echo $duration_err; ?></span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Account Information Section -->
                <div class="form-section">
                    <div class="section-title">Account Information</div>
                    
                    <div class="form-group <?php echo (!empty($email_err)) ? 'has-error' : ''; ?>">
                        <label class="form-label" for="email">Email Address</label>
                        <div class="input-group">
                            <input type="email" name="email" id="email" class="form-control" value="<?php echo $email; ?>" placeholder="hospital@example.com" required>
                            <i class="input-icon fas fa-envelope"></i>
                        </div>
                        <span class="help-block"><?php echo $email_err; ?></span>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($password_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="password">Password</label>
                                <div class="input-group">
                                    <input type="password" name="password" id="password" class="form-control" placeholder="Create a secure password" required>
                                    <i class="input-icon fas fa-lock"></i>
                                </div>
                                <span class="help-block"><?php echo $password_err; ?></span>
                            </div>
                        </div>
                        
                        <div class="form-col">
                            <div class="form-group <?php echo (!empty($confirm_password_err)) ? 'has-error' : ''; ?>">
                                <label class="form-label" for="confirm_password">Confirm Password</label>
                                <div class="input-group">
                                    <input type="password" name="confirm_password" id="confirm_password" class="form-control" placeholder="Confirm your password" required>
                                    <i class="input-icon fas fa-lock"></i>
                                </div>
                                <span class="help-block"><?php echo $confirm_password_err; ?></span>
                            </div>
                        </div>
                    </div>
                </div>
                
                <!-- Terms and Consent -->
                <div class="form-section">
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="terms" id="terms" required>
                            <span class="checkmark"></span>
                            I agree to the Terms and Conditions
                        </label>
                    </div>
                    
                    <div class="checkbox-group">
                        <label class="checkbox-label">
                            <input type="checkbox" name="consent" id="consent" required>
                            <span class="checkmark"></span>
                            I consent to the processing of my data
                        </label>
                    </div>
                </div>
                
                <!-- Submit Button -->
                <button type="submit" class="btn">Register Hospital</button>
                
                <!-- Login Link -->
                <div class="form-footer">
                    <p>Already registered?</p>
                    <a href="Admin_login.php" class="btn btn-login">
                        <i class="fas fa-sign-in-alt"></i> Login to your account
                    </a>
                </div>
            </form>
        </div>
    </div>

    <script>
        // Toggle Fee Fields
        function toggleFeeFields() {
            const feeFields = document.getElementById('fee_fields');
            feeFields.style.display = document.getElementById('collect_fee').checked ? 'block' : 'none';
        }
        
        // File input display
        document.querySelectorAll('.file-input').forEach(input => {
            input.addEventListener('change', function() {
                const fileName = this.files[0]?.name || 'No file chosen';
                const fileNameElement = document.getElementById(this.id + '_name');
                const labelElement = document.getElementById(this.id + '_label');
                
                if (this.files[0]) {
                    fileNameElement.textContent = fileName;
                    labelElement.textContent = 'File selected';
                } else {
                    fileNameElement.textContent = '';
                    labelElement.textContent = 'Choose file';
                }
            });
        });
    </script>
</body>
</html>
