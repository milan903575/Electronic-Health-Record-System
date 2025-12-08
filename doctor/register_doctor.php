<?php
// Include connection
include '../connection.php';

// Sanitize POST data
$first_name = mysqli_real_escape_string($conn, trim($_POST['first_name']));
$last_name = mysqli_real_escape_string($conn, trim($_POST['last_name']));
$specialization = mysqli_real_escape_string($conn, trim($_POST['specialization']));
$email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
$password = mysqli_real_escape_string($conn, trim($_POST['password']));
$confirm_password = mysqli_real_escape_string($conn, trim($_POST['confirm_password']));
$hospital_id = intval($_POST['hospital_id']);
$location = mysqli_real_escape_string($conn, trim($_POST['location']));
$dob = mysqli_real_escape_string($conn, trim($_POST['dob']));
$gender = mysqli_real_escape_string($conn, trim($_POST['gender']));
$terms = isset($_POST['terms']) ? 1 : 0;
$consent = isset($_POST['consent']) ? 1 : 0;

// Initialize file variables
$gov_id_proof = null;
$hospital_id_proof = null;
$profile_picture = null;
$signature = null;

// File upload validation settings
$allowed_types = ['image/jpeg', 'image/png', 'image/jpg', 'application/pdf'];
$max_file_size = 5 * 1024 * 1024; // 5MB in bytes

// Handle government ID proof upload
if (!empty($_FILES['gov_id_proof']['tmp_name'])) {
    if (!in_array($_FILES['gov_id_proof']['type'], $allowed_types)) {
        die("Invalid file type for government ID. Only JPEG, PNG, and PDF files are allowed.");
    }
    if ($_FILES['gov_id_proof']['size'] > $max_file_size) {
        die("Government ID file size exceeds the maximum limit of 5MB.");
    }
    $gov_id_proof = file_get_contents($_FILES['gov_id_proof']['tmp_name']);
}

// Handle hospital ID proof upload
if (!empty($_FILES['hospital_id_proof']['tmp_name'])) {
    if (!in_array($_FILES['hospital_id_proof']['type'], $allowed_types)) {
        die("Invalid file type for hospital ID. Only JPEG, PNG, and PDF files are allowed.");
    }
    if ($_FILES['hospital_id_proof']['size'] > $max_file_size) {
        die("Hospital ID file size exceeds the maximum limit of 5MB.");
    }
    $hospital_id_proof = file_get_contents($_FILES['hospital_id_proof']['tmp_name']);
}

// Handle profile picture (file upload OR camera capture)
// Check for file upload first
if (!empty($_FILES['photo_file']['tmp_name'])) {
    if (!in_array($_FILES['photo_file']['type'], $allowed_types)) {
        die("Invalid file type for profile picture. Only JPEG, PNG, and PDF files are allowed.");
    }
    if ($_FILES['photo_file']['size'] > $max_file_size) {
        die("Profile picture file size exceeds the maximum limit of 5MB.");
    }
    $profile_picture = file_get_contents($_FILES['photo_file']['tmp_name']);
}
// If no file upload, check for camera capture
elseif (!empty($_POST['camera_photo'])) {
    $data_url = $_POST['camera_photo'];
    if (preg_match('/^data:image\/(\w+);base64,/', $data_url, $type)) {
        $data = substr($data_url, strpos($data_url, ',') + 1);
        $profile_picture = base64_decode($data);
        
        if ($profile_picture === false) {
            die("Invalid camera photo data.");
        }
    } else {
        die("Invalid camera photo format.");
    }
}

// Handle signature file upload
if (!empty($_FILES['signature']['tmp_name'])) {
    if (!in_array($_FILES['signature']['type'], $allowed_types)) {
        die("Invalid file type for signature. Only JPEG, PNG, and PDF files are allowed.");
    }
    if ($_FILES['signature']['size'] > $max_file_size) {
        die("Signature file size exceeds the maximum limit of 5MB.");
    }
    $signature = file_get_contents($_FILES['signature']['tmp_name']);
}
// Also handle signature from POST data (base64 encoded) if using canvas
elseif (!empty($_POST['signature'])) {
    $signature_data_url = $_POST['signature'];
    if (preg_match('/^data:image\/(\w+);base64,/', $signature_data_url, $type)) {
        $signature_data = substr($signature_data_url, strpos($signature_data_url, ',') + 1);
        $signature = base64_decode($signature_data);
        
        if ($signature === false) {
            die("Invalid signature data.");
        }
    } else {
        die("Invalid signature format.");
    }
}

// Validation
$errors = [];

// Basic field validation
if (empty($first_name)) $errors[] = "First name is required.";
if (empty($last_name)) $errors[] = "Last name is required.";
if (empty($email)) $errors[] = "Email is required.";
if (empty($password)) $errors[] = "Password is required.";
if (empty($specialization)) $errors[] = "Specialization is required.";
if (empty($location)) $errors[] = "Location is required.";
if (empty($dob)) $errors[] = "Date of birth is required.";
if (empty($gender)) $errors[] = "Gender is required.";

// Validate signature
if (empty($signature)) $errors[] = "Signature is required.";

// Validate password match
if ($password !== $confirm_password) {
    $errors[] = "Passwords do not match.";
}

// Check if email exists in doctors, patients, or receptionists
$email_check = $conn->prepare("SELECT id FROM doctors WHERE email = ? UNION SELECT id FROM patients WHERE email = ? UNION SELECT id FROM receptionist WHERE email = ?");
$email_check->bind_param("sss", $email, $email, $email);
$email_check->execute();
$email_check_result = $email_check->get_result();
if ($email_check_result->num_rows > 0) {
    $errors[] = "This email is already registered in the system.";
}
$email_check->close();

// Validate hospital ID
if (empty($hospital_id)) {
    $errors[] = "Hospital not selected.";
} else {
    // Check if hospital ID exists in the database
    $hospital_check = $conn->prepare("SELECT id FROM hospitals WHERE id = ?");
    $hospital_check->bind_param("i", $hospital_id);
    $hospital_check->execute();
    $hospital_check_result = $hospital_check->get_result();
    if ($hospital_check_result->num_rows === 0) {
        $errors[] = "Hospital not found.";
    }
    $hospital_check->close();
}

// Validate terms and consent
if (!$terms) $errors[] = "You must agree to terms and conditions.";
if (!$consent) $errors[] = "You must give consent for data processing.";

// If there are errors, display them
if (!empty($errors)) {
    echo "<div class='message-container'>
            <h2 class='error-heading'>Registration Errors</h2>";
    foreach ($errors as $error) {
        echo "<p class='error-message'>" . htmlspecialchars($error) . "</p>";
    }
    echo "<p>You will be redirected in <span id='countdown'>5</span> seconds...</p>
          <script>
            var countdown = 5;
            setInterval(function() {
                countdown--;
                document.getElementById('countdown').innerText = countdown;
                if (countdown == 0) {
                    window.location.href = 'doctor_registration.php';
                }
            }, 1000);
          </script>
          </div>";
} else {
    // Hash the password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    // Set registration status
    $registration_status = 'pending';
    
    // Prepare and execute the SQL statement to insert data into doctors table
    $stmt = $conn->prepare("INSERT INTO doctors (first_name, last_name, dob, gender, email, password, specialization, hospital_id, location, terms, consent, registration_status, gov_id_proof, hospital_id_proof, profile_picture, signature) 
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
    
    $stmt->bind_param("sssssssissssssss", 
        $first_name, 
        $last_name, 
        $dob, 
        $gender, 
        $email, 
        $hashed_password, 
        $specialization, 
        $hospital_id, 
        $location, 
        $terms, 
        $consent, 
        $registration_status, 
        $gov_id_proof, 
        $hospital_id_proof, 
        $profile_picture,
        $signature
    );
    
    // Execute the query
    if ($stmt->execute()) {
        echo "<div class='message-container'>
                <h2 class='success-heading'>Registration Successful!</h2>
                <p class='success-message'>Your application has been sent to the admin for approval. Please try to login after approval.</p>
                <p>You will be redirected to login page in <span id='countdown'>5</span> seconds...</p>
                <script>
                    var countdown = 5;
                    setInterval(function() {
                        countdown--;
                        document.getElementById('countdown').innerText = countdown;
                        if (countdown == 0) {
                            window.location.href = '../login.php';
                        }
                    }, 1000);
                </script>
              </div>";
    } else {
        echo "<div class='message-container'>
                <h2 class='error-heading'>Registration Failed</h2>
                <p class='error-message'>Database Error: " . htmlspecialchars($stmt->error) . "</p>
                <p>You will be redirected in <span id='countdown'>5</span> seconds...</p>
                <script>
                    var countdown = 5;
                    setInterval(function() {
                        countdown--;
                        document.getElementById('countdown').innerText = countdown;
                        if (countdown == 0) {
                            window.location.href = 'doctor_registration.php';
                        }
                    }, 1000);
                </script>
              </div>";
    }
    
    $stmt->close();
}

$conn->close();
?>

<style>
    body {
        font-family: 'Arial', sans-serif;
        background: linear-gradient(135deg, #87CEEB 0%, #4682B4 100%);
        padding: 20px;
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 100vh;
        margin: 0;
    }

    .message-container {
        text-align: center;
        background-color: #fff;
        padding: 40px;
        border-radius: 15px;
        box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
        max-width: 500px;
        width: 100%;
        animation: slideIn 0.5s ease-out;
    }

    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(-30px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }

    .error-heading {
        color: #e74c3c;
        font-size: 28px;
        margin-bottom: 20px;
        font-weight: 600;
    }

    .success-heading {
        color: #27ae60;
        font-size: 28px;
        margin-bottom: 20px;
        font-weight: 600;
    }

    .error-message {
        color: #e74c3c;
        background: #fdf2f2;
        border: 1px solid #fecaca;
        padding: 12px;
        border-radius: 8px;
        margin: 10px 0;
        font-size: 16px;
    }

    .success-message {
        color: #27ae60;
        font-size: 18px;
        margin: 20px 0;
        line-height: 1.5;
    }

    #countdown {
        font-weight: bold;
        color: #3498db;
        font-size: 20px;
    }

    p {
        margin: 15px 0;
        font-size: 16px;
        color: #555;
    }
</style>
