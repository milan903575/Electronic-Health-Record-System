<?php
include '../connection.php';

// AJAX: Hospital search
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

// AJAX: Email check
if (isset($_POST['email_check'])) {
    $email = mysqli_real_escape_string($conn, $_POST['email_check']);
    $response = ['exists' => false, 'who' => ''];

    // Receptionist check
    $stmt = $conn->prepare("SELECT id FROM receptionist WHERE email = ? LIMIT 1");
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $response = ['exists' => true, 'who' => 'receptionist'];
    }
    $stmt->close();

    // If not receptionist, check patients/doctors specifically
    if (!$response['exists']) {
        $stmt = $conn->prepare("SELECT 'patient' as who FROM patients WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc()) {
            $response = ['exists' => true, 'who' => 'patient'];
        }
        $stmt->close();
    }
    if (!$response['exists']) {
        $stmt = $conn->prepare("SELECT 'doctor' as who FROM doctors WHERE email = ? LIMIT 1");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($row = $result->fetch_assoc()) {
            $response = ['exists' => true, 'who' => 'doctor'];
        }
        $stmt->close();
    }

    header('Content-Type: application/json');
    echo json_encode($response);
    exit;
}

// Registration form processing
if ($_SERVER['REQUEST_METHOD'] == 'POST' && !isset($_POST['email_check'])) {
    $first_name = mysqli_real_escape_string($conn, $_POST['first_name']);
    $last_name = mysqli_real_escape_string($conn, $_POST['last_name']);
    $email = mysqli_real_escape_string($conn, $_POST['email']);
    $password = mysqli_real_escape_string($conn, $_POST['password']);
    $confirm_password = mysqli_real_escape_string($conn, $_POST['confirm_password']);
    $hospital_id = mysqli_real_escape_string($conn, $_POST['hospital_id']);

    // File uploads
    $hospital_id_proof = $_FILES['hospital_id_proof']['name'];
    $government_id_proof = $_FILES['government_id_proof']['name'];
    $upload_dir = 'uploads/images/';
    $hospital_id_proof_ext = pathinfo($hospital_id_proof, PATHINFO_EXTENSION);
    $government_id_proof_ext = pathinfo($government_id_proof, PATHINFO_EXTENSION);
    $hospital_id_proof_unique = uniqid('hospital_', true) . '.' . $hospital_id_proof_ext;
    $government_id_proof_unique = uniqid('government_', true) . '.' . $government_id_proof_ext;
    $hospital_id_proof_path = $upload_dir . $hospital_id_proof_unique;
    $government_id_proof_path = $upload_dir . $government_id_proof_unique;

    // Password validation
    if ($password !== $confirm_password) {
        showMessage("Error: Passwords do not match.", "receptionist_registration.php", 3);
        exit;
    }

    // Hash password
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Check if email exists in any table
    $check_email_sql = "
        SELECT email, 'patient' as who FROM patients WHERE email = ? 
        UNION 
        SELECT email, 'doctor' as who FROM doctors WHERE email = ? 
        UNION 
        SELECT email, 'receptionist' as who FROM receptionist WHERE email = ?
    ";
    $stmt = $conn->prepare($check_email_sql);
    $stmt->bind_param('sss', $email, $email, $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        showMessage("Error: Email already exists. Login or use a different email.", "login.html", 3);
        $stmt->close();
        $conn->close();
        exit;
    }
    $stmt->close();

    // Move uploaded files
    if (!move_uploaded_file($_FILES['hospital_id_proof']['tmp_name'], $hospital_id_proof_path) ||
        !move_uploaded_file($_FILES['government_id_proof']['tmp_name'], $government_id_proof_path)) {
        showMessage("Error: File upload failed.", "receptionist_registration.php", 3);
        $conn->close();
        exit;
    }

    // Insert new receptionist
    $insert_sql = "
        INSERT INTO receptionist (first_name, last_name, email, password, hospital_id, hospital_id_proof, government_id_proof, status) 
        VALUES (?, ?, ?, ?, ?, ?, ?, 'pending')
    ";
    $stmt = $conn->prepare($insert_sql);
    $stmt->bind_param('ssssiss', $first_name, $last_name, $email, $hashed_password, $hospital_id, $hospital_id_proof_path, $government_id_proof_path);

    if ($stmt->execute()) {
        showMessage("Receptionist registered successfully! Application sent to admin for approval. Try to login.", "../login.html", 10);
    } else {
        showMessage("Error: " . $stmt->error, "receptionist_registration.php", 5);
    }

    $stmt->close();
    $conn->close();
    exit;
}

// Function to display the styled message and handle redirection
function showMessage($message, $redirectUrl, $redirectTime) {
    echo "
    <style>
        .message-container {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
            padding: 20px;
            border: 1px solid #ddd;
            background-color: #f8f8f8;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            border-radius: 10px;
            font-family: Arial, sans-serif;
            color: #333;
        }
        .message-container p {
            font-size: 1.1em;
            margin: 5px 0;
        }
        .message-container span {
            font-weight: bold;
            color: #e74c3c;
        }
    </style>
    <div class='message-container'>
        <p>$message</p>
        <p>You will be redirected in <span id='countdown'>$redirectTime</span> seconds...</p>
    </div>
    <script>
        let countdown = $redirectTime;
        const interval = setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown === 0) {
                clearInterval(interval);
                window.location.href = '$redirectUrl';
            }
        }, 1000);
    </script>";
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Receptionist Registration</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
    body {
        font-family: 'Segoe UI', Arial, sans-serif;
        background: linear-gradient(135deg,#e0e7ff 0%, #f8fafc 100%);
        margin: 0;
        padding: 0;
    }
    .container {
        max-width: 480px;
        margin: 48px auto;
        background: #fff;
        border-radius: 18px;
        box-shadow: 0 8px 32px rgba(67,97,238,0.08), 0 1.5px 5px rgba(67,97,238,0.03);
        padding: 38px 30px 30px 30px;
        position: relative;
    }
    h2 {
        text-align: center;
        color: #4361ee;
        margin-bottom: 18px;
        letter-spacing: 1px;
    }
    .form-group {
        margin-bottom: 18px;
        position: relative;
    }
    label {
        font-weight: 500;
        color: #334155;
        margin-bottom: 6px;
        display: block;
    }
    input[type="text"], input[type="email"], input[type="password"], input[type="file"] {
        width: 100%;
        padding: 10px 12px;
        border: 1.5px solid #cbd5e1;
        border-radius: 7px;
        font-size: 1rem;
        margin-top: 5px;
        font-family: inherit;
        box-sizing: border-box;
        transition: border .2s;
        background: #f8fafc;
    }
    input[type="text"]:focus, input[type="email"]:focus, input[type="password"]:focus, input[type="file"]:focus {
        border-color: #4361ee;
        outline: none;
        background: #fff;
    }
    .checkbox-group {
        margin-bottom: 16px;
    }
    .checkbox-group label {
        font-weight: normal;
        color: #222;
        display: inline;
        margin-left: 8px;
        font-size: 0.97em;
    }
    .btn {
        width: 100%;
        padding: 12px;
        background: linear-gradient(90deg,#4361ee 60%, #4cc9f0 100%);
        color: #fff;
        border: none;
        border-radius: 7px;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        margin-top: 8px;
        transition: background .2s;
        box-shadow: 0 2px 8px rgba(67,97,238,0.06);
    }
    .btn:hover {
        background: linear-gradient(90deg,#3f37c9 60%, #4895ef 100%);
    }
    .btn-login {
        background: #64748b;
        margin-top: 12px;
        display: inline-block;
        padding: 8px 24px;
        border-radius: 6px;
        color: #fff;
        text-decoration: none;
        font-weight: 500;
        font-size: 1em;
        transition: background .2s;
    }
    .btn-login:hover {
        background: #334155;
    }
    #email-exists-alert {
        display: none;
        background: #fff6f6;
        border: 1.5px solid #f87171;
        color: #b91c1c;
        padding: 20px 12px 15px 12px;
        border-radius: 8px;
        margin-bottom: 18px;
        text-align: center;
        font-size: 1.05em;
        box-shadow: 0 2px 8px rgba(248,113,113,0.04);
        animation: fadein 0.3s;
    }
    #email-exists-alert strong { color: #b91c1c; font-size: 1.1em; }
    @keyframes fadein { from { opacity: 0; } to { opacity: 1; } }
    .hospital-results {
        position: absolute;
        background: #fff;
        border: 1.5px solid #cbd5e1;
        border-radius: 0 0 8px 8px;
        width: 100%;
        max-height: 160px;
        overflow-y: auto;
        z-index: 10;
        box-shadow: 0 4px 8px rgba(67,97,238,0.07);
        display: none;
    }
    .hospital-option {
        padding: 10px 14px;
        cursor: pointer;
        transition: background .2s;
        font-size: 1em;
    }
    .hospital-option:hover {
        background: #e0e7ff;
    }
    @media (max-width: 600px) {
        .container { padding: 18px 6px; }
    }
</style>
</head>
<body>
<div class="container">
    <h2>Receptionist Registration</h2>
    <form id="receptionist_form" action="receptionist_registration.php" method="POST" enctype="multipart/form-data" autocomplete="off">
        <!-- Email -->
        <div class="form-group">
            <label for="email">Email Address</label>
            <input name="email" id="email" placeholder="Email" type="email" required autocomplete="off">
        </div>
        <!-- Email Exists Alert -->
        <div id="email-exists-alert">
            <strong id="email-exists-title"></strong>
            <div id="email-exists-message"></div>
            <a href="login.html" class="btn-login">Login</a>
        </div>
        <div id="registration-fields">
            <!-- Hospital Search -->
            <div class="form-group" style="position:relative;">
                <label for="hospital_search">Hospital</label>
                <input type="text" id="hospital_search" placeholder="Search by name or zip code" autocomplete="off">
                <input type="hidden" name="hospital_id" id="hospital_id">
                <div id="hospital_list" class="hospital-results"></div>
            </div>
            <div class="form-group">
                <label for="first_name">First Name</label>
                <input name="first_name" id="first_name" placeholder="First Name" type="text" required>
            </div>
            <div class="form-group">
                <label for="last_name">Last Name</label>
                <input name="last_name" id="last_name" placeholder="Last Name" type="text" required>
            </div>
            <div class="form-group">
                <label for="hospital_id_proof">Hospital ID Proof</label>
                <input name="hospital_id_proof" id="hospital_id_proof" type="file" accept="image/*" required>
            </div>
            <div class="form-group">
                <label for="government_id_proof">Government ID Proof</label>
                <input name="government_id_proof" id="government_id_proof" type="file" accept="image/*" required>
            </div>
            <div class="form-group">
                <label for="password">Password</label>
                <input name="password" id="password" placeholder="Password" type="password" required>
            </div>
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input name="confirm_password" id="confirm_password" placeholder="Confirm Password" type="password" required>
            </div>
            <div class="checkbox-group">
                <input type="checkbox" id="terms" name="terms" required>
                <label for="terms">I agree to the terms and conditions.</label>
            </div>
            <div class="checkbox-group">
                <input type="checkbox" id="hospital_consent" name="hospital_consent" required>
                <label for="hospital_consent">I confirm that I am associated with this hospital.</label>
            </div>
            <button type="submit" class="btn">Register</button>
        </div>
    </form>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script>
$(document).ready(function() {
    // Dynamic hospital search
    $('#hospital_search').on('input', function() {
        let query = $(this).val();
        if (query.length > 0) {
            $.ajax({
                url: '', // same file
                type: 'GET',
                data: { query: query },
                success: function(response) {
                    $('#hospital_list').html(response).show();
                    $('.hospital-option').click(function() {
                        let hospital_id = $(this).data('id');
                        $('#hospital_search').val($(this).text());
                        $('#hospital_id').val(hospital_id);
                        $('#hospital_list').hide();
                    });
                }
            });
        } else {
            $('#hospital_list').hide();
        }
    });

    // Hide hospital list on outside click
    $(document).on('click', function(e) {
        if (!$(e.target).closest('#hospital_search, #hospital_list').length) {
            $('#hospital_list').hide();
        }
    });

    // Dynamic email check and hide/show
    $('#email').on('input', function() {
        var email = $(this).val().trim();
        var $alert = $('#email-exists-alert');
        var $fields = $('#registration-fields');
        var $title = $('#email-exists-title');
        var $msg = $('#email-exists-message');
        if (email.length === 0) {
            $alert.hide();
            $fields.show();
            return;
        }
        var emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            $alert.hide();
            $fields.show();
            return;
        }
        $.ajax({
            url: '', // same file
            method: 'POST',
            data: { email_check: email },
            dataType: 'json',
            success: function(data) {
                if (data.exists) {
                    if (data.who === 'receptionist') {
                        $title.text('This email is already registered as a receptionist.');
                        $msg.html('Please login.');
                    } else if (data.who === 'patient') {
                        $title.text('This email is already registered as a patient.');
                        $msg.html('Please use a different email.');
                    } else if (data.who === 'doctor') {
                        $title.text('This email is already registered as a doctor.');
                        $msg.html('Please use a different email.');
                    } else {
                        $title.text('This email already exists.');
                        $msg.html('Please use a different email.');
                    }
                    $alert.show();
                    $fields.hide();
                } else {
                    $alert.hide();
                    $fields.show();
                }
            }
        });
    });
});
</script>
</body>
</html>
