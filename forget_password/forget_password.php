<?php
session_start();

// Clear session data for a fresh start
if (!isset($_POST['email']) && !isset($_POST['otp']) && !isset($_POST['new_password'])) {
    session_unset();
    session_destroy();
    session_start(); // Restart the session to avoid issues with subsequent requests
}

include '../connection.php';
require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Function to send OTP
function sendOtp($email, $otp) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = ''; // Replace with your email
        $mail->Password = ''; // Replace with your App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        $mail->setFrom('yourmail@gmail.com', 'Password Reset');
        $mail->addAddress($email);

        $mail->isHTML(true);
        $mail->Subject = 'Password Reset Verification Code';
        $mail->Body = '
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e0e0e0; border-radius: 5px;">
                <h2 style="color: #4361ee; text-align: center;">Password Reset Code</h2>
                <p style="font-size: 16px; color: #333;">Use the following code to reset your password:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #1e293b; background-color: #f8fafc; padding: 15px; border-radius: 5px; display: inline-block;">' . $otp . '</div>
                </div>
                <p style="font-size: 14px; color: #666;">This code will expire in 15 minutes.</p>
                <p style="font-size: 14px; color: #666;">If you did not request this code, please ignore this email.</p>
            </div>
        ';

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("PHPMailer error: " . $mail->ErrorInfo);
        return false;
    }
}

// Handle form submission
$message = "";
$status = "";
$current_step = isset($_SESSION['step']) ? $_SESSION['step'] : 'email';

// Email submission
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['email']) && !isset($_POST['otp'])) {
    $email = mysqli_real_escape_string($conn, $_POST['email']);

    // Check email in patients and doctors tables
    $query = "SELECT email FROM patients WHERE email = ? UNION SELECT email FROM doctors WHERE email = ?";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("ss", $email, $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($result->num_rows > 0) {
        // Generate OTP and store in session
        $otp = rand(100000, 999999);
        $_SESSION['otp'] = $otp;
        $_SESSION['email'] = $email;
        $_SESSION['otp_time'] = time();
        $_SESSION['step'] = 'otp';
        $current_step = 'otp';

        // Send OTP to user's email
        if (sendOtp($email, $otp)) {
            $message = "Verification code sent to your email.";
            $status = "success";
        } else {
            $message = "Failed to send verification code. Please try again.";
            $status = "error";
        }
    } else {
        $message = "Email not found in our records.";
        $status = "error";
    }
}

// OTP verification
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['otp'])) {
    $entered_otp = $_POST['otp'];

    // Check if OTP is expired (15 minutes)
    $otp_time = isset($_SESSION['otp_time']) ? $_SESSION['otp_time'] : 0;
    $current_time = time();
    $time_diff = $current_time - $otp_time;
    $otp_expiry = 15 * 60; // 15 minutes in seconds

    if ($time_diff > $otp_expiry) {
        $message = "Verification code has expired. Please request a new one.";
        $status = "error";
        $_SESSION['step'] = 'email';
        $current_step = 'email';
    } elseif ($entered_otp == $_SESSION['otp']) {
        // OTP is correct; proceed to password reset
        $_SESSION['step'] = 'password';
        $current_step = 'password';
    } else {
        $message = "Invalid verification code. Please try again.";
        $status = "error";
    }
}

// Password update
if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['new_password']) && isset($_POST['confirm_password'])) {
    $new_password = mysqli_real_escape_string($conn, $_POST['new_password']);
    $confirm_password = mysqli_real_escape_string($conn, $_POST['confirm_password']);

    // Check if passwords match
    if ($new_password === $confirm_password) {
        $email = $_SESSION['email'];

        // Hash the password for security
        $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);

        // Update password in patients table
        $update_patients_query = "UPDATE patients SET password = ? WHERE email = ?";
        $stmt1 = $conn->prepare($update_patients_query);
        $stmt1->bind_param("ss", $hashed_password, $email);
        $patients_updated = $stmt1->execute();

        // Update password in doctors table
        $update_doctors_query = "UPDATE doctors SET password = ? WHERE email = ?";
        $stmt2 = $conn->prepare($update_doctors_query);
        $stmt2->bind_param("ss", $hashed_password, $email);
        $doctors_updated = $stmt2->execute();

        // Check if the updates succeeded
        if ($patients_updated || $doctors_updated) {
            $message = "Password updated successfully!";
            $status = "success";
            $_SESSION['step'] = 'success';
            $current_step = 'success';
        } else {
            $message = "Failed to update password. Please try again.";
            $status = "error";
        }
    } else {
        $message = "Passwords do not match.";
        $status = "error";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #4361ee;
            --primary-dark: #3a56d4;
            --secondary-color: #4cc9f0;
            --success-color: #4ade80;
            --warning-color: #fbbf24;
            --danger-color: #f87171;
            --light-color: #f8fafc;
            --dark-color: #1e293b;
            --gray-100: #f1f5f9;
            --gray-200: #e2e8f0;
            --gray-300: #cbd5e1;
            --gray-400: #94a3b8;
            --gray-500: #64748b;
            --gray-600: #475569;
            --gray-700: #334155;
            --gray-800: #1e293b;
            --gray-900: #0f172a;
        }

        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Poppins', sans-serif;
            background: linear-gradient(135deg, #4361ee, #4cc9f0);
            color: var(--gray-800);
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            padding: 20px;
        }

        .container {
            width: 100%;
            max-width: 450px;
            padding: 0 15px;
        }

        .card {
            background-color: white;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.15);
            transition: all 0.3s ease;
        }

        .card-header {
            background-color: var(--primary-color);
            color: white;
            padding: 25px 30px;
            text-align: center;
            position: relative;
        }

        .card-header h2 {
            font-size: 1.8rem;
            font-weight: 600;
            margin-bottom: 5px;
        }

        .card-header p {
            font-size: 0.95rem;
            opacity: 0.9;
        }

        .card-body {
            padding: 30px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-label {
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
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
            outline: none;
        }

        .password-container {
            position: relative;
        }

        .toggle-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: var(--gray-500);
        }

        .btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 100%;
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

        .alert {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .alert-success {
            background-color: rgba(74, 222, 128, 0.1);
            border: 1px solid rgba(74, 222, 128, 0.3);
            color: #166534;
        }

        .alert-error {
            background-color: rgba(248, 113, 113, 0.1);
            border: 1px solid rgba(248, 113, 113, 0.3);
            color: #b91c1c;
        }

        .steps {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
            position: relative;
        }

        .steps::before {
            content: '';
            position: absolute;
            top: 15px;
            left: 40px;
            right: 40px;
            height: 2px;
            background-color: var(--gray-300);
            z-index: 1;
        }

        .step {
            display: flex;
            flex-direction: column;
            align-items: center;
            position: relative;
            z-index: 2;
        }

        .step-number {
            width: 30px;
            height: 30px;
            border-radius: 50%;
            background-color: var(--gray-300);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 600;
            margin-bottom: 8px;
            transition: all 0.3s ease;
        }

        .step-text {
            font-size: 0.8rem;
            color: var(--gray-500);
            transition: all 0.3s ease;
        }

        .step.active .step-number {
            background-color: var(--primary-color);
        }

        .step.active .step-text {
            color: var(--primary-color);
            font-weight: 500;
        }

        .step.completed .step-number {
            background-color: var(--success-color);
        }

        .otp-inputs {
            display: flex;
            justify-content: space-between;
            gap: 10px;
            margin-bottom: 20px;
        }

        .otp-input {
            width: 50px;
            height: 60px;
            border: 1px solid var(--gray-300);
            border-radius: 8px;
            font-size: 1.5rem;
            text-align: center;
            font-weight: 600;
            transition: all 0.3s ease;
        }

        .otp-input:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(67, 97, 238, 0.15);
            outline: none;
        }

        .resend-link {
            text-align: center;
            margin-top: 15px;
        }

        .resend-link a {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 500;
            transition: all 0.3s ease;
        }

        .resend-link a:hover {
            text-decoration: underline;
        }

        .countdown {
            font-size: 0.9rem;
            color: var(--gray-600);
            margin-top: 5px;
            text-align: center;
        }

        .password-requirements {
            margin-top: 15px;
            font-size: 0.85rem;
            color: var(--gray-600);
        }

        .requirement {
            display: flex;
            align-items: center;
            margin-bottom: 5px;
            gap: 5px;
        }

        .requirement i {
            font-size: 0.8rem;
        }

        .requirement.valid {
            color: var(--success-color);
        }

        .requirement.invalid {
            color: var(--gray-500);
        }

        .success-icon {
            font-size: 4rem;
            color: var(--success-color);
            margin-bottom: 20px;
        }

        .success-message {
            text-align: center;
            margin-bottom: 30px;
        }

        .success-message h3 {
            font-size: 1.5rem;
            color: var(--gray-800);
            margin-bottom: 10px;
        }

        .success-message p {
            color: var(--gray-600);
        }

        .redirect-countdown {
            font-weight: 600;
            color: var(--primary-color);
        }

        @media (max-width: 576px) {
            .card-header {
                padding: 20px;
            }
            
            .card-header h2 {
                font-size: 1.5rem;
            }
            
            .card-body {
                padding: 20px;
            }
            
            .otp-input {
                width: 40px;
                height: 50px;
                font-size: 1.2rem;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="card">
            <div class="card-header">
                <h2>Reset Password</h2>
                <p>Follow the steps to reset your password</p>
            </div>
            <div class="card-body">
                <!-- Progress Steps -->
                <div class="steps">
                    <div class="step <?php echo ($current_step == 'email' || $current_step == 'otp' || $current_step == 'password' || $current_step == 'success') ? 'active' : ''; ?> <?php echo ($current_step == 'otp' || $current_step == 'password' || $current_step == 'success') ? 'completed' : ''; ?>">
                        <div class="step-number">1</div>
                        <div class="step-text">Email</div>
                    </div>
                    <div class="step <?php echo ($current_step == 'otp' || $current_step == 'password' || $current_step == 'success') ? 'active' : ''; ?> <?php echo ($current_step == 'password' || $current_step == 'success') ? 'completed' : ''; ?>">
                        <div class="step-number">2</div>
                        <div class="step-text">Verify</div>
                    </div>
                    <div class="step <?php echo ($current_step == 'password' || $current_step == 'success') ? 'active' : ''; ?> <?php echo ($current_step == 'success') ? 'completed' : ''; ?>">
                        <div class="step-number">3</div>
                        <div class="step-text">Password</div>
                    </div>
                </div>

                <!-- Alert Messages -->
                <?php if ($message): ?>
                    <div class="alert alert-<?php echo $status; ?>">
                        <i class="fas fa-<?php echo $status == 'success' ? 'check-circle' : 'exclamation-circle'; ?>"></i>
                        <?php echo htmlspecialchars($message); ?>
                    </div>
                <?php endif; ?>

                <!-- Email Form -->
                <?php if ($current_step == 'email'): ?>
                    <form method="POST" id="email-form">
                        <div class="form-group">
                            <label for="email" class="form-label">Email Address</label>
                            <input type="email" id="email" name="email" class="form-control" placeholder="Enter your registered email" required>
                        </div>
                        <button type="submit" class="btn">
                            <i class="fas fa-paper-plane"></i> Send Verification Code
                        </button>
                    </form>
                <?php endif; ?>

                <!-- OTP Form -->
                <?php if ($current_step == 'otp'): ?>
                    <form method="POST" id="otp-form">
                        <div class="form-group">
                            <label class="form-label">Enter Verification Code</label>
                            <p style="font-size: 0.9rem; color: var(--gray-600); margin-bottom: 15px;">
                                We've sent a 6-digit code to <strong><?php echo htmlspecialchars(substr($_SESSION['email'], 0, 3) . '***' . substr($_SESSION['email'], strpos($_SESSION['email'], '@'))); ?></strong>
                            </p>
                            <div class="otp-inputs">
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                                <input type="text" class="otp-input" maxlength="1" pattern="[0-9]" inputmode="numeric" required>
                            </div>
                            <input type="hidden" id="otp" name="otp">
                        </div>
                        <button type="submit" class="btn" id="verify-btn">
                            <i class="fas fa-check-circle"></i> Verify Code
                        </button>
                        <div class="resend-link">
                            <span>Didn't receive the code? </span>
                            <a href="#" id="resend-otp">Resend Code</a>
                        </div>
                        <div class="countdown" id="countdown-timer">
                            Code expires in <span id="minutes">15</span>:<span id="seconds">00</span>
                        </div>
                    </form>
                <?php endif; ?>

                <!-- Password Reset Form -->
                <?php if ($current_step == 'password'): ?>
                    <form method="POST" id="password-form">
                        <div class="form-group">
                            <label for="new_password" class="form-label">New Password</label>
                            <div class="password-container">
                                <input type="password" id="new_password" name="new_password" class="form-control" placeholder="Enter new password" required>
                                <i class="toggle-password fas fa-eye-slash" id="toggle-new-password"></i>
                            </div>
                        </div>
                        <div class="form-group">
                            <label for="confirm_password" class="form-label">Confirm Password</label>
                            <div class="password-container">
                                <input type="password" id="confirm_password" name="confirm_password" class="form-control" placeholder="Confirm your password" required>
                                <i class="toggle-password fas fa-eye-slash" id="toggle-confirm-password"></i>
                            </div>
                        </div>
                        
                        <div class="password-requirements">
                            <div class="requirement" id="length">
                                <i class="fas fa-circle"></i> At least 8 characters
                            </div>
                            <div class="requirement" id="uppercase">
                                <i class="fas fa-circle"></i> At least one uppercase letter
                            </div>
                            <div class="requirement" id="lowercase">
                                <i class="fas fa-circle"></i> At least one lowercase letter
                            </div>
                            <div class="requirement" id="number">
                                <i class="fas fa-circle"></i> At least one number
                            </div>
                            <div class="requirement" id="match">
                                <i class="fas fa-circle"></i> Passwords match
                            </div>
                        </div>
                        
                        <button type="submit" class="btn" id="reset-btn" disabled>
                            <i class="fas fa-lock"></i> Reset Password
                        </button>
                    </form>
                <?php endif; ?>

                <!-- Success Message -->
                <?php if ($current_step == 'success'): ?>
                    <div class="success-message">
                        <i class="fas fa-check-circle success-icon"></i>
                        <h3>Password Reset Successfully!</h3>
                        <p>Your password has been updated. You will be redirected to the login page in <span id="redirect-countdown" class="redirect-countdown">5</span> seconds.</p>
                    </div>
                    <a href="../login.html" class="btn">
                        <i class="fas fa-sign-in-alt"></i> Go to Login
                    </a>
                <?php endif; ?>
            </div>
        </div>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // OTP Input Handling
            if (document.getElementById('otp-form')) {
                const otpInputs = document.querySelectorAll('.otp-input');
                const otpHiddenInput = document.getElementById('otp');
                const verifyBtn = document.getElementById('verify-btn');
                
                // Set up OTP countdown
                let timeLeft = <?php echo isset($_SESSION['otp_time']) ? (15 * 60) - (time() - $_SESSION['otp_time']) : 0; ?>;
                const minutesEl = document.getElementById('minutes');
                const secondsEl = document.getElementById('seconds');
                
                const countdownTimer = setInterval(() => {
                    if (timeLeft <= 0) {
                        clearInterval(countdownTimer);
                        document.getElementById('countdown-timer').textContent = 'Code expired. Please request a new one.';
                        verifyBtn.disabled = true;
                    } else {
                        const minutes = Math.floor(timeLeft / 60);
                        const seconds = timeLeft % 60;
                        minutesEl.textContent = minutes.toString().padStart(2, '0');
                        secondsEl.textContent = seconds.toString().padStart(2, '0');
                        timeLeft--;
                    }
                }, 1000);
                
                // Handle OTP input
                otpInputs.forEach((input, index) => {
                    input.addEventListener('keyup', (e) => {
                        // Move to next input if a number is entered
                        if (/^[0-9]$/.test(e.key) && index < otpInputs.length - 1) {
                            otpInputs[index + 1].focus();
                        }
                        
                        // Handle backspace
                        if (e.key === 'Backspace' && index > 0) {
                            otpInputs[index - 1].focus();
                        }
                        
                        // Update hidden input with combined OTP value
                        otpHiddenInput.value = Array.from(otpInputs).map(input => input.value).join('');
                    });
                    
                    // Handle paste event on first input
                    if (index === 0) {
                        input.addEventListener('paste', (e) => {
                            e.preventDefault();
                            const pasteData = e.clipboardData.getData('text').trim().slice(0, 6);
                            
                            if (/^\d+$/.test(pasteData)) {
                                for (let i = 0; i < pasteData.length; i++) {
                                    if (i < otpInputs.length) {
                                        otpInputs[i].value = pasteData[i];
                                    }
                                }
                                
                                otpHiddenInput.value = pasteData;
                                
                                // Focus the last filled input
                                const focusIndex = Math.min(pasteData.length, otpInputs.length) - 1;
                                if (focusIndex >= 0) {
                                    otpInputs[focusIndex].focus();
                                }
                            }
                        });
                    }
                });
                
                // Handle resend OTP
                document.getElementById('resend-otp').addEventListener('click', (e) => {
                    e.preventDefault();
                    window.location.href = window.location.pathname;
                });
            }
            
            // Password Validation
            if (document.getElementById('password-form')) {
                const newPasswordInput = document.getElementById('new_password');
                const confirmPasswordInput = document.getElementById('confirm_password');
                const resetBtn = document.getElementById('reset-btn');
                
                const requirements = {
                    length: document.getElementById('length'),
                    uppercase: document.getElementById('uppercase'),
                    lowercase: document.getElementById('lowercase'),
                    number: document.getElementById('number'),
                    match: document.getElementById('match')
                };
                
                function validatePassword() {
                    const password = newPasswordInput.value;
                    const confirmPassword = confirmPasswordInput.value;
                    
                    // Check length
                    if (password.length >= 8) {
                        requirements.length.classList.add('valid');
                        requirements.length.classList.remove('invalid');
                        requirements.length.querySelector('i').className = 'fas fa-check-circle';
                    } else {
                        requirements.length.classList.remove('valid');
                        requirements.length.classList.add('invalid');
                        requirements.length.querySelector('i').className = 'fas fa-circle';
                    }
                    
                    // Check uppercase
                    if (/[A-Z]/.test(password)) {
                        requirements.uppercase.classList.add('valid');
                        requirements.uppercase.classList.remove('invalid');
                        requirements.uppercase.querySelector('i').className = 'fas fa-check-circle';
                    } else {
                        requirements.uppercase.classList.remove('valid');
                        requirements.uppercase.classList.add('invalid');
                        requirements.uppercase.querySelector('i').className = 'fas fa-circle';
                    }
                    
                    // Check lowercase
                    if (/[a-z]/.test(password)) {
                        requirements.lowercase.classList.add('valid');
                        requirements.lowercase.classList.remove('invalid');
                        requirements.lowercase.querySelector('i').className = 'fas fa-check-circle';
                    } else {
                        requirements.lowercase.classList.remove('valid');
                        requirements.lowercase.classList.add('invalid');
                        requirements.lowercase.querySelector('i').className = 'fas fa-circle';
                    }
                    
                    // Check number
                    if (/[0-9]/.test(password)) {
                        requirements.number.classList.add('valid');
                        requirements.number.classList.remove('invalid');
                        requirements.number.querySelector('i').className = 'fas fa-check-circle';
                    } else {
                        requirements.number.classList.remove('valid');
                        requirements.number.classList.add('invalid');
                        requirements.number.querySelector('i').className = 'fas fa-circle';
                    }
                    
                    // Check match
                    if (password && password === confirmPassword) {
                        requirements.match.classList.add('valid');
                        requirements.match.classList.remove('invalid');
                        requirements.match.querySelector('i').className = 'fas fa-check-circle';
                    } else {
                        requirements.match.classList.remove('valid');
                        requirements.match.classList.add('invalid');
                        requirements.match.querySelector('i').className = 'fas fa-circle';
                    }
                    
                    // Enable/disable submit button
                    const allValid = Object.values(requirements).every(req => req.classList.contains('valid'));
                    resetBtn.disabled = !allValid;
                }
                
                newPasswordInput.addEventListener('input', validatePassword);
                confirmPasswordInput.addEventListener('input', validatePassword);
                
                // Toggle password visibility
                document.getElementById('toggle-new-password').addEventListener('click', function() {
                    togglePasswordVisibility(newPasswordInput, this);
                });
                
                document.getElementById('toggle-confirm-password').addEventListener('click', function() {
                    togglePasswordVisibility(confirmPasswordInput, this);
                });
                
                function togglePasswordVisibility(input, icon) {
                    if (input.type === 'password') {
                        input.type = 'text';
                        icon.classList.remove('fa-eye-slash');
                        icon.classList.add('fa-eye');
                    } else {
                        input.type = 'password';
                        icon.classList.remove('fa-eye');
                        icon.classList.add('fa-eye-slash');
                    }
                }
            }
            
            // Success redirect countdown
            if (document.getElementById('redirect-countdown')) {
                let countdown = 5;
                const countdownEl = document.getElementById('redirect-countdown');
                
                const redirectTimer = setInterval(() => {
                    countdown--;
                    countdownEl.textContent = countdown;
                    
                    if (countdown <= 0) {
                        clearInterval(redirectTimer);
                        window.location.href = '../login.html';
                    }
                }, 1000);
            }
        });
    </script>
</body>
</html>
