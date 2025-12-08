<?php
require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';
include '../connection.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

session_start();

$step = 'login';
$message = '';
$error_message = '';
$otp_sent = false;
$email = '';
$otp_expiry_seconds = 300; // 5 min
$resend_wait_seconds = 60; // 1 min

if (isset($_SESSION['awaiting_otp']) && $_SESSION['awaiting_otp'] === true) {
    $step = 'otp';
    $otp_sent = true;
    $email = $_SESSION['admin_id'] ?? '';
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'login') {
    if (isset($_POST['email']) && isset($_POST['password'])) {
        $email = mysqli_real_escape_string($conn, $_POST['email']);
        $password = mysqli_real_escape_string($conn, $_POST['password']);
        $sql_admin = "SELECT * FROM hospitals WHERE email = ?";
        $stmt_admin = $conn->prepare($sql_admin);
        $stmt_admin->bind_param("s", $email);
        $stmt_admin->execute();
        $result_admin = $stmt_admin->get_result();
        $admin = $result_admin->fetch_assoc();

        if ($admin && password_verify($password, $admin['password'])) {
            // Check hospital status
            if (isset($admin['status'])) {
                if ($admin['status'] === 'pending') {
                    $error_message = "Your application is still pending. Please wait for super admin approval.";
                    $stmt_admin->close();
                } elseif ($admin['status'] === 'approved' || $admin['status'] === 'rejected') {
                    // Proceed with OTP generation for approved and rejected hospitals
                    $otp = rand(100000, 999999);
                    $_SESSION['otp'] = $otp;
                    $_SESSION['admin_id'] = $email;
                    $_SESSION['awaiting_otp'] = true;
                    $_SESSION['otp_generated_at'] = time();
                    $_SESSION['otp_last_sent'] = time();

                    $message = sendOtpEmail($admin['email'], $otp);
                    $step = 'otp';
                    $otp_sent = true;
                    $stmt_admin->close();
                } else {
                    // Handle other status values (inactive, suspended, etc.)
                    $error_message = "Your account status is: " . ucfirst($admin['status']) . ". Please contact support.";
                    $stmt_admin->close();
                }
            } else {
                // If status column doesn't exist, proceed normally (backward compatibility)
                $otp = rand(100000, 999999);
                $_SESSION['otp'] = $otp;
                $_SESSION['admin_id'] = $email;
                $_SESSION['awaiting_otp'] = true;
                $_SESSION['otp_generated_at'] = time();
                $_SESSION['otp_last_sent'] = time();

                $message = sendOtpEmail($admin['email'], $otp);
                $step = 'otp';
                $otp_sent = true;
                $stmt_admin->close();
            }
        } else {
            $error_message = "Invalid Email or Password.";
            $stmt_admin->close();
        }
    } else {
        $error_message = "Please enter both email and password.";
    }
}

if (isset($_GET['resend']) && $_GET['resend'] == 1 && isset($_SESSION['admin_id'])) {
    $now = time();
    if (isset($_SESSION['otp_last_sent']) && ($now - $_SESSION['otp_last_sent']) < $resend_wait_seconds) {
        $error_message = "Please wait before resending OTP.";
        $step = 'otp';
        $otp_sent = true;
        $email = $_SESSION['admin_id'];
    } else {
        $otp = rand(100000, 999999);
        $_SESSION['otp'] = $otp;
        $_SESSION['otp_generated_at'] = $now;
        $_SESSION['otp_last_sent'] = $now;
        $message = sendOtpEmail($_SESSION['admin_id'], $otp);
        $step = 'otp';
        $otp_sent = true;
        $email = $_SESSION['admin_id'];
    }
}

if (isset($_GET['back']) && $_GET['back'] == 1) {
    session_unset();
    $step = 'login';
    $otp_sent = false;
    $email = '';
}

if ($_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && $_POST['action'] === 'otp') {
    if (!isset($_SESSION['otp'])) {
        $error_message = "OTP is not set. Please request a new OTP.";
        $step = 'login';
        session_unset();
    } else {
        $entered_otp = $_POST['otp'];
        $now = time();
        if (isset($_SESSION['otp_generated_at']) && ($now - $_SESSION['otp_generated_at']) > $otp_expiry_seconds) {
            $error_message = "OTP expired. Please request a new OTP.";
            $step = 'otp';
            $otp_sent = true;
            $email = $_SESSION['admin_id'];
        } elseif ($entered_otp == $_SESSION['otp']) {
            unset($_SESSION['otp'], $_SESSION['awaiting_otp'], $_SESSION['otp_generated_at'], $_SESSION['otp_last_sent']);
            $admin_id = $_SESSION['admin_id'];
            $sql = "SELECT id FROM hospitals WHERE email = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param("s", $admin_id);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result->num_rows > 0) {
                $row = $result->fetch_assoc();
                $_SESSION['hospital_id'] = $row['id'];
            }
            $stmt->close();

            header("Location: admin_dashboard.php");
            exit();
        } else {
            $error_message = "Invalid OTP. Please try again.";
            $step = 'otp';
            $otp_sent = true;
            $email = $_SESSION['admin_id'];
        }
    }
}

function sendOtpEmail($email, $otp) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host = 'smtp.gmail.com';
        $mail->SMTPAuth = true;
        $mail->Username = ''; // replace email
         $mail->Password = ''; // password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port = 587;

        $mail->setFrom('your@gmail.com', 'Admin Login OTP');
        $mail->addAddress($email);

        $mail->isHTML(true);
        $mail->Subject = 'Your OTP for Admin Login';
        $mail->Body    = '<div style="font-size:1.2em;color:#333;">Your OTP is: <b style="color:#007bff;">' . $otp . '</b></div>';
        
        $mail->send();
        return "An OTP has been sent to your email.";
    } catch (Exception $e) {
        error_log("PHPMailer error: " . $mail->ErrorInfo);
        return "An error occurred while sending the OTP.";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Login & OTP Verification</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --primary: #1976d2;
      --primary-dark: #1565c0;
      --accent: #00bcd4;
      --danger: #e53935;
      --success: #43a047;
      --warning: #ff9800;
      --bg: #f4f8fb;
      --card-bg: rgba(255,255,255,0.85);
      --shadow: 0 8px 32px rgba(25,118,210,0.11), 0 1.5px 8px rgba(0,0,0,0.05);
      --radius: 20px;
    }
    html,body {
      height: 100%;
      margin: 0;
      padding: 0;
      font-family: 'Inter', Arial, sans-serif;
      background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
      min-height: 100vh;
    }
    body {
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .auth-card {
      background: var(--card-bg);
      border-radius: var(--radius);
      box-shadow: var(--shadow);
      max-width: 400px;
      width: 100%;
      padding: 38px 32px 28px 32px;
      display: flex;
      flex-direction: column;
      align-items: stretch;
      position: relative;
      overflow: hidden;
      animation: fadeIn 0.7s cubic-bezier(.4,0,.2,1);
      backdrop-filter: blur(8px);
    }
    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(40px);}
      to { opacity: 1; transform: none;}
    }
    .auth-header {
      text-align: center;
      margin-bottom: 24px;
    }
    .auth-header h2 {
      font-size: 2.1rem;
      font-weight: 700;
      color: var(--primary-dark);
      margin-bottom: 6px;
      letter-spacing: -1px;
    }
    .auth-header p {
      color: #666;
      font-size: 1.07rem;
      margin: 0;
    }
    .form-group {
      position: relative;
      margin-bottom: 26px;
    }
    .form-input {
      width: 100%;
      padding: 14px 12px 14px 12px;
      border: 1.6px solid #cfd8dc;
      border-radius: 8px;
      background: #f5f7fa;
      font-size: 1.07rem;
      outline: none;
      transition: border-color 0.2s, background 0.2s;
      box-sizing: border-box;
      font-family: inherit;
    }
    .form-input:focus {
      border-color: var(--primary);
      background: #e3f2fd;
    }
    .form-label {
      position: absolute;
      left: 14px;
      top: 14px;
      background: transparent;
      color: #888;
      font-size: 1rem;
      pointer-events: none;
      transition: 0.18s;
      font-weight: 500;
      letter-spacing: 0.01em;
    }
    .form-input:focus + .form-label,
    .form-input:not(:placeholder-shown) + .form-label {
      top: -11px;
      left: 10px;
      background: var(--card-bg);
      padding: 0 6px;
      font-size: 0.93rem;
      color: var(--primary-dark);
      font-weight: 600;
      letter-spacing: 0;
    }
    .input-icon {
      position: absolute;
      right: 12px;
      top: 50%;
      transform: translateY(-50%);
      cursor: pointer;
      color: #888;
      font-size: 1.2rem;
      z-index: 2;
    }
    .caps-lock-warning {
      color: var(--danger);
      font-size: 0.92rem;
      margin-top: 4px;
      display: none;
    }
    .auth-btn {
      width: 100%;
      background: linear-gradient(90deg, var(--primary), var(--accent));
      color: #fff;
      border: none;
      border-radius: 8px;
      padding: 13px 0;
      font-size: 1.09rem;
      font-weight: 700;
      box-shadow: 0 2px 8px rgba(25,118,210,0.09);
      cursor: pointer;
      transition: background 0.18s, transform 0.12s;
      margin-top: 5px;
      margin-bottom: 0;
      box-sizing: border-box;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    .auth-btn:active { transform: scale(0.97);}
    .auth-btn:disabled { background: #b0bec5; cursor: not-allowed;}
    .otp-section {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 100%;
      animation: fadeIn 0.7s cubic-bezier(.4,0,.2,1);
    }
    .otp-inputs {
      display: flex;
      gap: 10px;
      justify-content: center;
      margin-bottom: 12px;
      margin-top: 6px;
    }
    .otp-input {
      width: 44px;
      height: 54px;
      font-size: 2rem;
      text-align: center;
      border: 1.6px solid #cfd8dc;
      border-radius: 8px;
      background: #f5f7fa;
      transition: border 0.2s;
      box-sizing: border-box;
      font-family: inherit;
      outline: none;
    }
    .otp-input:focus {
      border-color: var(--primary);
      background: #e3f2fd;
    }
    .resend-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-top: 8px;
      width: 100%;
      box-sizing: border-box;
      font-size: 0.97rem;
    }
    .resend-link {
      color: var(--primary-dark);
      text-decoration: underline;
      cursor: pointer;
      background: none;
      border: none;
      padding: 0;
      font-size: inherit;
      font-family: inherit;
      margin-left: 8px;
      transition: color 0.2s;
    }
    .resend-link.disabled {
      color: #b0bec5 !important;
      pointer-events: none !important;
      text-decoration: none !important;
      cursor: not-allowed !important;
    }
    .timer {
      color: #888;
      font-size: 0.98rem;
      margin-right: 8px;
    }
    .go-back-btn {
      background: none;
      border: none;
      color: var(--primary-dark);
      font-size: 1rem;
      text-decoration: underline;
      cursor: pointer;
      margin-top: 14px;
      margin-bottom: 0;
      align-self: stretch;
      width: 100%;
      text-align: center;
      display: block;
      transition: color 0.15s;
    }
    .go-back-btn:hover { color: var(--primary);}
    .register-link {
      margin-top: 18px;
      text-align: center;
      font-size: 1rem;
      color: var(--primary-dark);
    }
    .register-link a {
      color: var(--primary-dark);
      text-decoration: underline;
      font-weight: 600;
    }
    .alert {
      display: flex;
      align-items: center;
      gap: 12px;
      border-radius: 10px;
      padding: 13px 18px;
      margin-bottom: 18px;
      font-size: 1.02rem;
      font-weight: 500;
      width: 100%;
      position: relative;
      box-sizing: border-box;
      animation: fadeIn 0.5s;
    }
    .alert-error {
      background: #ffebee;
      color: #c62828;
      border: 1px solid #e53935;
    }
    .alert-success {
      background: #e8f5e9;
      color: #2e7d32;
      border: 1px solid #43a047;
    }
    .alert-warning {
      background: #fff3e0;
      color: #ef6c00;
      border: 1px solid #ff9800;
    }
    @media (max-width: 500px) {
      .auth-card { max-width: 98vw; padding: 16px 5vw 12px 5vw;}
      .otp-input { width: 36px; height: 44px; font-size: 1.3rem;}
    }
  </style>
</head>
<body>
  <div class="auth-card" id="authCard">
    <div class="auth-header">
      <h2 id="formTitle"><?= $step === 'otp' ? "Enter OTP" : "Login" ?></h2>
      <p id="formSubtitle">
        <?php if ($step === 'otp'): ?>
          We've sent a 6-digit code to <b><?= htmlspecialchars($email) ?></b>.<br>Enter it below.
        <?php else: ?>
          Sign in to your account to continue.
        <?php endif; ?>
      </p>
    </div>
    <?php if ($error_message): ?>
      <div class="alert <?= (strpos($error_message, 'pending') !== false) ? 'alert-warning' : 'alert-error' ?>"><?= htmlspecialchars($error_message) ?></div>
    <?php elseif ($message): ?>
      <div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>

    <?php if ($step === 'login'): ?>
      <form method="post" autocomplete="on">
        <div class="form-group">
          <input class="form-input" type="email" id="email" name="email" placeholder=" " required autocomplete="email" value="<?= htmlspecialchars($email) ?>">
          <label class="form-label" for="email">Email</label>
        </div>
        <div class="form-group" style="margin-bottom: 10px;">
          <input class="form-input" type="password" id="password" name="password" placeholder=" " required autocomplete="current-password" onkeyup="checkCapsLock(event)">
          <label class="form-label" for="password">Password</label>
          <span class="input-icon" onclick="togglePassword()" tabindex="0" aria-label="Show or hide password">
            <svg id="eyeIcon" width="22" height="22" fill="none" stroke="#888" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" viewBox="0 0 24 24">
              <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
              <circle cx="12" cy="12" r="3"/>
            </svg>
          </span>
          <div id="capsLockWarning" class="caps-lock-warning" aria-live="polite">Caps Lock is ON</div>
        </div>
        <input type="hidden" name="action" value="login">
        <button class="auth-btn" type="submit" id="loginBtn">
          <span>Send OTP</span>
        </button>
        <div class="register-link">
          New Hospital Registration? <a href="hospital_registration.php">Click here</a>
        </div>
      </form>
    <?php elseif ($step === 'otp'): ?>
      <form method="post" autocomplete="off">
        <div class="otp-section">
          <div class="otp-inputs" aria-label="OTP input fields">
            <?php for ($i = 1; $i <= 6; $i++): ?>
              <input class="otp-input" type="text" inputmode="numeric" maxlength="1" pattern="[0-9]*" name="otp<?= $i ?>" id="otp<?= $i ?>" required>
            <?php endfor; ?>
          </div>
          <input type="hidden" name="otp" id="fullOtp">
          <div class="resend-row">
            <span class="timer" id="otp-timer"></span>
            <a class="resend-link" href="?resend=1" id="resendBtn">Resend OTP</a>
          </div>
        </div>
        <input type="hidden" name="action" value="otp">
        <button class="auth-btn" type="submit" id="verifyBtn">
          <span>Verify OTP</span>
        </button>
        <a class="go-back-btn" href="?back=1">&larr; Go Back</a>
      </form>
      <script>
        // OTP input auto-advance
        const otpInputs = Array.from(document.querySelectorAll('.otp-input'));
        otpInputs.forEach((input, idx, arr) => {
          input.addEventListener('input', function(e) {
            if (this.value.length === 1 && idx < arr.length - 1) {
              arr[idx + 1].focus();
            }
            if (this.value.length > 1) {
              this.value = this.value.slice(0,1);
            }
          });
          input.addEventListener('keydown', function(e) {
            if (e.key === 'Backspace' && !this.value && idx > 0) {
              arr[idx - 1].focus();
            }
          });
        });
        // Combine OTP before submit
        document.querySelector('form').addEventListener('submit', function(e){
          document.getElementById('fullOtp').value = otpInputs.map(i=>i.value).join('');
        });

        // OTP expiry and Resend countdown
        <?php if (isset($_SESSION['otp_generated_at']) && isset($_SESSION['otp_last_sent'])): ?>
        let otpExpiry = <?= $_SESSION['otp_generated_at'] + $otp_expiry_seconds ?>;
        let resendAvailable = <?= $_SESSION['otp_last_sent'] + $resend_wait_seconds ?>;
        let timerEl = document.getElementById('otp-timer');
        let resendBtn = document.getElementById('resendBtn');

        function updateOtpTimer() {
          let now = Math.floor(Date.now() / 1000);
          let timeLeft = otpExpiry - now;
          let resendLeft = resendAvailable - now;

          // OTP expiry countdown
          if (timeLeft > 0) {
            let min = Math.floor(timeLeft / 60);
            let sec = timeLeft % 60;
            timerEl.textContent = `OTP expires in ${min}:${sec.toString().padStart(2,'0')}`;
          } else {
            timerEl.textContent = "OTP expired. Please resend.";
          }

          // Resend OTP countdown
          if (resendLeft > 0) {
            resendBtn.classList.add('disabled');
            resendBtn.textContent = `Resend OTP (${resendLeft}s)`;
          } else {
            resendBtn.classList.remove('disabled');
            resendBtn.textContent = "Resend OTP";
          }
        }

        updateOtpTimer();
        setInterval(updateOtpTimer, 1000);
        <?php endif; ?>
      </script>
    <?php endif; ?>
  </div>
  <script>
    // Password show/hide toggle
    function togglePassword() {
      const pwd = document.getElementById('password');
      const eye = document.getElementById('eyeIcon');
      if (pwd.type === 'password') {
        pwd.type = 'text';
        eye.innerHTML = `<path d="M17.94 17.94A10.06 10.06 0 0 1 12 20c-7 0-11-8-11-8a21.73 21.73 0 0 1 5.06-7.94M1 1l22 22"/><circle cx="12" cy="12" r="3"/>`;
      } else {
        pwd.type = 'password';
        eye.innerHTML = `<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>`;
      }
    }
    // Caps Lock warning
    function checkCapsLock(e) {
      const warning = document.getElementById('capsLockWarning');
      if (e.getModifierState && e.getModifierState('CapsLock')) {
        warning.style.display = 'block';
      } else {
        warning.style.display = 'none';
      }
    }
  </script>
</body>
</html>
