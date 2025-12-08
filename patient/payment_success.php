<?php
session_start();

// Add security headers
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\';');

require('../connection.php');
require('../vendor/autoload.php');

use Razorpay\Api\Api;

// Load environment variables
function loadEnv($path) {
    if (!file_exists($path)) {
        throw new Exception('.env file not found');
    }
    
    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) {
            continue;
        }
        list($name, $value) = explode('=', $line, 2);
        $_ENV[trim($name)] = trim($value);
    }
}

try {
    loadEnv('.env');
} catch (Exception $e) {
    die('Error loading environment variables: ' . $e->getMessage());
}

// Get Razorpay credentials
$keyId = $_ENV['RAZORPAY_KEY_ID'] ?? '';
$keySecret = $_ENV['RAZORPAY_KEY_SECRET'] ?? '';

if (empty($keyId) || empty($keySecret)) {
    die('Razorpay credentials not found');
}

// Get payment response data
$razorpay_payment_id = $_POST['razorpay_payment_id'] ?? '';
$razorpay_order_id = $_POST['razorpay_order_id'] ?? '';
$razorpay_signature = $_POST['razorpay_signature'] ?? '';
$patient_id = filter_input(INPUT_POST, 'patient_id', FILTER_VALIDATE_INT);
$hospital_id = filter_input(INPUT_POST, 'hospital_id', FILTER_VALIDATE_INT);

// Validate required data
if (empty($razorpay_payment_id) || empty($razorpay_order_id) || empty($razorpay_signature) || !$patient_id || !$hospital_id) {
    die('Invalid payment response data');
}

// Verify payment signature
try {
    $api = new Api($keyId, $keySecret);
    
    $attributes = [
        'razorpay_order_id' => $razorpay_order_id,
        'razorpay_payment_id' => $razorpay_payment_id,
        'razorpay_signature' => $razorpay_signature
    ];
    
    $api->utility->verifyPaymentSignature($attributes);
    
    // Payment is verified, now update the database
    try {
        // Start transaction
        $conn->begin_transaction();
        
        // Get registration duration from hospital table
        $hospital_query = "SELECT registration_duration FROM hospitals WHERE id = ?";
        $hospital_stmt = $conn->prepare($hospital_query);
        $hospital_stmt->bind_param("i", $hospital_id);
        $hospital_stmt->execute();
        $hospital_result = $hospital_stmt->get_result();
        
        if ($hospital_result->num_rows === 0) {
            throw new Exception("Hospital not found");
        }
        
        $hospital_data = $hospital_result->fetch_assoc();
        $registration_duration = $hospital_data['registration_duration'];
        
        // Update patient_hospital table
        $update_query = "UPDATE patient_hospital
                        SET registration_duration = ?, 
                            paid_date = NOW(), 
                            registration_status = 'Completed',
                            payment_id = ?,
                            razorpay_order_id = ?
                        WHERE patient_id = ? AND hospital_id = ?";
        
        $update_stmt = $conn->prepare($update_query);
        $update_stmt->bind_param("issii", $registration_duration, $razorpay_payment_id, $razorpay_order_id, $patient_id, $hospital_id);
        
        if (!$update_stmt->execute()) {
            throw new Exception("Failed to update patient hospital record");
        }
        
        if ($update_stmt->affected_rows === 0) {
            throw new Exception("No matching patient hospital record found");
        }
        
        // Commit transaction
        $conn->commit();
        
        // Clear session data
        unset($_SESSION['razorpay_order_id']);
        unset($_SESSION['patient_id']);
        unset($_SESSION['hospital_id']);
        unset($_SESSION['hospital_fee']);
        
        // Success message
        $success_message = "Payment successful! Registration completed.";
        
    } catch (Exception $e) {
        // Rollback transaction
        $conn->rollback();
        error_log("Database update error: " . $e->getMessage());
        die('Error updating registration: ' . $e->getMessage());
    }
    
} catch (Exception $e) {
    error_log("Payment verification failed: " . $e->getMessage());
    die('Payment verification failed. Please contact support.');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Payment Successful</title>
    <meta http-equiv="refresh" content="5;url=patient_homepage.php">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            animation: fadeIn 0.8s ease-in;
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(30px); }
            to { opacity: 1; transform: translateY(0); }
        }

        .success-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
            max-width: 600px;
            width: 100%;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.2);
            animation: slideUp 0.6s ease-out;
        }

        @keyframes slideUp {
            from { opacity: 0; transform: translateY(50px) scale(0.9); }
            to { opacity: 1; transform: translateY(0) scale(1); }
        }

        .success-icon {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            width: 80px;
            height: 80px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            margin: 0 auto 25px;
            box-shadow: 0 10px 30px rgba(40, 167, 69, 0.3);
            animation: checkmark 0.8s ease-in-out 0.3s both;
        }

        @keyframes checkmark {
            0% { transform: scale(0) rotate(180deg); opacity: 0; }
            50% { transform: scale(1.2) rotate(180deg); opacity: 1; }
            100% { transform: scale(1) rotate(0deg); opacity: 1; }
        }

        .success-title {
            color: #2c3e50;
            font-size: 32px;
            font-weight: 700;
            margin-bottom: 15px;
            background: linear-gradient(135deg, #28a745, #20c997);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .success-message {
            color: #6c757d;
            font-size: 18px;
            margin-bottom: 30px;
            line-height: 1.6;
        }

        .payment-details {
            background: linear-gradient(135deg, #f8f9fa, #e9ecef);
            padding: 25px;
            border-radius: 15px;
            margin: 25px 0;
            text-align: left;
            border-left: 4px solid #28a745;
            box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
        }

        .payment-details h3 {
            color: #2c3e50;
            font-size: 20px;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .payment-details h3::before {
            content: "💳";
            font-size: 24px;
        }

        .detail-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid rgba(0, 0, 0, 0.1);
        }

        .detail-row:last-child {
            border-bottom: none;
        }

        .detail-label {
            font-weight: 600;
            color: #495057;
        }

        .detail-value {
            color: #6c757d;
            font-family: 'Courier New', monospace;
            background: rgba(40, 167, 69, 0.1);
            padding: 4px 8px;
            border-radius: 6px;
            font-size: 14px;
        }

        .countdown-container {
            background: linear-gradient(135deg, #17a2b8, #138496);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            font-size: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }

        .countdown {
            font-weight: bold;
            font-size: 20px;
            background: rgba(255, 255, 255, 0.2);
            padding: 5px 10px;
            border-radius: 5px;
            min-width: 30px;
            display: inline-block;
        }

        .btn {
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 15px 35px;
            text-decoration: none;
            border-radius: 50px;
            display: inline-block;
            margin-top: 20px;
            font-weight: 600;
            font-size: 16px;
            transition: all 0.3s ease;
            box-shadow: 0 8px 25px rgba(0, 123, 255, 0.3);
            border: none;
            cursor: pointer;
        }

        .btn:hover {
            background: linear-gradient(135deg, #0056b3, #004085);
            transform: translateY(-2px);
            box-shadow: 0 12px 35px rgba(0, 123, 255, 0.4);
        }

        .btn:active {
            transform: translateY(0);
        }

        .status-badge {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }

        @media (max-width: 768px) {
            .success-container {
                padding: 30px 20px;
                margin: 10px;
            }

            .success-title {
                font-size: 24px;
            }

            .success-icon {
                width: 60px;
                height: 60px;
                font-size: 30px;
            }

            .detail-row {
                flex-direction: column;
                align-items: flex-start;
                gap: 5px;
            }

            .detail-value {
                word-break: break-all;
            }
        }

        .loading-dots {
            display: inline-block;
        }

        .loading-dots::after {
            content: '';
            animation: dots 1.5s infinite;
        }

        @keyframes dots {
            0%, 20% { content: ''; }
            40% { content: '.'; }
            60% { content: '..'; }
            80%, 100% { content: '...'; }
        }
    </style>
</head>
<body>
    <div class="success-container">
        <div class="success-icon">✓</div>
        <h1 class="success-title">Payment Successful!</h1>
        <p class="success-message"><?= htmlspecialchars($success_message) ?></p>
        
        <div class="payment-details">
            <h3>Payment Details</h3>
            <div class="detail-row">
                <span class="detail-label">Payment ID:</span>
                <span class="detail-value"><?= htmlspecialchars($razorpay_payment_id) ?></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Order ID:</span>
                <span class="detail-value"><?= htmlspecialchars($razorpay_order_id) ?></span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Status:</span>
                <span class="status-badge">Completed</span>
            </div>
            <div class="detail-row">
                <span class="detail-label">Date:</span>
                <span class="detail-value"><?= date('Y-m-d H:i:s') ?></span>
            </div>
        </div>

        <div class="countdown-container">
            <span>Redirecting to dashboard in <span class="countdown" id="countdown">5</span> seconds<span class="loading-dots"></span></span>
        </div>
        
        <a href="patient_homepage.php" class="btn">Go to Dashboard Now</a>
    </div>

    <script>
        // Countdown timer
        let timeLeft = 5;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(() => {
            timeLeft--;
            countdownElement.textContent = timeLeft;
            
            if (timeLeft <= 0) {
                clearInterval(timer);
                window.location.href = 'patient_homepage.php';
            }
        }, 1000);

        // Optional: Pause countdown on hover
        const container = document.querySelector('.success-container');
        let isPaused = false;
        
        container.addEventListener('mouseenter', () => {
            if (!isPaused) {
                clearInterval(timer);
                isPaused = true;
            }
        });
        
        container.addEventListener('mouseleave', () => {
            if (isPaused && timeLeft > 0) {
                isPaused = false;
                const newTimer = setInterval(() => {
                    timeLeft--;
                    countdownElement.textContent = timeLeft;
                    
                    if (timeLeft <= 0) {
                        clearInterval(newTimer);
                        window.location.href = 'patient_homepage.php';
                    }
                }, 1000);
            }
        });
    </script>
</body>
</html>
