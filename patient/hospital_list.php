<?php
// Security headers with corrected CSP for Font Awesome
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');
header('Referrer-Policy: strict-origin-when-cross-origin');
header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\' https://cdnjs.cloudflare.com; style-src \'self\' \'unsafe-inline\' https://fonts.googleapis.com https://cdnjs.cloudflare.com; font-src \'self\' https://fonts.gstatic.com https://cdnjs.cloudflare.com; img-src \'self\' data: https:; connect-src \'self\';');
header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');

session_start();

// Regenerate session ID for security
if (!isset($_SESSION['session_regenerated'])) {
    session_regenerate_id(true);
    $_SESSION['session_regenerated'] = true;
}

include '../connection.php';

// CSRF Token Generation
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Get the patient ID from the session
$patient_id = $_SESSION['user_id'] ?? null;

// Redirect if not logged in
if (!$patient_id) {
    header('Location: login.php');
    exit();
}

// Initialize variables
$patient_name = '';
$patient_email = '';
$hospitals = [];

// Fetch patient details with prepared statement
if ($patient_id) {
    $patient_sql = "SELECT first_name, last_name, email FROM patients WHERE id = ? LIMIT 1";
    $patient_stmt = $conn->prepare($patient_sql);
    
    if (!$patient_stmt) {
        error_log("Database prepare error: " . $conn->error);
        die("Database error occurred");
    }
    
    $patient_stmt->bind_param("i", $patient_id);
    $patient_stmt->execute();
    $patient_result = $patient_stmt->get_result();
    
    if ($patient = $patient_result->fetch_assoc()) {
        $patient_name = htmlspecialchars($patient['first_name'] . ' ' . $patient['last_name'], ENT_QUOTES, 'UTF-8');
        $patient_email = htmlspecialchars($patient['email'], ENT_QUOTES, 'UTF-8');
    }
    $patient_stmt->close();
}

// Fetch hospital details with payment information
if ($patient_id) {
    $sql = "
        SELECT h.id AS hospital_id, h.hospital_name, h.state, h.city, 
               ph.registration_status, h.registration_fee, h.registration_duration,
               ph.paid_date, ph.payment_id, ph.razorpay_order_id
        FROM patient_hospital ph
        INNER JOIN hospitals h ON ph.hospital_id = h.id
        WHERE ph.patient_id = ?
    ";
    $stmt = $conn->prepare($sql);
    
    if (!$stmt) {
        error_log("Database prepare error: " . $conn->error);
        die("Database error occurred");
    }
    
    $stmt->bind_param("i", $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    while ($row = $result->fetch_assoc()) {
        // Calculate validity date if paid_date and registration_duration exist
        $valid_till = null;
        if ($row['paid_date'] && $row['registration_duration']) {
            $paid_date = new DateTime($row['paid_date']);
            $valid_till = $paid_date->add(new DateInterval('P' . $row['registration_duration'] . 'D'))->format('Y-m-d');
        }
        
        // Sanitize output data
        $hospitals[] = [
            'hospital_id' => (int)$row['hospital_id'],
            'hospital_name' => htmlspecialchars($row['hospital_name'], ENT_QUOTES, 'UTF-8'),
            'state' => htmlspecialchars($row['state'], ENT_QUOTES, 'UTF-8'),
            'city' => htmlspecialchars($row['city'], ENT_QUOTES, 'UTF-8'),
            'registration_status' => htmlspecialchars($row['registration_status'], ENT_QUOTES, 'UTF-8'),
            'registration_fee' => (float)$row['registration_fee'],
            'registration_duration' => (int)$row['registration_duration'],
            'paid_date' => $row['paid_date'],
            'payment_id' => htmlspecialchars($row['payment_id'], ENT_QUOTES, 'UTF-8'),
            'razorpay_order_id' => htmlspecialchars($row['razorpay_order_id'], ENT_QUOTES, 'UTF-8'),
            'valid_till' => $valid_till
        ];
    }
    $stmt->close();
}
$conn->close();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hospital Registration</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f0f7fa;
            color: #333;
            line-height: 1.6;
            padding: 20px;
        }
        
        .page-header {
            text-align: center;
            margin-bottom: 40px;
            padding: 30px 0;
            position: relative;
        }
        
        .page-header h1 {
            font-size: 32px;
            font-weight: 700;
            color: #1a365d;
            margin-bottom: 12px;
            letter-spacing: -0.5px;
        }
        
        .page-header p {
            color: #4a6f8a;
            font-size: 16px;
            max-width: 600px;
            margin: 0 auto;
        }
        
        .page-header::after {
            content: '';
            position: absolute;
            bottom: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 80px;
            height: 4px;
            background: linear-gradient(90deg, #0ea5e9, #06b6d4);
            border-radius: 2px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
            gap: 30px;
        }
        
        .card {
            background-color: #ffffff;
            border-radius: 16px;
            overflow: hidden;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.05);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
            border: 1px solid #e2e8f0;
        }
        
        .card:hover {
            transform: translateY(-8px);
            box-shadow: 0 25px 30px -12px rgba(0, 0, 0, 0.15), 0 10px 15px -5px rgba(0, 0, 0, 0.08);
        }
        
        .card-header {
            background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
            color: white;
            padding: 25px;
            position: relative;
        }
        
        .card-header.completed {
            background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        }
        
        .hospital-icon {
            position: absolute;
            top: 25px;
            right: 25px;
            font-size: 28px;
            opacity: 0.8;
            color: rgba(255, 255, 255, 0.9);
        }
        
        .hospital-name {
            font-size: 22px;
            font-weight: 600;
            margin-bottom: 8px;
            padding-right: 30px;
            text-shadow: 0 1px 2px rgba(0, 0, 0, 0.1);
        }
        
        .location {
            display: flex;
            align-items: center;
            font-size: 15px;
            opacity: 0.9;
        }
        
        .location i {
            margin-right: 8px;
        }
        
        .card-body {
            padding: 25px;
        }
        
        .info-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 20px;
            border-bottom: 1px solid #edf2f7;
        }
        
        .info-row:last-child {
            border-bottom: none;
            margin-bottom: 0;
            padding-bottom: 0;
        }
        
        .info-label {
            color: #4a6f8a;
            font-size: 15px;
            font-weight: 500;
        }
        
        .info-value {
            font-weight: 600;
            color: #1a365d;
        }
        
        .status {
            display: inline-flex;
            align-items: center;
            padding: 8px 16px;
            border-radius: 50px;
            font-size: 14px;
            font-weight: 600;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.05);
        }
        
        .status.completed {
            background-color: #dcfce7;
            color: #166534;
            border: 1px solid #bbf7d0;
        }
        
        .status.pending {
            background-color: #fff7ed;
            color: #9a3412;
            border: 1px solid #fed7aa;
        }
        
        .status i {
            margin-right: 8px;
        }
        
        .fee-container {
            background-color: #f8fafc;
            padding: 18px;
            border-radius: 12px;
            margin: 20px 0;
            display: flex;
            justify-content: space-between;
            align-items: center;
            border: 1px solid #e2e8f0;
        }
        
        .fee-label {
            font-size: 16px;
            color: #4a6f8a;
            font-weight: 500;
        }
        
        .fee-amount {
            font-size: 22px;
            font-weight: 700;
            color: #1a365d;
            background: linear-gradient(90deg, #0ea5e9, #06b6d4);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .payment-details {
            background-color: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 12px;
            padding: 20px;
            margin: 20px 0;
        }
        
        .payment-header {
            display: flex;
            align-items: center;
            margin-bottom: 15px;
            color: #166534;
            font-weight: 600;
            font-size: 16px;
        }
        
        .payment-header i {
            margin-right: 10px;
            font-size: 18px;
        }
        
        .payment-info {
            display: grid;
            gap: 10px;
        }
        
        .payment-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            font-size: 14px;
        }
        
        .payment-label {
            color: #374151;
            font-weight: 500;
        }
        
        .payment-value {
            color: #166534;
            font-weight: 600;
        }
        
        .validity-warning {
            background-color: #fef3c7;
            border: 1px solid #f59e0b;
            color: #92400e;
            padding: 12px;
            border-radius: 8px;
            margin-top: 15px;
            font-size: 14px;
            display: flex;
            align-items: center;
        }
        
        .validity-warning i {
            margin-right: 8px;
        }
        
        .no-fee-message {
            background-color: #e0f2fe;
            border: 1px solid #0ea5e9;
            color: #0c4a6e;
            padding: 15px;
            border-radius: 12px;
            margin: 20px 0;
            font-size: 15px;
            display: flex;
            align-items: center;
            font-weight: 500;
        }
        
        .no-fee-message i {
            margin-right: 10px;
            font-size: 18px;
        }
        
        .button-container {
            margin-top: 25px;
        }
        
        .btn-payment {
            width: 100%;
            background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
            color: white;
            padding: 14px 20px;
            border: none;
            border-radius: 12px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            display: flex;
            justify-content: center;
            align-items: center;
            transition: all 0.3s ease;
            box-shadow: 0 4px 12px rgba(6, 182, 212, 0.3);
            letter-spacing: 0.5px;
        }
        
        .btn-payment:hover {
            background: linear-gradient(135deg, #06b6d4 0%, #0ea5e9 100%);
            transform: translateY(-3px);
            box-shadow: 0 8px 16px rgba(6, 182, 212, 0.4);
        }
        
        .btn-payment i {
            margin-right: 10px;
            font-size: 18px;
        }
        
        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 80px 30px;
            background-color: white;
            border-radius: 16px;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
        }
        
        .empty-state i {
            font-size: 70px;
            color: #94a3b8;
            margin-bottom: 25px;
            background: linear-gradient(135deg, #0ea5e9 0%, #06b6d4 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .empty-state h2 {
            font-size: 28px;
            color: #1a365d;
            margin-bottom: 15px;
        }
        
        .empty-state p {
            color: #4a6f8a;
            max-width: 500px;
            margin: 0 auto;
            font-size: 16px;
            line-height: 1.7;
        }
        
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
            }
            
            .page-header h1 {
                font-size: 28px;
            }
            
            .card-header {
                padding: 20px;
            }
            
            .card-body {
                padding: 20px;
            }
            
            .hospital-name {
                font-size: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="page-header">
        <h1>Hospital Registration</h1>
        <p>Manage your hospital registrations and complete any pending payments</p>
    </div>
    
    <div class="container">
        <?php if (!empty($hospitals)): ?>
            <?php foreach ($hospitals as $hospital): ?>
            <div class="card">
                <div class="card-header <?= ($hospital['registration_status'] === 'Completed') ? 'completed' : '' ?>">
                    <i class="fas fa-hospital hospital-icon"></i>
                    <div class="hospital-name"><?= $hospital['hospital_name'] ?></div>
                    <div class="location">
                        <i class="fas fa-map-marker-alt"></i>
                        <?= $hospital['city'] ?>, <?= $hospital['state'] ?>
                    </div>
                </div>
                <div class="card-body">
                    <div class="info-row">
                        <span class="info-label">Registration Status</span>
                        <?php if ($hospital['registration_status'] === 'Completed'): ?>
                            <span class="status completed">
                                <i class="fas fa-check-circle"></i>Completed
                            </span>
                        <?php else: ?>
                            <span class="status pending">
                                <i class="fas fa-clock"></i>Pending
                            </span>
                        <?php endif; ?>
                    </div>
                    
                    <?php if ($hospital['registration_fee'] == 0 && $hospital['registration_status'] === 'Completed'): ?>
                        <!-- No Fee Message for Completed Registration with Zero Fee -->
                        <div class="no-fee-message">
                            <i class="fas fa-info-circle"></i>
                            This hospital does not take registration fee
                        </div>
                    <?php elseif ($hospital['registration_fee'] > 0 && $hospital['paid_date']): ?>
                        <!-- Payment Details Section -->
                        <div class="payment-details">
                            <div class="payment-header">
                                <i class="fas fa-check-circle"></i>
                                Payment Completed
                            </div>
                            <div class="payment-info">
                                <div class="payment-row">
                                    <span class="payment-label">Amount Paid:</span>
                                    <span class="payment-value">₹<?= number_format($hospital['registration_fee'], 2) ?></span>
                                </div>
                                <div class="payment-row">
                                    <span class="payment-label">Payment Date:</span>
                                    <span class="payment-value"><?= date('d M Y', strtotime($hospital['paid_date'])) ?></span>
                                </div>
                                <?php if ($hospital['valid_till']): ?>
                                <div class="payment-row">
                                    <span class="payment-label">Valid Till:</span>
                                    <span class="payment-value"><?= date('d M Y', strtotime($hospital['valid_till'])) ?></span>
                                </div>
                                <?php endif; ?>
                                <?php if ($hospital['payment_id']): ?>
                                <div class="payment-row">
                                    <span class="payment-label">Payment ID:</span>
                                    <span class="payment-value"><?= $hospital['payment_id'] ?></span>
                                </div>
                                <?php endif; ?>
                                <?php if ($hospital['razorpay_order_id']): ?>
                                <div class="payment-row">
                                    <span class="payment-label">Razorpay Order ID:</span>
                                    <span class="payment-value"><?= $hospital['razorpay_order_id'] ?></span>
                                </div>
                                <?php endif; ?>
                            </div>
                            
                            <?php if ($hospital['valid_till'] && strtotime($hospital['valid_till']) < time()): ?>
                            <div class="validity-warning">
                                <i class="fas fa-exclamation-triangle"></i>
                                Registration has expired. Please renew your registration.
                            </div>
                            <?php endif; ?>
                        </div>
                    <?php elseif ($hospital['registration_status'] !== 'Completed' && $hospital['registration_fee'] > 0): ?>
                        <!-- Pending Payment Section -->
                        <div class="fee-container">
                            <span class="fee-label">Registration Fee</span>
                            <span class="fee-amount">₹<?= number_format($hospital['registration_fee'], 2) ?></span>
                        </div>
                        
                        <div class="button-container">
                            <form action="process_payment.php" method="POST">
                                <!-- CSRF Token -->
                                <input type="hidden" name="csrf_token" value="<?= $_SESSION['csrf_token'] ?>">
                                <!-- Hidden fields with required data -->
                                <input type="hidden" name="patient_name" value="<?= $patient_name ?>">
                                <input type="hidden" name="hospital_id" value="<?= $hospital['hospital_id'] ?>">
                                <input type="hidden" name="patient_email" value="<?= $patient_email ?>">
                                <input type="hidden" name="hospital_fee" value="<?= $hospital['registration_fee'] ?>">
                                <input type="hidden" name="patient_id" value="<?= $patient_id ?>">
                                <button type="submit" class="btn-payment">
                                    <i class="fas fa-credit-card"></i>Complete Payment
                                </button>
                            </form>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
            <?php endforeach; ?>
        <?php else: ?>
            <div class="empty-state">
                <i class="fas fa-hospital-user"></i>
                <h2>No Hospitals Found</h2>
                <p>You haven't registered with any hospitals yet. Please contact your healthcare provider for more information.</p>
            </div>
        <?php endif; ?>
    </div>
</body>
</html>
