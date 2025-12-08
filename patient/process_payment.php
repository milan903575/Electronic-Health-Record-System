<?php
session_start();
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

loadEnv('.env');

// Razorpay credentials from environment
$keyId = $_ENV['RAZORPAY_KEY_ID'];
$keySecret = $_ENV['RAZORPAY_KEY_SECRET'];

// Get POST data
$patient_name   = $_POST['patient_name'] ?? '';
$hospital_id    = $_POST['hospital_id'] ?? '';
$patient_email  = $_POST['patient_email'] ?? '';
$hospital_fee   = $_POST['hospital_fee'] ?? '';
$patient_id     = $_POST['patient_id'] ?? '';

// Amount in paise
$amount_paise = intval($hospital_fee) * 100;

// Create Razorpay Order
$api = new Api($keyId, $keySecret);
$orderData = [
    'receipt'         => 'order_rcptid_' . uniqid(),
    'amount'          => $amount_paise,
    'currency'        => 'INR',
    'payment_capture' => 1
];

$razorpayOrder = $api->order->create($orderData);
$razorpayOrderId = $razorpayOrder['id'];

// Store in session
$_SESSION['razorpay_order_id'] = $razorpayOrderId;
$_SESSION['patient_id'] = $patient_id;
$_SESSION['hospital_id'] = $hospital_id;

$data = [
    "key"               => $keyId,
    "amount"            => $amount_paise,
    "name"              => "Hospital Registration",
    "description"       => "Registration Fee",
    "image"             => "https://localhost/patientRecords/patient/uploads/images/profile_678137534509a9.29237744.png",
    "prefill"           => [
        "name"  => $patient_name,
        "email" => $patient_email
    ],
    "order_id"          => $razorpayOrderId,
    "theme"             => [
        "color" => "#F37254"
    ]
];
$json = json_encode($data);
?>

<!DOCTYPE html>
<html>
<head>
    <title>Processing Payment...</title>
    <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
</head>
<body>
    <p style="text-align:center;">Redirecting to payment...</p>
    <script>
        var options = <?= $json ?>;
        options.handler = function (response){
            var form = document.createElement('form');
            form.method = 'POST';
            form.action = "payment_success.php";

            var fields = {
                razorpay_payment_id: response.razorpay_payment_id,
                razorpay_order_id: response.razorpay_order_id,
                razorpay_signature: response.razorpay_signature,
                patient_id: "<?= $patient_id ?>",
                hospital_id: "<?= $hospital_id ?>",
                patient_name: "<?= $patient_name ?>",
                patient_email: "<?= $patient_email ?>"
            };

            for (var key in fields) {
                if (fields.hasOwnProperty(key)) {
                    var hiddenField = document.createElement("input");
                    hiddenField.type = "hidden";
                    hiddenField.name = key;
                    hiddenField.value = fields[key];
                    form.appendChild(hiddenField);
                }
            }
            document.body.appendChild(form);
            form.submit();
        };

        options.modal = {
            "ondismiss": function(){
                window.location.href = "hospital_list.php";
            }
        };

        var rzp1 = new Razorpay(options);
        window.onload = function() {
            rzp1.open();
        };
    </script>
</body>
</html>
