<?php
include '../connection.php';
session_start();

// Retrieve patient_id and doctor_id from session
$patient_id = $_SESSION['patient_id'];
$doctor_id = $_SESSION['doctor_id'];

if (!$patient_id || !$doctor_id) {
    header("Location: doctor_profile.php?error=Missing required session data.");
    exit;
}

// Get the patient's email address from the patients table
$sql_email = "SELECT email FROM patients WHERE id = ?";
$stmt_email = $conn->prepare($sql_email);
$stmt_email->bind_param("i", $patient_id);
$stmt_email->execute();
$result_email = $stmt_email->get_result();

if ($result_email->num_rows == 0) {
    header("Location: doctor_profile.php?error=Patient email not found.");
    exit;
}

$patient_email = $result_email->fetch_assoc()['email'];
$stmt_email->close();

// Get doctor's name from the doctors table
$sql_doctor = "SELECT first_name, last_name FROM doctors WHERE id = ?";
$stmt_doctor = $conn->prepare($sql_doctor);
$stmt_doctor->bind_param("i", $doctor_id);
$stmt_doctor->execute();
$result_doctor = $stmt_doctor->get_result();

if ($result_doctor->num_rows == 0) {
    header("Location: doctor_profile.php?error=Doctor not found.");
    exit;
}

$doctor = $result_doctor->fetch_assoc();
$doctor_name = "Dr. " . $doctor['first_name'] . " " . $doctor['last_name'];
$stmt_doctor->close();

require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// Send the email
try {
    $mail = new PHPMailer(true);
    $mail->isSMTP();
    $mail->Host = 'smtp.gmail.com';
    $mail->SMTPAuth = true;
    $mail->Username = ''; // Replace with your email
    $mail->Password = ''; // Replace with your App Password
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
    $mail->Port = 587;
    $mail->setFrom('replace@gmail.com', 'Medication Alert'); // Replace with your email
    $mail->addAddress($patient_email);

    // Email content
    $mail->isHTML(true);
    $mail->Subject = "Medication Alert";

    $mail->Body = "
        <h1 style='color: red;'>Medication Alert</h1>
        <p style='font-size: 16px;'>
            <b>$doctor_name</b> has updated your problem description. 
            Please check it out on the portal</a>.
        </p>
        <p>Thank you!</p>
    ";

    $mail->send();
} catch (Exception $e) {
    error_log("Mailer Error: " . $mail->ErrorInfo);
    header("Location: doctor_profile.php?error=Email could not be sent.");
    exit;
}

// Close the database connection
$conn->close();

// Redirect to doctor_dashboard.php
header("Location: doctor_profile.php?message=Email sent successfully.");
exit;
?>