<?php
include '../connection.php';
session_start();

// Retrieve the encryption key
$key_path = '../../encryption_key.key';
$encryption_key = trim(file_get_contents($key_path));

// Validate the request method
if ($_SERVER["REQUEST_METHOD"] !== "POST" || $_POST['form_action'] !== 'solution_form') {
    header("Location: doctor_profile.php?message=Invalid request.");
    exit;
}

// Extract history ID and validate
$history_id = $_POST['history_id'] ?? null;
if (!$history_id) {
    header("Location: doctor_profile.php?message=History ID is required.");
    exit;
}
$doctor_id = $_SESSION['doctor_id'];

// Fetch patient_id from the database using history_id
$patient_query = "SELECT patient_id FROM patient_history WHERE id = ?";
$patient_stmt = $conn->prepare($patient_query);
$patient_stmt->bind_param("i", $history_id);
$patient_stmt->execute();
$patient_stmt->bind_result($patient_id);
$patient_stmt->fetch();
$patient_stmt->close();

if (!$patient_id) {
    header("Location: doctor_profile.php?message=Invalid History ID.");
    exit;
}

// Set patient_id in session
$_SESSION['patient_id'] = $patient_id;

// Extract and validate form inputs
$doctor_solution = htmlspecialchars(mysqli_real_escape_string($conn, $_POST['doctor_solution'] ?? ''));
$treatment_type = htmlspecialchars(mysqli_real_escape_string($conn, $_POST['treatment_type'] ?? ''));
$appointment_date = isset($_POST['appointment_date']) ? mysqli_real_escape_string($conn, $_POST['appointment_date']) : null;
$medication_count = isset($_POST['medication_count']) ? intval($_POST['medication_count']) : 0;

if (empty($doctor_solution) || empty($treatment_type)) {
    header("Location: edit_issue.php?id=$history_id&error=All fields are required.");
    exit;
}

// Encrypt the doctor solution
$iv = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
$tag = ''; // Define tag as a reference variable
$encrypted_solution = openssl_encrypt(
    $doctor_solution,
    'aes-256-gcm',
    $encryption_key,
    0,
    $iv,
    $tag
);

// Begin transaction
$conn->begin_transaction();

try {
    // Update patient history
    $update_query = "UPDATE patient_history
                     SET doctor_id = ?, doctor_solution = ?, treatment_type = ?, appointment_date = ?, status = 'completed', date_completed = NOW(), solution_iv = ?, solution_tag = ?
                     WHERE id = ?";
    $stmt = $conn->prepare($update_query);
    $stmt->bind_param("ssssssi", $doctor_id, $encrypted_solution, $treatment_type, $appointment_date, $iv, $tag, $history_id);
    $stmt->execute();

    // Insert medications if provided
    for ($i = 1; $i <= $medication_count; $i++) {
        $medication_name = $_POST["medication_name_$i"] ?? '';
        $medication_type = $_POST["medication_type_$i"] ?? '';
        $dosage_quantity = $_POST["dosage_quantity_$i"] ?? '';
        $morning_time = $_POST["morning_time_$i"] ?? null;
        $afternoon_time = $_POST["afternoon_time_$i"] ?? null;
        $evening_time = $_POST["evening_time_$i"] ?? null;
        $night_time = $_POST["night_time_$i"] ?? null;
        $start_date = $_POST["start_date_$i"] ?? null;
        $end_date = $_POST["end_date_$i"] ?? null;
        $additional_instructions = $_POST["additional_instructions_$i"] ?? null;

        if (!empty($medication_name)) {
            $med_insert_query = "INSERT INTO medication_alerts (patient_history_id, medication_name, medication_type, dosage, morning_time, afternoon_time, evening_time, night_time, start_date, end_date, additional_instructions)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $med_stmt = $conn->prepare($med_insert_query);
            $med_stmt->bind_param("issssssssss", $history_id, $medication_name, $medication_type, $dosage_quantity, $morning_time, $afternoon_time, $evening_time, $night_time, $start_date, $end_date, $additional_instructions);
            $med_stmt->execute();
        }
    }

    // Commit transaction
    $conn->commit();

    // Redirect after success
    header("Location: conformation_mail.php?message=Solution submitted successfully.");
    exit;
} catch (Exception $e) {
    // Rollback on error
    $conn->rollback();
    header("Location: edit_issue.php?id=$history_id&error=" . urlencode($e->getMessage()));
    exit;
}
?>
