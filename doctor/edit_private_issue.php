<?php
include '../connection.php';
session_start();

// Check if the doctor is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.html");
    exit;
}

$doctor_id = $_SESSION['user_id'];

// Retrieve the encryption key securely
$key_path = '../../encryption_key.key';
$encryption_key = trim(file_get_contents($key_path));

if (!$encryption_key) {
    die("Error: Encryption key is missing!");
}

// Helper function for decryption
function decrypt_data($data, $iv, $auth_tag, $encryption_key)
{
    return openssl_decrypt($data, 'aes-256-gcm', $encryption_key, 0, $iv, $auth_tag);
}

// Handle form submission for solution
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $problem_id = filter_input(INPUT_POST, 'problem_id', FILTER_VALIDATE_INT);
    $doctor_solution = trim($_POST['doctor_solution']);

    if (!$problem_id || !$doctor_solution) {
        die("Error: Problem ID and Solution are required.");
    }

    // Encrypt the solution
    $iv = random_bytes(16);
    $auth_tag = '';

    $encrypted_solution = openssl_encrypt(
        $doctor_solution,
        'aes-256-gcm',
        $encryption_key,
        0,
        $iv,
        $auth_tag
    );

    if ($encrypted_solution === false) {
        die("Error: Failed to encrypt the solution!");
    }

    // Update solution in the database
    $query = "UPDATE private_problems 
              SET doctor_solution = ?, solution_iv = ?, solution_auth_tag = ?, status = 'completed', updated_at = NOW()
              WHERE id = ? AND doctor_id = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        die("Error: Failed to prepare query.");
    }
    $stmt->bind_param("sssii", $encrypted_solution, $iv, $auth_tag, $problem_id, $doctor_id);

    if ($stmt->execute()) {
        header("Location: edit_private_issue.php?message=SolutionSubmitted");
        exit;
    } else {
        die("Error: Failed to update the solution. " . $stmt->error);
    }
} else {
    // Fetch encrypted problem details
    $problem_id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

    if (!$problem_id) {
        die("Error: Valid Problem ID is required.");
    }

    $query = "SELECT problem_description, iv, auth_tag, video_file, video_iv, video_auth_tag 
              FROM private_problems 
              WHERE id = ? AND doctor_id = ?";
    $stmt = $conn->prepare($query);
    if (!$stmt) {
        die("Error: Failed to prepare query.");
    }
    $stmt->bind_param("ii", $problem_id, $doctor_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();

    if (!$row) {
        die("Error: No problem found or access denied. Problem ID: $problem_id, Doctor ID: $doctor_id");
    }

    // Decrypt problem description
    $decrypted_description = decrypt_data(
        $row['problem_description'],
        $row['iv'],
        $row['auth_tag'],
        $encryption_key
    );

    if ($decrypted_description === false) {
        die("Error: Failed to decrypt the problem description!");
    }

    // Decrypt and save video if available
    $decrypted_video_path = null;
    if (!empty($row['video_file'])) {
        $decrypted_video = decrypt_data(
            $row['video_file'],
            $row['video_iv'],
            $row['video_auth_tag'],
            $encryption_key
        );

        if ($decrypted_video === false) {
            die("Error: Failed to decrypt the video file!");
        }

        // Save to temporary file
        $temp_dir = '../temp/';
        if (!is_dir($temp_dir)) {
            mkdir($temp_dir, 0755, true);
        }
        $decrypted_video_path = $temp_dir . uniqid() . '.mp4';
        file_put_contents($decrypted_video_path, $decrypted_video);
    }

    // Fetch patient_id for previous consultation link
    $query_patient = "SELECT patient_id FROM private_problems WHERE id = ? AND doctor_id = ?";
    $stmt_patient = $conn->prepare($query_patient);
    if (!$stmt_patient) {
        die("Error: Failed to prepare query for patient_id.");
    }
    $stmt_patient->bind_param("ii", $problem_id, $doctor_id);
    $stmt_patient->execute();
    $result_patient = $stmt_patient->get_result();
    $patient_row = $result_patient->fetch_assoc();

    if (!$patient_row) {
        die("Error: Patient ID not found for the provided problem ID.");
    }
    $patient_id = $patient_row['patient_id'];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Provide Solution</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f9f9f9;
        }
        .container {
            max-width: 800px;
            margin: auto;
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
        }
        header h1 {
            text-align: center;
            color: #333;
        }
        label {
            font-weight: bold;
            display: block;
            margin-top: 15px;
        }
        textarea, input[type="submit"], .btn {
            width: 100%;
            padding: 10px;
            margin-top: 5px;
            border-radius: 5px;
            border: 1px solid #ccc;
            font-size: 16px;
        }
        input[type="submit"] {
            background-color: #4CAF50;
            color: white;
            cursor: pointer;
        }
        input[type="submit"]:hover {
            background-color: #45a049;
        }
        video {
            display: block;
            margin-top: 15px;
            width: 100%;
            max-width: 100%;
            border: 1px solid #ccc;
        }
        .btn {
            text-align: center;
            background-color: #007BFF;
            color: white;
            text-decoration: none;
            display: block;
            text-align: center;
            cursor: pointer;
        }
        .btn:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
<div class="container">
    <header>
        <h1>Provide Solution</h1>
    </header>
    <form action="" method="POST">
        <input type="hidden" name="problem_id" value="<?= htmlspecialchars($problem_id) ?>">
        <label for="problem_description">Problem Description:</label>
        <textarea id="problem_description" name="problem_description" disabled><?= htmlspecialchars($decrypted_description) ?></textarea>
        <label for="doctor_solution">Doctor Solution:</label>
        <textarea id="doctor_solution" name="doctor_solution" required></textarea>
        <?php if ($decrypted_video_path): ?>
            <label for="video">Attached Video:</label>
            <video controls>
                <source src="<?= htmlspecialchars($decrypted_video_path) ?>" type="video/mp4">
                Your browser does not support the video tag.
            </video>
        <?php endif; ?>
        <input type="submit" value="Submit Solution">
    </form>
    <a href="cunsult_page.php?patient_id=<?= htmlspecialchars($patient_id) ?>" class="btn">Previous Consultation</a>
</div>
</body>
</html>
