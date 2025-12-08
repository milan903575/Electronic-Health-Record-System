<?php
require_once '../connection.php';
session_start();

// Check if the patient is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.php");
    exit;
}

$patient_id = $_SESSION['user_id'];

// Retrieve the encryption key
$key_path = '../../encryption_key.key';
$encryption_key = trim(file_get_contents($key_path));

if (!$encryption_key) {
    displayMessageAndRedirect("Encryption key is missing!", "detailed_problem.php", false);
    exit;
}

// Process the form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $problem_description = $_POST['problem_description'];
    $problem_specialization = $_POST['problem'];
    $current_medication = $_POST['current_medication'] ?? '';

    // Find a suitable doctor based on specialization and workload
    $sql = "SELECT d.id, COUNT(ph.id) AS pending_count
            FROM doctors d
            LEFT JOIN patient_history ph ON d.id = ph.doctor_id AND ph.status = 'pending'
            WHERE d.specialization = ?
            GROUP BY d.id
            ORDER BY pending_count ASC
            LIMIT 1";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $problem_specialization);
    $stmt->execute();
    $result = $stmt->get_result();
    $doctor_row = $result->fetch_assoc();

    if ($doctor_row) {
        $doctor_id = $doctor_row['id'];
    } else {
        // Try to assign a General Physician
        $sql = "SELECT id FROM doctors WHERE specialization = 'General Physician' LIMIT 1";
        $result = $conn->query($sql);
        $general_physician = $result->fetch_assoc();
    
        if ($general_physician) {
            $doctor_id = $general_physician['id'];
        } else {
            // No doctor available at all
            displayMessageAndRedirect(
                "No doctors available for your problem type at the moment. For selected problem type in your selected hospital please try again later",
                "detailed_problem.php",
                false
            );
            exit;
        }
    }
    

    $sql = "SELECT hospital_id FROM patient_hospital WHERE patient_id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("i", $patient_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $row = $result->fetch_assoc();
    $hospital_id = $row['hospital_id'] ?? null;

    if (!$hospital_id) {
        displayMessageAndRedirect("Hospital not found for this patient.", "detailed_problem.php", false);
        exit;
    }

    // Encrypt problem description
    $iv_desc = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $tag_desc = '';
    $encrypted_description = openssl_encrypt(
        $problem_description,
        'aes-256-gcm',
        $encryption_key,
        0,
        $iv_desc,
        $tag_desc
    );

    if ($encrypted_description === false) {
        displayMessageAndRedirect("Encryption failed for problem description!", "detailed_problem.php", false);
        exit;
    }

    // Encrypt current medication
    $iv_medication = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
    $tag_medication = '';
    $encrypted_medication = openssl_encrypt(
        $current_medication,
        'aes-256-gcm',
        $encryption_key,
        0,
        $iv_medication,
        $tag_medication
    );

    // Encrypt and store video file locally if uploaded
    $video_path = null;
    $encrypted_video = null;
    $iv_video = null;
    $tag_video = null;

    if (isset($_FILES['video']) && $_FILES['video']['error'] === UPLOAD_ERR_OK) {
        if ($_FILES['video']['size'] > 200 * 1024 * 1024) {
            displayMessageAndRedirect("File size exceeds the 200 MB limit.", "detailed_problem.php", false);
            exit;
        }

        $video_tmp_path = $_FILES['video']['tmp_name'];
        $video_data = file_get_contents($video_tmp_path);

        $iv_video = random_bytes(openssl_cipher_iv_length('aes-256-gcm'));
        $tag_video = '';
        $encrypted_video = openssl_encrypt(
            $video_data,
            'aes-256-gcm',
            $encryption_key,
            0,
            $iv_video,
            $tag_video
        );

        if ($encrypted_video === false) {
            displayMessageAndRedirect("Encryption failed for video file!", "detailed_problem.php", false);
            exit;
        }

        // Save the encrypted video locally
        $video_storage_path = 'uploads/videos/';
        $video_filename = $video_storage_path . uniqid('video_', true) . '.enc';
        file_put_contents($video_filename, $encrypted_video);
        $video_path = $video_filename;
    }

    // Insert data into patient_history table
    $query = "INSERT INTO patient_history 
              (patient_id, doctor_id, hospital_id, problem, problem_description, problem_iv, problem_auth_tag, video_file, video_iv, video_auth_tag, current_medication, medication_iv, medication_auth_tag, status) 
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')";
    $stmt = $conn->prepare($query);

    $stmt->bind_param(
        'iiissssssssss',
        $patient_id,
        $doctor_id,
        $hospital_id,
        $problem_specialization,
        $encrypted_description,
        $iv_desc,
        $tag_desc,
        $video_path,
        $iv_video,
        $tag_video,
        $encrypted_medication,
        $iv_medication,
        $tag_medication
    );

    if ($stmt->execute()) {
        displayMessageAndRedirect("Problem submitted securely.", "patient_homepage.php", true);
    } else {
        displayMessageAndRedirect("Database error: " . $stmt->error, "detailed_problem.php", false);
    }

    $stmt->close();
}

// Function to display a message and redirect with a countdown
function displayMessageAndRedirect($message, $redirect_url, $success) {
    echo "
        <div style='display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center; font-family: Arial, sans-serif;'>
            <div>
                <h2>" . htmlspecialchars($message) . "</h2>
                <p>Redirecting in <span id='countdown'>3</span> seconds...</p>
            </div>
        </div>
        <script>
            let countdown = 3;
            const interval = setInterval(() => {
                countdown--;
                document.getElementById('countdown').textContent = countdown;
                if (countdown <= 0) {
                    clearInterval(interval);
                    window.location.href = '" . $redirect_url . "';
                }
            }, 1000);
        </script>
    ";
}
?>
