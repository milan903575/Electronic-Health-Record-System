<?php
include '../connection.php';

// Define the upload directory
$upload_dir = 'uploads/images/'; // Path to the folder where images will be uploaded

// Fetch and sanitize form inputs
$first_name = mysqli_real_escape_string($conn, $_POST['first_name']);
$last_name = mysqli_real_escape_string($conn, $_POST['last_name']);
$email = mysqli_real_escape_string($conn, $_POST['email']);
$hospital_id = intval($_POST['hospital_id']);
$date_of_birth = mysqli_real_escape_string($conn, $_POST['dob']);
$blood_group = mysqli_real_escape_string($conn, $_POST['blood_group']);
$location = mysqli_real_escape_string($conn, $_POST['location']);

// Handle profile picture upload (base64 image data)
$profile_picture_path = NULL;
if (!empty($_POST['profile_picture'])) {
    $base64_image = $_POST['profile_picture'];

    // Extract the base64 string and decode
    if (preg_match('/^data:image\/(jpeg|png);base64,/', $base64_image, $type)) {
        $base64_image = substr($base64_image, strpos($base64_image, ',') + 1);
        $base64_image = base64_decode($base64_image);
        // Generate a unique file name
        $file_extension = $type[1] === 'jpeg' ? 'jpg' : 'png';
        $unique_file_name = uniqid('profile_', true) . '.' . $file_extension;
        $profile_picture_path = $upload_dir . $unique_file_name;

        // Save the file
        if (!file_put_contents($profile_picture_path, $base64_image)) {
            echo '<script>alert("Failed to save the profile picture.");</script>';
            exit;
        }

        // Store only the relative path for database storage
        $profile_picture_path = 'uploads/images/' . $unique_file_name;
    } else {
        echo '<script>alert("Invalid image format. Only JPEG and PNG are allowed.");</script>';
        exit;
    }
}

// Calculate age based on the date of birth
$dob = new DateTime($date_of_birth);
$today = new DateTime();
$age = $today->diff($dob)->y;

// Check if email exists in the doctors table
$sql_check_doctor = "SELECT id FROM doctors WHERE email = ?";
$stmt_check_doctor = $conn->prepare($sql_check_doctor);
$stmt_check_doctor->bind_param("s", $email);
$stmt_check_doctor->execute();
$result_check_doctor = $stmt_check_doctor->get_result();

if ($result_check_doctor->num_rows > 0) {
    echo "<script>
        alert('This email is already registered as a doctor.');
        window.location.href = 'patient_registration.php';
    </script>";
    exit;
}

// Check if patient already exists by email
$sql_check_patient = "SELECT id FROM patients WHERE email = ?";
$stmt_check_patient = $conn->prepare($sql_check_patient);
$stmt_check_patient->bind_param("s", $email);
$stmt_check_patient->execute();
$result_check_patient = $stmt_check_patient->get_result();

if ($result_check_patient->num_rows > 0) {
    // Existing patient logic
    $patient = $result_check_patient->fetch_assoc();
    $patient_id = $patient['id'];

    // Check if patient is already registered with this hospital
    $sql_check_hospital = "SELECT * FROM patient_hospital WHERE patient_id = ? AND hospital_id = ?";
    $stmt_check_hospital = $conn->prepare($sql_check_hospital);
    $stmt_check_hospital->bind_param("ii", $patient_id, $hospital_id);
    $stmt_check_hospital->execute();
    $result_check_hospital = $stmt_check_hospital->get_result();

    if ($result_check_hospital->num_rows > 0) {
        echo "
        <div class='message-container'>
            <p>This patient is already registered with this hospital. Please log in.</p>
            <p>You will be redirected in <span id='countdown'>4</span> seconds...</p>
        </div>
        <script>
            let countdown = 4;
            const interval = setInterval(() => {
                countdown--;
                document.getElementById('countdown').textContent = countdown;
                if (countdown === 0) {
                    clearInterval(interval);
                    window.location.href = '../login.php';
                }
            }, 1000);
        </script>";
    } else {
        // Fetch the registration fee from the hospital table
        $sql_get_fee = "SELECT registration_fee FROM hospitals WHERE id = ?";
        $stmt_get_fee = $conn->prepare($sql_get_fee);
        $stmt_get_fee->bind_param("i", $hospital_id);
        $stmt_get_fee->execute();
        $result_fee = $stmt_get_fee->get_result();
        $hospital = $result_fee->fetch_assoc();
        $registration_fee = $hospital['registration_fee'];

        // Determine the registration status based on the fee
        $registration_status = ($registration_fee == 0) ? 'Completed' : 'Pending';

        // Register the patient with the new hospital, including date_registered
        $sql_register_hospital = "INSERT INTO patient_hospital (patient_id, hospital_id, registration_status, date_registered) VALUES (?, ?, ?, NOW())";
        $stmt_register_hospital = $conn->prepare($sql_register_hospital);
        $stmt_register_hospital->bind_param("iis", $patient_id, $hospital_id, $registration_status);
        $stmt_register_hospital->execute();

        echo "
        <div class='message-container'>
            <p>Patient registered with new hospital successfully.</p>
            <p>You will be redirected in <span id='countdown'>5</span> seconds...</p>
        </div>
        <script>
            let countdown = 5;
            const interval = setInterval(() => {
                countdown--;
                document.getElementById('countdown').textContent = countdown;
                if (countdown === 0) {
                    clearInterval(interval);
                    window.location.href = '../login.php';
                }
            }, 1000);
        </script>";
    }
} else {
    // New patient registration logic
    $password = password_hash($_POST['password'], PASSWORD_BCRYPT);
    $sql_create_patient = "INSERT INTO patients (first_name, last_name, email, password, date_of_birth, blood_group, age, profile_picture, location) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
    $stmt_create_patient = $conn->prepare($sql_create_patient);
    $stmt_create_patient->bind_param("sssssssss", $first_name, $last_name, $email, $password, $date_of_birth, $blood_group, $age, $profile_picture_path, $location);
    $stmt_create_patient->execute();
    $patient_id = $stmt_create_patient->insert_id;

    // Fetch the registration fee from the hospital table
    $sql_get_fee = "SELECT registration_fee FROM hospitals WHERE id = ?";
    $stmt_get_fee = $conn->prepare($sql_get_fee);
    $stmt_get_fee->bind_param("i", $hospital_id);
    $stmt_get_fee->execute();
    $result_fee = $stmt_get_fee->get_result();
    $hospital = $result_fee->fetch_assoc();
    $registration_fee = $hospital['registration_fee'];

    // Determine the registration status based on the fee
    $registration_status = ($registration_fee == 0) ? 'Completed' : 'Pending';

    // Register the patient with the hospital, including date_registered
    $sql_register_hospital = "INSERT INTO patient_hospital (patient_id, hospital_id, registration_status, date_registered) VALUES (?, ?, ?, NOW())";
    $stmt_register_hospital = $conn->prepare($sql_register_hospital);
    $stmt_register_hospital->bind_param("iis", $patient_id, $hospital_id, $registration_status);
    $stmt_register_hospital->execute();

    echo "
    <div class='message-container'>
        <p>New patient registered successfully.</p>
        <p>You will be redirected in <span id='countdown'>3</span> seconds...</p>
    </div>
    <script>
        let countdown = 3;
        const interval = setInterval(() => {
            countdown--;
            document.getElementById('countdown').textContent = countdown;
            if (countdown === 0) {
                clearInterval(interval);
                window.location.href = '../login.php';
            }
        }, 1000);
    </script>";
}

$conn->close();
?>

<style>
/* Centered and styled message container */
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
