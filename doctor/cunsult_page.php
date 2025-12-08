<?php
include '../connection.php';
session_start();

// Enable error reporting for debugging during development
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Check if the doctor is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.html");
    exit;
}

$doctor_id = $_SESSION['user_id'];

// Retrieve the encryption key securely
$key_path = 'C:/secure_keys/encryption_key.key';
$encryption_key = trim(file_get_contents($key_path));

if (!$encryption_key) {
    die("Error: Encryption key is missing!");
}

// Helper function for decryption
function decrypt_data($data, $iv, $auth_tag, $encryption_key)
{
    return openssl_decrypt($data, 'aes-256-gcm', $encryption_key, 0, $iv, $auth_tag);
}

// Fetch patient consultations dynamically
$sql = "SELECT 
            pp.patient_id, 
            p.first_name, 
            p.last_name, 
            pp.problem_description, 
            pp.iv, 
            pp.auth_tag, 
            pp.status, 
            pp.created_at 
        FROM private_problems pp
        INNER JOIN patients p ON pp.patient_id = p.id
        WHERE pp.doctor_id = ? AND (pp.status = 'completed' OR pp.status = 'pending')
        ORDER BY pp.created_at DESC";

$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $doctor_id);
$stmt->execute();
$result = $stmt->get_result();
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Dashboard - Patient List</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f9f9f9;
        }
        .header {
            background-color: #4CAF50;
            color: white;
            padding: 1rem;
            text-align: center;
        }
        .container {
            margin: 20px auto;
            width: 90%;
            max-width: 1000px;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        table th, table td {
            border: 1px solid #ddd;
            padding: 10px;
            text-align: center;
        }
        table th {
            background-color: #4CAF50;
            color: white;
        }
        .description-cell {
            text-align: left;
            max-width: 400px;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Doctor's Dashboard</h1>
        <p>List of Patient Consultations</p>
    </div>
    <div class="container">
        <table>
            <thead>
                <tr>
                    <th>Patient ID</th>
                    <th>Patient Name</th>
                    <th>Consultation Date</th>
                    <th>Problem Description</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($result->num_rows > 0): ?>
                    <?php while ($row = $result->fetch_assoc()): ?>
                        <?php
                        $decrypted_description = decrypt_data(
                            $row['problem_description'], 
                            $row['iv'], 
                            $row['auth_tag'], 
                            $encryption_key
                        );
                        ?>
                        <tr>
                            <td><?= htmlspecialchars($row['patient_id']) ?></td>
                            <td><?= htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) ?></td>
                            <td><?= htmlspecialchars(date('Y-m-d', strtotime($row['created_at']))) ?></td>
                            <td class="description-cell"><?= htmlspecialchars($decrypted_description) ?></td>
                            <td><?= htmlspecialchars(ucfirst($row['status'])) ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="5">No consultations found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>

<?php
// Close statement and connection
$stmt->close();
$conn->close();
?>
