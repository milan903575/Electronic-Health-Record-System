<?php
// Include connection
include '../connection.php';

// Start session if not already started
if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// Check if the user is logged in
if (!isset($_SESSION['user_id'])) {
    header("Location: ../login.html");
    exit();
}

// Get the logged-in doctor's ID
$doctor_id = $_SESSION['user_id'];

// Fetch the doctor's hospital_id
$doctor_hospital_query = "SELECT hospital_id FROM doctors WHERE id = ?";
$stmt_doctor = $conn->prepare($doctor_hospital_query);
$stmt_doctor->bind_param("i", $doctor_id);
$stmt_doctor->execute();
$result_doctor = $stmt_doctor->get_result();
$doctor_hospital_id = $result_doctor->fetch_assoc()['hospital_id'];
$stmt_doctor->close();

if (!$doctor_hospital_id) {
    die("Error: Hospital ID not found for the doctor.");
}

// Fetch pending issues
$pending_query = "SELECT pp.id, pp.problem_description, pp.created_at, 
                         p.first_name, p.last_name, p.blood_group, 
                         TIMESTAMPDIFF(YEAR, p.date_of_birth, CURDATE()) AS age, 
                         h.hospital_name
                  FROM private_problems pp
                  JOIN patients p ON pp.patient_id = p.id
                  JOIN patient_hospital ph ON p.id = ph.patient_id
                  JOIN hospitals h ON ph.hospital_id = h.id
                  WHERE pp.status = 'pending' 
                    AND pp.doctor_id = ? 
                    AND h.id = ?";
$stmt_pending = $conn->prepare($pending_query);
$stmt_pending->bind_param("ii", $doctor_id, $doctor_hospital_id);
$stmt_pending->execute();
$pending_result = $stmt_pending->get_result();
$stmt_pending->close();

// Fetch completed issues if requested
$completed_result = null;
if (isset($_GET['show_completed'])) {
    $completed_query = "SELECT pp.id, pp.problem_description, pp.created_at, 
                               p.first_name, p.last_name, p.blood_group, 
                               TIMESTAMPDIFF(YEAR, p.date_of_birth, CURDATE()) AS age, 
                               h.hospital_name
                        FROM private_problems pp
                        JOIN patients p ON pp.patient_id = p.id
                        JOIN patient_hospital ph ON p.id = ph.patient_id
                        JOIN hospitals h ON ph.hospital_id = h.id
                        WHERE pp.status = 'completed' 
                          AND pp.doctor_id = ? 
                          AND h.id = ?";
    $stmt_completed = $conn->prepare($completed_query);
    $stmt_completed->bind_param("ii", $doctor_id, $doctor_hospital_id);
    $stmt_completed->execute();
    $completed_result = $stmt_completed->get_result();
    $stmt_completed->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Doctor Dashboard</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f4f4f4;
            margin: 0;
            padding: 0;
        }
        .container {
            width: 90%;
            max-width: 1200px;
            margin: auto;
        }
        header {
            background: #333;
            color: #fff;
            padding: 10px 0;
            text-align: center;
        }
        header h1 {
            margin: 0;
        }
        table {
            width: 100%;
            margin: 20px 0;
            border-collapse: collapse;
        }
        table th, table td {
            padding: 10px;
            border: 1px solid #ddd;
            text-align: left;
        }
        table th {
            background: #333;
            color: #fff;
        }
        table tr:nth-child(even) {
            background: #f2f2f2;
        }
        .button {
            background: #007bff;
            color: #fff;
            padding: 10px 15px;
            border: none;
            border-radius: 5px;
            cursor: pointer;
            text-decoration: none;
        }
        .button:hover {
            background: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Doctor Dashboard</h1>
        </header>

        <h2>Pending Issues</h2>
        <table>
            <thead>
                <tr>
                    <th>Patient Name</th>
                    <th>Blood Group</th>
                    <th>Age</th>
                    <th>Date Submitted</th>
                    <th>Hospital</th>
                    <th>Action</th>
                </tr>
            </thead>
            <tbody>
                <?php while ($row = mysqli_fetch_assoc($pending_result)): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($row['first_name'] . ' ' . $row['last_name']); ?></td>
                        <td><?php echo htmlspecialchars($row['blood_group']); ?></td>
                        <td><?php echo htmlspecialchars($row['age']); ?></td>
                        <td><?php echo htmlspecialchars($row['created_at']); ?></td>
                        <td><?php echo htmlspecialchars($row['hospital_name']); ?></td>
                        <td><a href="edit_private_issue.php?id=<?php echo $row['id']; ?>" class="button">Provide Solution</a></td>
                    </tr>
                <?php endwhile; ?>
            </tbody>
        </table>

            <button type="submit" name="show_completed" class="button">Show Completed Cases</button>


        <?php if ($completed_result): ?>
            <h2>Completed Issues</h2>
            <table>
                <thead>
                    <tr>
                        <th>Patient Name</th>
                        <th>Blood Group</th>
                        <th>Age</th>
                        <th>Date Submitted</th>
                        <th>Hospital</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php while ($row = mysqli_fetch_assoc($completed_result)): ?>
                        <tr>
                            <td><?php echo htmlspecialchars($row['first_name'] . ' ' . $row['last_name']); ?></td>
                            <td><?php echo htmlspecialchars($row['blood_group']); ?></td>
                            <td><?php echo htmlspecialchars($row['age']); ?></td>
                            <td><?php echo htmlspecialchars($row['created_at']); ?></td>
                            <td><?php echo htmlspecialchars($row['hospital_name']); ?></td>
                            <td><a href="view_solution.php?id=<?php echo $row['id']; ?>" class="button">View Solution</a></td>
                        </tr>
                    <?php endwhile; ?>
                </tbody>
            </table>
        <?php endif; ?>
    </div>
</body>
</html>
