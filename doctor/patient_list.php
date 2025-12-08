<?php
session_start();
include '../connection.php';

// Check if doctor is logged in
if (!isset($_SESSION['doctor_id'])) {
    die("Unauthorized access. Please log in.");
}
$doctor_id = $_SESSION['doctor_id'];
$filter_date = isset($_GET['filter_date']) ? $_GET['filter_date'] : '';
$filter_count = isset($_GET['filter_count']) ? (int)$_GET['filter_count'] : 10;

// Capture the 'id' from the URL (passed in the query string)
$url_patient_id = isset($_GET['id']) ? (int)$_GET['id'] : null;

// Query to fetch patient history
$sql = "
    SELECT 
        p.id,
        p.first_name, 
        ph.date_submitted, 
        ph.problem, 
        ph.problem_description
    FROM 
        patients p
    INNER JOIN 
        patient_history ph
    ON 
        p.id = ph.patient_id
    WHERE 
        ph.status = 'completed' AND ph.doctor_id = ?
";
if (!empty($filter_date)) {
    $sql .= " AND DATE(ph.date_submitted) = ?";
}
$sql .= " ORDER BY ph.date_submitted DESC LIMIT ?";

$stmt = $conn->prepare($sql);
if (!empty($filter_date)) {
    $stmt->bind_param("isi", $doctor_id, $filter_date, $filter_count);
} else {
    $stmt->bind_param("ii", $doctor_id, $filter_count);
}
$stmt->execute();
$result = $stmt->get_result();

// Reset the pointer for rendering the table
$result->data_seek(0);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient History</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .go-back {
            margin-bottom: 20px;
            display: inline-block;
            padding: 10px 20px;
            background-color: #007bff;
            color: #fff;
            text-decoration: none;
            border-radius: 5px;
        }
        .go-back:hover {
            background-color: #0056b3;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            border-radius: 8px;
            overflow: hidden;
        }
        table th, table td {
            text-align: left;
            padding: 15px;
            border: 1px solid #ddd;
            font-size: 0.9rem;
        }
        table th {
            background: #28a745;
            color: #fff;
        }
        table tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .filter-form {
            margin-bottom: 20px;
        }
        .filter-form label, .filter-form input, .filter-form select, .filter-form button {
            margin-right: 10px;
            font-size: 1rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Go Back Button -->
        <?php if ($url_patient_id): ?>
            <a href="edit_issue.php?id=<?= $url_patient_id; ?>" class="go-back">Go Back</a>
        <?php else: ?>
            <a href="#" class="go-back" onclick="alert('No patients available.'); return false;">Go Back</a>
        <?php endif; ?>

        <!-- Filter Form -->
        <form method="GET" class="filter-form">
            <label for="filter_date">Select Date:</label>
            <input type="date" id="filter_date" name="filter_date" value="<?= htmlspecialchars($filter_date); ?>">

            <label for="filter_count">Recent Records:</label>
            <select id="filter_count" name="filter_count">
                <?php foreach ([1, 2, 4, 10, 20] as $count): ?>
                    <option value="<?= $count; ?>" <?= $filter_count == $count ? 'selected' : ''; ?>>
                        <?= $count; ?>
                    </option>
                <?php endforeach; ?>
            </select>

            <button type="submit">Apply Filter</button>
        </form>

        <!-- Patient History Table -->
        <table>
            <thead>
                <tr>
                    <th>First Name</th>
                    <th>Created At</th>
                    <th>Problem</th>
                    <th>Problem Description</th>
                </tr>
            </thead>
            <tbody>
                <?php if ($result->num_rows > 0): ?>
                    <?php while ($row = $result->fetch_assoc()): ?>
                        <tr>
                            <td><?= htmlspecialchars($row['first_name']); ?></td>
                            <td><?= htmlspecialchars($row['date_submitted']); ?></td>
                            <td><?= htmlspecialchars($row['problem']); ?></td>
                            <td><?= htmlspecialchars($row['problem_description']); ?></td>
                        </tr>
                    <?php endwhile; ?>
                <?php else: ?>
                    <tr>
                        <td colspan="4">No records found.</td>
                    </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
