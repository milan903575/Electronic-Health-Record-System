<?php
include '../connection.php';

// Determine the sorting order based on the query parameter
$order_by = isset($_GET['order_by']) && $_GET['order_by'] === 'oldest' ? 'ASC' : 'DESC';

// Query to fetch patient data with dynamic sorting
$query = "
    SELECT patients.first_name, patients.last_name, 
           patients.created_at, patient_history.status, patient_history.problem 
    FROM patients 
    JOIN patient_history ON patients.id = patient_history.patient_id 
    WHERE patient_history.status = 'pending'
    ORDER BY patients.created_at $order_by
";

$result = mysqli_query($conn, $query);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Patient List</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 0;
            background-color: #f4f4f9;
        }
        .container {
            max-width: 1200px;
            margin: 20px auto;
            padding: 0 20px;
        }
        .header {
            text-align: center;
            margin-bottom: 20px;
        }
        .filter-container {
            margin-bottom: 20px;
            display: flex;
            justify-content: flex-end;
        }
        .filter-container a {
            text-decoration: none;
            color: #007bff;
            font-size: 14px;
            margin-left: 10px;
            font-weight: bold;
        }
        .filter-container a:hover {
            text-decoration: underline;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .card {
            background-color: #ffffff;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            transition: transform 0.2s, box-shadow 0.2s;
            cursor: pointer;
        }
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 8px 12px rgba(0, 0, 0, 0.15);
        }
        .details {
            font-size: 14px;
            color: #555;
            margin-bottom: 10px;
        }
        .status {
            font-size: 14px;
            font-weight: bold;
            color: #1abc9c;
        }
        .date {
            font-size: 14px;
            color: #888;
            margin-top: 10px;
            font-style: italic;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h3>Patient List</h3>
        </div>
        <div class="filter-container">
            <span>Sort by:</span>
            <a href="?order_by=recent">Recent</a>
            <a href="?order_by=oldest">Oldest</a>
        </div>
        <div class="grid">
            <?php while ($row = mysqli_fetch_assoc($result)): ?>
                <?php
                // Sanitize the data before displaying
                $first_name = htmlspecialchars($row['first_name']);
                $last_name = htmlspecialchars($row['last_name']);
                $problem = htmlspecialchars($row['problem']);
                $created_at = htmlspecialchars($row['created_at']);
                $status = htmlspecialchars($row['status']);
                ?>
                <div class="card">
                    <div class="details"><strong>First Name:</strong> <?= $first_name ?></div>
                    <div class="details"><strong>Last Name:</strong> <?= $last_name ?></div>
                    <div class="details"><strong>Problem:</strong> <?= $problem ?></div>
                    <div class="date"><strong>Created At:</strong> <?= $created_at ?></div>
                    <div class="status">Status: <?= $status ?></div>
                </div>
            <?php endwhile; ?>
        </div>
    </div>
</body>
</html>
