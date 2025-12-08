<?php
// connection.php
include '../connection.php'
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ratings Information</title>
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
            padding: 20px;
            background: #fff;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
        }

        h1 {
            text-align: center;
            color: #333;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }

        .grid-item {
            background: #f9f9f9;
            padding: 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0, 0, 0, 0.1);
        }

        .grid-item p {
            margin: 8px 0;
            color: #555;
        }

        @media (max-width: 768px) {
            .grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Ratings Information</h1>
        <div class="grid">
            <?php
            $query = "SELECT 
                        r.rating_id, 
                        CONCAT(p.first_name, ' ', p.last_name) AS patient_name, 
                        CONCAT(d.first_name, ' ', d.last_name) AS doctor_name, 
                        r.rating, 
                        r.response_time, 
                        r.clarity, 
                        r.treatment_effectiveness, 
                        r.comment, 
                        r.created_at 
                      FROM ratings r
                      JOIN patients p ON r.patient_id = p.id
                      JOIN doctors d ON r.doctor_id = d.id";

            $result = mysqli_query($conn, $query);

            if (mysqli_num_rows($result) > 0) {
                while ($row = mysqli_fetch_assoc($result)) {
                    echo "
                        <div class='grid-item'>
                            <p><strong>Patient Name:</strong> {$row['patient_name']}</p>
                            <p><strong>Doctor Name:</strong> {$row['doctor_name']}</p>
                            <p><strong>Rating:</strong> {$row['rating']}</p>
                            <p><strong>Response Time:</strong> {$row['response_time']}</p>
                            <p><strong>Clarity:</strong> {$row['clarity']}</p>
                            <p><strong>Treatment Effectiveness:</strong> {$row['treatment_effectiveness']}</p>
                            <p><strong>Comment:</strong> {$row['comment']}</p>
                            <p><strong>Created At:</strong> {$row['created_at']}</p>
                        </div>
                    ";
                }
            } else {
                echo "<p>No ratings found.</p>";
            }

            mysqli_close($conn);
            ?>
        </div>
    </div>
</body>
</html>
