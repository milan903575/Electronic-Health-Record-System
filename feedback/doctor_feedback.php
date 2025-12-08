<?php
include '../connection.php'; // Include your database connection file
session_start();
// Check if 'doctor_id' is passed in the URL
if (!isset($_GET['doctor_id']) || !filter_var($_GET['doctor_id'], FILTER_VALIDATE_INT)) {
    die("Invalid doctor ID.");
}

$doctor_id = intval($_GET['doctor_id']);

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    // Validate form inputs
    $patient_id = $_SESSION['user_id']; // Replace with actual logged-in patient ID
    $rating = $_POST['rating'];
    $response_time = $_POST['response_time'];
    $clarity = $_POST['clarity'];
    $treatment_effectiveness = $_POST['treatment_effectiveness'];
    $comment = $_POST['comment'];

    // Insert feedback into the ratings table
    $query = "INSERT INTO ratings (patient_id, doctor_id, type, rating, response_time, clarity, treatment_effectiveness, comment) 
              VALUES (?, ?, 'doctor', ?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("iiissss", $patient_id, $doctor_id, $rating, $response_time, $clarity, $treatment_effectiveness, $comment);

    if ($stmt->execute()) {
        echo "<div class='alert alert-success'>Thank you for your feedback!</div>";
    } else {
        echo "<div class='alert alert-danger'>Error: " . $stmt->error . "</div>";
    }

    $stmt->close();
}

// Fetch doctor's first and last name from the database
$query = "SELECT first_name, last_name FROM doctors WHERE id = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("i", $doctor_id);
$stmt->execute();
$stmt->bind_result($first_name, $last_name);
$stmt->fetch();
$stmt->close();

if (!$first_name || !$last_name) {
    die("Doctor not found.");
}

$doctor_name = $first_name . ' ' . $last_name;
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Feedback for Dr. <?= htmlspecialchars($doctor_name) ?></title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
    <style>
        body {
            background-color: #f8f9fa;
        }
        .container {
            max-width: 700px;
            margin: 50px auto;
            background: #ffffff;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0px 4px 12px rgba(0, 0, 0, 0.2);
        }
        h2 {
            text-align: center;
            color: #007bff;
            margin-bottom: 20px;
        }
        .form-group label {
            font-weight: bold;
        }
        .btn-primary {
            background-color: #007bff;
            border: none;
        }
        .btn-primary:hover {
            background-color: #0056b3;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>Feedback for Dr. <?= htmlspecialchars($doctor_name) ?></h2>
        <form action="doctor_feedback.php?doctor_id=<?= htmlspecialchars($doctor_id) ?>" method="POST">
            <div class="form-group">
                <label for="rating">Rate Your Overall Experience:</label>
                <select class="form-control" id="rating" name="rating" required>
                    <option value="">Select Rating</option>
                    <option value="1">1 - Very Bad</option>
                    <option value="2">2 - Below Average</option>
                    <option value="3">3 - Average</option>
                    <option value="4">4 - Good</option>
                    <option value="5">5 - Excellent</option>
                </select>
            </div>
            <div class="form-group">
                <label for="response_time">How Would You Rate the Response Time?</label>
                <select class="form-control" id="response_time" name="response_time" required>
                    <option value="">Select Response Time</option>
                    <option value="Very Fast">Very Fast (within a few hours)</option>
                    <option value="Fast">Fast (within a day)</option>
                    <option value="Moderate">Moderate (within 2-3 days)</option>
                    <option value="Slow">Slow (more than 3 days)</option>
                </select>
            </div>
            <div class="form-group">
                <label for="clarity">Did the Doctor Explain Things Clearly?</label>
                <select class="form-control" id="clarity" name="clarity" required>
                    <option value="">Select Option</option>
                    <option value="Very Clear">Very Clear</option>
                    <option value="Clear">Clear</option>
                    <option value="Moderate">Moderately Clear</option>
                    <option value="Unclear">Unclear</option>
                </select>
            </div>
            <div class="form-group">
                <label for="treatment_effectiveness">How Effective Was the Treatment?</label>
                <select class="form-control" id="treatment_effectiveness" name="treatment_effectiveness" required>
                    <option value="">Select Effectiveness</option>
                    <option value="Very Effective">Very Effective</option>
                    <option value="Effective">Effective</option>
                    <option value="Somewhat Effective">Somewhat Effective</option>
                    <option value="Ineffective">Ineffective</option>
                </select>
            </div>
            <div class="form-group">
                <label for="comment">Additional Feedback:</label>
                <textarea class="form-control" id="comment" name="comment" rows="4" placeholder="Share your thoughts..." required></textarea>
            </div>
            <button type="submit" class="btn btn-primary btn-block">Submit Feedback</button>
        </form>
    </div>
</body>
</html>
