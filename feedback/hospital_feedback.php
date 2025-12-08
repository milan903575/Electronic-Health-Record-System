<?php
include '../connection.php'; // Include your database connection file

if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $patient_id = 1; // Replace with session variable or actual logged-in patient ID
    $hospital_id = $_POST['hospital_id'];
    $rating = $_POST['rating'];
    $response_time = $_POST['response_time'];
    $comment = $_POST['comment'];

    // Prepare the SQL query to insert feedback into the ratings table
    $query = "INSERT INTO ratings (patient_id, hospital_id, type, rating, response_time, comment) 
              VALUES (?, ?, 'hospital', ?, ?, ?)";
    $stmt = $conn->prepare($query);
    $stmt->bind_param("iiiss", $patient_id, $hospital_id, $rating, $response_time, $comment);

    // Execute the query and handle success or error
    if ($stmt->execute()) {
        echo "<div class='alert alert-success'>Feedback submitted successfully!</div>";
    } else {
        echo "<div class='alert alert-danger'>Error: " . $stmt->error . "</div>";
    }

    $stmt->close();
}

// Display the feedback form
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hospital Feedback</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css">
</head>
<body>
    <div class="container mt-5">
        <h2>Hospital Feedback Form</h2>
        <form action="hospital_feedback.php" method="POST">
            <div class="form-group">
                <label for="rating">Rate Hospital:</label>
                <select class="form-control" id="rating" name="rating" required>
                    <option value="">Select Rating</option>
                    <option value="1">1 - Very Bad</option>
                    <option value="2">2 - Average</option>
                    <option value="3">3 - Good</option>
                    <option value="4">4 - Very Good</option>
                    <option value="5">5 - Excellent</option>
                </select>
            </div>
            <div class="form-group">
                <label for="response_time">Response Time:</label>
                <select class="form-control" id="response_time" name="response_time" required>
                    <option value="">Select Response Time</option>
                    <option value="in 1 day">In 1 day</option>
                    <option value="more than 1 day">More than 1 day</option>
                    <option value="< week">Less than a week</option>
                    <option value="> week">More than a week</option>
                </select>
            </div>
            <div class="form-group">
                <label for="comment">Comment:</label>
                <textarea class="form-control" id="comment" name="comment" rows="3" placeholder="Example: Very good hospital and doctors." required></textarea>
            </div>
            <input type="hidden" name="hospital_id" value="1"> <!-- Set dynamically if needed -->
            <button type="submit" class="btn btn-primary">Submit Feedback</button>
        </form>
    </div>
</body>
</html>
