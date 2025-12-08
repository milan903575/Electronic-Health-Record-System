<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Completed Issues</title>
    <style>
 /* General Styles */
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
    overflow: hidden;
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

/* Form Styles */
form {
    background: #fff;
    padding: 20px;
    margin: 20px 0;
    border-radius: 5px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

form label {
    display: block;
    margin-bottom: 8px;
}

form input[type="text"],
form input[type="email"],
form input[type="password"],
form input[type="date"],
form select {
    width: 100%;
    padding: 10px;
    margin-bottom: 10px;
    border: 1px solid #ccc;
    border-radius: 5px;
}

form input[type="submit"] {
    background: #5cb85c;
    color: #fff;
    border: 0;
    padding: 10px 20px;
    cursor: pointer;
    border-radius: 5px;
}

form input[type="submit"]:hover {
    background: #4cae4c;
}

.form-group {
    margin-bottom: 15px;
}

.form-group label {
    font-weight: bold;
}

/* Error and Success Messages */
.error, .success {
    padding: 10px;
    margin-bottom: 20px;
    border-radius: 5px;
}

.error {
    background: #f2dede;
    color: #a94442;
}

.success {
    background: #dff0d8;
    color: #3c763d;
}

/* Table Styles */
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

/* Profile Styles */
.profile-header {
    background: #fff;
    padding: 20px;
    margin: 20px 0;
    border-radius: 5px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

.profile-header h2, .profile-header h3 {
    margin: 0;
    color: #333;
}

.profile-details {
    list-style: none;
    padding: 0;
}

.profile-details li {
    padding: 5px 0;
}

.profile-details li strong {
    display: inline-block;
    width: 150px;
}

/* Dashboard Styles */
.dashboard {
    background: #fff;
    padding: 20px;
    margin: 20px 0;
    border-radius: 5px;
    box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
}

.dashboard h2 {
    margin-top: 0;
}

/* Button Styles */
.button {
    background: #007bff;
    color: #fff;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
    text-decoration: none;
    display: inline-block;
}

.button:hover {
    background: #0056b3;
}

button {
    background: #007bff;
    color: #fff;
    padding: 10px 15px;
    border: none;
    border-radius: 5px;
    cursor: pointer;
}

button:hover {
    background: #0056b3;
}
</style>
</head>
<body>
    <h2>Completed Issues</h2>
    <a href="doctor_dashboard.php">Back to Dashboard</a>
    
    <table>
        <thead>
            <tr>
                <th>Patient Name</th>
                <th>Issue</th>
                <th>Solution</th>
                <th>Blood Group</th>
                <th>Age</th>
                <th>Date</th>
            </tr>
        </thead>
        <tbody>
            <?php
            include '../connection.php';

            $sql = "SELECT patients.first_name, patients.last_name, patients.blood_group, patients.date_of_birth, patient_history.problem, patient_history.doctor_solution, patient_history.date_submitted
                    FROM patient_history
                    JOIN patients ON patient_history.patient_id = patients.id
                    WHERE patient_history.status = 'completed'";
            $result = $conn->query($sql);

            if ($result->num_rows > 0) {
                while($row = $result->fetch_assoc()) {
                    $age = date_diff(date_create($row['date_of_birth']), date_create('today'))->y;
                    echo "<tr>";
                    echo "<td>" . htmlspecialchars($row['first_name'] . ' ' . $row['last_name']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['problem']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['doctor_solution']) . "</td>";
                    echo "<td>" . htmlspecialchars($row['blood_group']) . "</td>";
                    echo "<td>" . htmlspecialchars($age) . "</td>";
                    echo "<td>" . htmlspecialchars($row['date_submitted']) . "</td>";
                    echo "</tr>";
                }
            } else {
                echo "<tr><td colspan='6'>No completed issues found.</td></tr>";
            }

            $conn->close();
            ?>
        </tbody>
    </table>
</body>
</html>
