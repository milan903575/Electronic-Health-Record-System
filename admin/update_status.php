<?php
include '../connection.php';

$type = $_POST['type'];
$id = $_POST['id'];
$status = $_POST['status'];

$table = $type === 'doctor' ? 'doctors' : 'receptionist';
$column = $type === 'doctor' ? 'registration_status' : 'status';

$query = "UPDATE $table SET $column = '$status' WHERE id = $id";
if (mysqli_query($conn, $query)) {
    echo "Status updated successfully!";
} else {
    echo "Error updating status: " . mysqli_error($conn);
}
?>