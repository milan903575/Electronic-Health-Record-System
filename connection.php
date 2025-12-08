<?php
$conn = mysqli_connect(
    "", // MySQL Host Name
    "", // MySQL User Name
    "", // MySQL Password
    ""  // MySQL DB Name
);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
