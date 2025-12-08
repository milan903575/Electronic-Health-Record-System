<?php
$conn = mysqli_connect(
    "sql100.infinityfree.com", // MySQL Host Name
    "if0_38023308",            // MySQL User Name
    "milan903575",             // MySQL Password
    "if0_38023308_ehr"         // MySQL DB Name
);

// Check connection
if (!$conn) {
    die("Connection failed: " . mysqli_connect_error());
}
?>
