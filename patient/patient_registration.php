<?php
include '../connection.php';

// Handle email check AJAX request
if (isset($_POST['email_check'])) {
    $email = $_POST['email_check'];
    
    // Check in doctors table first
    $stmt_doctors = $conn->prepare("SELECT id FROM doctors WHERE email = ?");
    $stmt_doctors->bind_param("s", $email);
    $stmt_doctors->execute();
    $result_doctors = $stmt_doctors->get_result();
    
    // Check in receptionist table
    $stmt_receptionist = $conn->prepare("SELECT id FROM receptionist WHERE email = ?");
    $stmt_receptionist->bind_param("s", $email);
    $stmt_receptionist->execute();
    $result_receptionist = $stmt_receptionist->get_result();
    
    // Check in patients table
    $stmt_patients = $conn->prepare("SELECT id FROM patients WHERE email = ?");
    $stmt_patients->bind_param("s", $email);
    $stmt_patients->execute();
    $result_patients = $stmt_patients->get_result();
    
    // Return specific messages based on which table contains the email
    if ($result_doctors->num_rows > 0) {
        echo "doctor_exists";
    } elseif ($result_receptionist->num_rows > 0) {
        echo "receptionist_exists";
    } elseif ($result_patients->num_rows > 0) {
        echo "patient_exists";
    } else {
        echo "not_exists";
    }
    
    // Close statements
    $stmt_doctors->close();
    $stmt_receptionist->close();
    $stmt_patients->close();
    
    exit;
}

// Handle hospital search AJAX request
if (isset($_GET['query'])) {
    $query = $_GET['query'];
    $sql = "SELECT id, hospital_name FROM hospitals WHERE hospital_name LIKE ? OR zipcode LIKE ?";
    $stmt = $conn->prepare($sql);
    $search_query = "%" . $query . "%";
    $stmt->bind_param("ss", $search_query, $search_query);
    $stmt->execute();
    $result = $stmt->get_result();

    $output = '';
    while ($row = $result->fetch_assoc()) {
        $output .= '<div class="hospital-option" data-id="' . $row['id'] . '">' . htmlspecialchars($row['hospital_name']) . '</div>';
    }

    echo $output;
    $stmt->close();
    $conn->close();
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patient Registration</title>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-validator/0.5.3/css/bootstrapValidator.min.css">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.3/css/all.min.css">
    <style>
        body {
            background-color: #f5f7fa;
            font-family: 'Roboto', sans-serif;
            color: #2c3e50;
            line-height: 1.6;
            margin: 0;
            padding: 0;
            min-height: 100vh;
        }

        .container {
            max-width: 800px;
            margin: 40px auto;
            padding: 0 15px;
            animation: fadeIn 0.8s ease-out;
        }

        .well {
            background-color: #fff;
            box-shadow: 0 15px 35px rgba(50, 50, 93, 0.1), 0 5px 15px rgba(0, 0, 0, 0.07);
            padding: 35px 40px;
            border-radius: 16px;
            border: none;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }

        .well::before {
            content: "";
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 5px;
            background: linear-gradient(90deg, #3498db, #2ecc71);
        }

        legend {
            color: #2c3e50;
            font-weight: 700;
            font-size: 26px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 12px;
            margin-bottom: 30px;
            width: 100%;
            position: relative;
        }

        .form-group {
            margin-bottom: 25px;
            position: relative;
            transition: all 0.3s ease;
            display: flex;
            flex-wrap: wrap;
        }

        .form-group:hover {
            transform: translateX(3px);
        }

        label.control-label {
            font-weight: 600;
            color: #34495e;
            margin-bottom: 10px;
            font-size: 15px;
            display: block;
            transition: color 0.3s;
        }

        .form-group:hover label {
            color: #3498db;
        }

        .col-md-4 {
            width: 33.33%;
            float: left;
            padding-right: 15px;
        }

        .col-md-8 {
            width: 66.67%;
            float: left;
        }

        .inputGroupContainer {
            width: 100%;
        }

        .form-control {
            height: 48px;
            border-radius: 8px;
            border: 1px solid #e0e6ed;
            box-shadow: none;
            transition: all 0.3s;
            padding: 10px 15px;
            font-size: 15px;
            background-color: #f9fafc;
            width: 100%;
        }

        .form-control:focus {
            border-color: #3498db;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.2);
            outline: none;
            background-color: #fff;
        }

        .input-group-addon {
            background-color: #3498db;
            color: white;
            border: none;
            border-radius: 8px 0 0 8px;
            width: 45px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background-color 0.3s;
        }

        .form-group:hover .input-group-addon {
            background-color: #2980b9;
        }

        .input-group {
            margin-bottom: 0;
            display: flex;
            box-shadow: 0 4px 6px rgba(50, 50, 93, 0.05);
            border-radius: 8px;
            width: 100%;
        }

        .radio {
            margin-top: 12px;
            display: inline-block;
            margin-right: 15px;
        }

        .radio label {
            margin-right: 20px;
            cursor: pointer;
            display: inline-flex;
            align-items: center;
            font-weight: normal;
            padding: 5px 10px;
            border-radius: 20px;
            transition: all 0.3s;
        }

        .radio label:hover {
            background-color: rgba(52, 152, 219, 0.1);
        }

        .radio input[type="radio"] {
            margin-right: 8px;
            transform: scale(1.2);
            accent-color: #3498db;
        }

        .btn {
            font-size: 16px;
            letter-spacing: 0.5px;
            border-radius: 8px;
            transition: all 0.3s;
            position: relative;
            overflow: hidden;
            z-index: 1;
        }

        .btn-primary {
            background-color: #3498db;
            border-color: #3498db;
            padding: 12px 24px;
            font-weight: 600;
            box-shadow: 0 4px 6px rgba(52, 152, 219, 0.2);
        }

        .btn-primary:hover {
            background-color: #2980b9;
            border-color: #2980b9;
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(52, 152, 219, 0.3);
        }

        .btn-secondary {
            background-color: #95a5a6;
            border-color: #95a5a6;
            padding: 12px 24px;
            font-weight: 600;
            box-shadow: 0 4px 6px rgba(149, 165, 166, 0.2);
            color: white;
            margin-left: 10px;
        }

        .btn-secondary:hover {
            background-color: #7f8c8d;
            border-color: #7f8c8d;
            transform: translateY(-2px);
            box-shadow: 0 7px 14px rgba(149, 165, 166, 0.3);
            color: white;
        }

        #capture-btn {
            margin-top: 15px;
            background-color: #2ecc71;
            border-color: #2ecc71;
            box-shadow: 0 4px 6px rgba(46, 204, 113, 0.2);
        }

        #retake-btn {
            margin-top: 15px;
            background-color: #e74c3c;
            border-color: #e74c3c;
            box-shadow: 0 4px 6px rgba(231, 76, 60, 0.2);
            display: none;
        }

        #upload-btn {
            margin-top: 15px;
            background-color: #f39c12;
            border-color: #f39c12;
            box-shadow: 0 4px 6px rgba(243, 156, 18, 0.2);
        }

        #request-camera-btn {
            background-color: #9b59b6;
            border-color: #9b59b6;
            padding: 10px 15px;
            font-size: 14px;
            box-shadow: 0 4px 6px rgba(155, 89, 182, 0.2);
        }

        #camera-container {
            background-color: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            margin-top: 15px;
            box-shadow: inset 0 2px 5px rgba(0, 0, 0, 0.05);
            transition: all 0.3s;
        }

        #video-container {
            border: 2px dashed #bdc3c7;
            padding: 20px;
            border-radius: 10px;
            background-color: #ecf0f1;
            text-align: center;
            transition: all 0.3s;
            margin-bottom: 15px;
        }

        #image-preview {
            display: none;
            max-width: 320px;
            border-radius: 10px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
            margin: 0 auto 15px;
        }

        video, canvas {
            width: 100%;
            max-width: 320px;
            border-radius: 10px;
            box-shadow: 0 6px 12px rgba(0, 0, 0, 0.1);
            transition: all 0.3s;
        }

        #hospitallist, #locationlist {
            position: absolute;
            background: white;
            border: 1px solid #e0e0e0;
            border-radius: 0 0 10px 10px;
            width: calc(100% - 20px);
            max-height: 200px;
            overflow-y: auto;
            z-index: 1000;
            box-shadow: 0 10px 20px rgba(0, 0, 0, 0.1);
        }

        .hospital-option, .location-option {
            padding: 14px 18px;
            cursor: pointer;
            border-bottom: 1px solid #f0f0f0;
            transition: all 0.2s;
        }

        .hospital-option:hover, .location-option:hover {
            background: #f0f7ff;
            padding-left: 22px;
        }

        .text-danger {
            color: #e74c3c;
            font-size: 14px;
            margin-top: 6px;
            display: block;
            animation: fadeIn 0.3s ease-out;
        }

        .photo-options {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 15px;
        }

        .file-upload {
            position: relative;
            overflow: hidden;
            margin-top: 15px;
            display: none;
        }

        .file-upload input[type=file] {
            position: absolute;
            top: 0;
            right: 0;
            min-width: 100%;
            min-height: 100%;
            font-size: 100px;
            text-align: right;
            filter: alpha(opacity=0);
            opacity: 0;
            outline: none;
            cursor: pointer;
            display: block;
        }

        .option-divider {
            display: flex;
            align-items: center;
            margin: 15px 0;
            color: #95a5a6;
        }

        .option-divider:before,
        .option-divider:after {
            content: "";
            flex: 1;
            border-bottom: 1px solid #ecf0f1;
        }

        .option-divider:before {
            margin-right: 10px;
        }

        .option-divider:after {
            margin-left: 10px;
        }

        /* Alert styles for email messages */
        .alert-error {
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .alert-warning {
            background-color: #fff3cd;
            border: 1px solid #ffeaa7;
            color: #856404;
            padding: 12px 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-weight: 500;
        }

        .button-container {
            text-align: center;
            margin-top: 15px;
        }

        /* Fixed responsive layout */
        @media (min-width: 768px) {
            .col-md-4 {
                width: 33.33%;
                float: left;
            }
            
            .col-md-8 {
                width: 66.67%;
                float: left;
            }
        }
        
        @media (max-width: 767px) {
            .well {
                padding: 25px;
            }
            
            legend {
                font-size: 22px;
            }
            
            .form-control {
                height: 46px;
            }
            
            .col-md-4, .col-md-8 {
                width: 100%;
                padding: 0;
            }
            
            label.control-label {
                text-align: left;
                margin-bottom: 8px;
            }
            
            .photo-options {
                flex-direction: column;
            }
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
    </style>
</head>
<body>
<div class="container">
    <form class="well form-horizontal" action="register_patient.php" method="POST" id="patient_form" enctype="multipart/form-data">
        <fieldset>
            <legend>Patient Registration</legend>
            
            <!-- Email -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="email">Email</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-envelope"></i></span>
                        <input name="email" id="email" placeholder="Email" class="form-control" type="email" required>
                    </div>
                </div>
            </div>

            <!-- Hospital Search -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="hospital_search">Hospital</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-plus"></i></span>
                        <input type="text" id="hospital_search" placeholder="Search by name or zip code" class="form-control" oninput="searchHospital()">
                        <input type="hidden" name="hospital_id" id="hospital_id">
                    </div>
                    <div id="hospital_list" class="list-group"></div>
                </div>
            </div>            

            <!-- First Name -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="first_name">First Name</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-user"></i></span>
                        <input name="first_name" id="first_name" placeholder="First Name" class="form-control" type="text" required>
                    </div>
                </div>
            </div>

            <!-- Last Name -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="last_name">Last Name</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-user"></i></span>
                        <input name="last_name" id="last_name" placeholder="Last Name" class="form-control" type="text">
                    </div>
                </div>
            </div>

            <!-- Date of Birth -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="dob">Date of Birth</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-calendar"></i></span>
                        <input id="dob" name="dob" placeholder="Date of Birth" class="form-control" type="date" required>
                    </div>
                </div>
            </div>

            <!-- Gender -->
            <div class="form-group">
                <label class="col-md-4 control-label">Gender</label>
                <div class="col-md-8">
                    <div class="radio">
                        <label><input type="radio" name="gender" value="Male" required> Male</label>
                    </div>
                    <div class="radio">
                        <label><input type="radio" name="gender" value="Female" required> Female</label>
                    </div>
                    <div class="radio">
                        <label><input type="radio" name="gender" value="Other" required> Other</label>
                    </div>
                </div>
            </div>

            <!-- Blood Group -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="blood_group">Blood Group</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-tint"></i></span>
                        <select name="blood_group" id="blood_group" class="form-control" required>
                            <option value="">Select Blood Group</option>
                            <option value="A+">A+</option>
                            <option value="A-">A-</option>
                            <option value="B+">B+</option>
                            <option value="B-">B-</option>
                            <option value="AB+">AB+</option>
                            <option value="AB-">AB-</option>
                            <option value="O+">O+</option>
                            <option value="O-">O-</option>
                        </select>
                    </div>
                </div>
            </div>

            <!-- Profile Picture Upload -->
            <div class="form-group">
                <label class="col-md-4 control-label">Profile Picture</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="photo-options">
                        <button id="request-camera-btn" type="button" class="btn btn-primary">
                            <i class="glyphicon glyphicon-camera"></i> Use Camera
                        </button>
                        <button id="upload-btn" type="button" class="btn btn-primary">
                            <i class="glyphicon glyphicon-upload"></i> Upload Photo
                        </button>
                    </div>
                    
                    <!-- File Upload -->
                    <div class="file-upload">
                        <input type="file" id="file-input" accept="image/*">
                    </div>
                    
                    <!-- Image Preview -->
                    <img id="image-preview" src="#" alt="Preview">
                    
                    <!-- Video Preview -->
                    <div id="video-container" style="display:none;">
                        <video id="video" width="320" height="240" autoplay></video>
                        <div class="photo-options">
                            <button id="capture-btn" type="button" class="btn btn-success">
                                <i class="glyphicon glyphicon-camera"></i> Capture
                            </button>
                            <button id="retake-btn" type="button" class="btn btn-danger">
                                <i class="glyphicon glyphicon-repeat"></i> Retake
                            </button>
                        </div>
                    </div>
                    
                    <!-- Canvas for Captured Image -->
                    <canvas id="canvas" width="320" height="240" style="display:none;"></canvas>
                    
                    <!-- Hidden Input to Store Captured Image -->
                    <input name="profile_picture" id="profile_picture" type="hidden" required>
                </div>
            </div>

            <!-- Location -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="location">Location</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-map-marker"></i></span>
                        <input name="location" id="location" placeholder="Enter Location" class="form-control" type="text">
                    </div>
                </div>
            </div>

            <!-- Password -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="password">Password</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                        <input name="password" id="password" placeholder="Password" class="form-control" type="password" required>
                    </div>
                </div>
            </div>

            <!-- Confirm Password -->
            <div class="form-group">
                <label class="col-md-4 control-label" for="confirm_password">Confirm Password</label>
                <div class="col-md-8 inputGroupContainer">
                    <div class="input-group">
                        <span class="input-group-addon"><i class="glyphicon glyphicon-lock"></i></span>
                        <input name="confirm_password" id="confirm_password" placeholder="Confirm Password" class="form-control" type="password" required>
                    </div>
                </div>
            </div>

            <!-- Submit Button -->
            <div class="form-group">
                <label class="col-md-4 control-label"></label>
                <div class="col-md-8">
                    <div class="button-container">
                        <button type="submit" class="btn btn-primary">Register <span class="glyphicon glyphicon-send"></span></button>
                        <button type="button" id="go-back-btn" class="btn btn-secondary" style="display: none;">
                            <span class="glyphicon glyphicon-arrow-left"></span> Go Back
                        </button>
                    </div>
                </div>
            </div>
        </fieldset>
    </form>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>
<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/js/bootstrap.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/bootstrap-validator/0.5.3/js/bootstrapValidator.min.js"></script>

<script>
$(document).ready(function() {
    let today = new Date();
    let minDate = new Date(today.setFullYear(today.getFullYear() - 1)).toISOString().split('T')[0];
    $('#dob').attr('max', minDate);

    // Initialize form validation
    $('#patient_form').bootstrapValidator({
        feedbackIcons: {
            valid: 'glyphicon glyphicon-ok',
            invalid: 'glyphicon glyphicon-remove',
            validating: 'glyphicon glyphicon-refresh'
        },
        fields: {
            first_name: {
                validators: {
                    notEmpty: {
                        message: 'The first name is required'
                    }
                }
            },
            last_name: {
                validators: {
                    notEmpty: {
                        message: 'The last name is required'
                    }
                }
            },
            dob: {
                validators: {
                    notEmpty: {
                        message: 'The date of birth is required'
                    },
                    date: {
                        format: 'DD-MM-YYYY',
                        message: 'The date of birth is not valid'
                    }
                }
            },
            gender: {
                validators: {
                    notEmpty: {
                        message: 'The gender is required'
                    }
                }
            },
            blood_group: {
                validators: {
                    notEmpty: {
                        message: 'The blood group is required'
                    }
                }
            },
            location: {
                validators: {
                    notEmpty: {
                        message: 'Location is required'
                    }
                }
            },
            email: {
                validators: {
                    notEmpty: {
                        message: 'The email address is required'
                    },
                    emailAddress: {
                        message: 'The email address is not valid'
                    }
                }
            },
            password: {
                validators: {
                    notEmpty: {
                        message: 'The password is required'
                    },
                    stringLength: {
                        min: 6,
                        message: 'The password must be at least 6 characters long'
                    }
                }
            },
            confirm_password: {
                validators: {
                    notEmpty: {
                        message: 'The password confirmation is required'
                    },
                    identical: {
                        field: 'password',
                        message: 'The password and its confirmation do not match'
                    }
                }
            }
        }
    });

    // Hospital search functionality
    $('#hospital_search').on('input', function() {
        let query = $(this).val();
        if (query.length > 0) {
            $.ajax({
                url: '', // Current file for hospital search
                type: 'GET',
                data: { query: query },
                success: function(response) {
                    $('#hospital_list').html(response).show();
                    $('.hospital-option').click(function() {
                        let hospital_id = $(this).data('id');
                        $('#hospital_search').val($(this).text());
                        $('#hospital_id').val(hospital_id);
                        $('#hospital_list').hide();
                    });
                },
                error: function() {
                    alert("Error: Could not retrieve hospital list.");
                }
            });
        } else {
            $('#hospital_list').hide();
        }
    });

    // Enhanced email input validation with specific messages
    $('input[name="email"]').on('input', function () {
        const email = $(this).val();
        if (email) {
            $.ajax({
                url: '', // Current file
                type: 'POST',
                data: { email_check: email },
                success: function (response) {
                    // Remove any existing messages
                    $('#email-message').remove();
                    
                    if (response.trim() === "doctor_exists") {
                        // Show error message for doctor and hide register button, show go back button
                        $('form').prepend('<div id="email-message" class="alert-error text-center"> This email is registered as a Doctor. Please try a different email address.</div>');
                        // Hide all fields except email and show go back button
                        $('fieldset > div').hide();
                        $('input[name="email"]').closest('.form-group').show();
                        $('button[type="submit"]').closest('.form-group').show(); // Show button container
                        $('button[type="submit"]').hide(); // Hide register button
                        $('#go-back-btn').show(); // Show go back button
                        
                    } else if (response.trim() === "receptionist_exists") {
                        // Show error message for receptionist and hide register button, show go back button
                        $('form').prepend('<div id="email-message" class="alert-error text-center"> This email is registered as a Receptionist. Please try a different email address.</div>');
                        // Hide all fields except email and show go back button
                        $('fieldset > div').hide();
                        $('input[name="email"]').closest('.form-group').show();
                        $('button[type="submit"]').closest('.form-group').show(); // Show button container
                        $('button[type="submit"]').hide(); // Hide register button
                        $('#go-back-btn').show(); // Show go back button
                        
                    } else if (response.trim() === "patient_exists") {
                        // Show warning message for existing patient
                        $('form').prepend('<div id="email-message" class="alert-warning text-center"><strong>Notice:</strong> Your email is already registered as a patient. Please select a hospital and submit.</div>');
                        // Hide all fields except Email, Hospital, and Register button
                        $('fieldset > div').hide();
                        $('input[name="email"]').closest('.form-group').show();
                        $('#hospital_search').closest('.form-group').show();
                        $('button[type="submit"]').closest('.form-group').show();
                        $('button[type="submit"]').show(); // Show register button
                        $('#go-back-btn').hide(); // Hide go back button
                        
                    } else {
                        // Show all fields for new email
                        $('fieldset > div').show();
                        $('button[type="submit"]').show(); // Show register button
                        $('#go-back-btn').hide(); // Hide go back button
                    }
                },
                error: function () {
                    alert("Error checking email.");
                }
            });
        } else {
            // Show all fields and remove the message if email input is cleared
            $('fieldset > div').show();
            $('#email-message').remove();
            $('button[type="submit"]').show(); // Show register button
            $('#go-back-btn').hide(); // Hide go back button
        }
    });

    // Go Back button functionality
    $('#go-back-btn').click(function() {
        // Clear email field
        $('input[name="email"]').val('');
        // Remove error message
        $('#email-message').remove();
        // Show all fields
        $('fieldset > div').show();
        // Show register button and hide go back button
        $('button[type="submit"]').show();
        $('#go-back-btn').hide();
    });

    // Validate hospital selection on form submit
    $('form').on('submit', function (e) {
        const hospitalValue = $('#hospital_search').val().trim();
        if (!hospitalValue) {
            e.preventDefault(); // Prevent form submission
            if ($('#hospital-message').length === 0) {
                // Add the message only if it doesn't already exist
                $('#hospital_search')
                    .closest('.form-group')
                    .append('<div id="hospital-message" class="text-danger">Please select a hospital.</div>');
            }
        } else {
            // Remove the message if hospital is selected
            $('#hospital-message').remove();
        }
    });

    // Remove error message when user starts typing in the hospital search field
    $('#hospital_search').on('input', function () {
        $('#hospital-message').remove();
    });
    
    // Toggle between camera and file upload
    $('#upload-btn').click(function() {
        $('#video-container').hide();
        $('.file-upload').show();
        $('#file-input').click();
    });
    
    $('#request-camera-btn').click(function() {
        $('.file-upload').hide();
        initCamera();
    });
    
    // Handle file upload
    $('#file-input').change(function(e) {
        if (e.target.files && e.target.files[0]) {
            const reader = new FileReader();
            
            reader.onload = function(event) {
                $('#image-preview').attr('src', event.target.result).show();
                $('#profile_picture').val(event.target.result);
                $('#retake-btn').hide();
                $('#capture-btn').hide();
            }
            
            reader.readAsDataURL(e.target.files[0]);
        }
    });
});

// Variables for camera functionality
let stream = null;
const video = document.getElementById('video');
const canvas = document.getElementById('canvas');
const captureButton = document.getElementById('capture-btn');
const retakeButton = document.getElementById('retake-btn');
const profilePictureInput = document.getElementById('profile_picture');
const imagePreview = document.getElementById('image-preview');
const videoContainer = document.getElementById('video-container');

// Initialize camera
function initCamera() {
    if (stream) {
        // If stream exists, stop all tracks
        stream.getTracks().forEach(track => track.stop());
    }
    
    navigator.mediaDevices.getUserMedia({ video: true, audio: false })
        .then(function(mediaStream) {
            stream = mediaStream;
            video.srcObject = mediaStream;
            videoContainer.style.display = 'block';
            $('#image-preview').hide();
            $('#capture-btn').show();
            $('#retake-btn').hide();
        })
        .catch(function(err) {
            console.error("Error accessing the webcam: ", err);
            alert("Unable to access the webcam. Please ensure you have granted permission or try uploading a photo instead.");
        });
}

// Capture image
captureButton.addEventListener('click', function() {
    const context = canvas.getContext('2d');
    // Draw the video frame to the canvas
    context.drawImage(video, 0, 0, canvas.width, canvas.height);
    
    // Convert the canvas to a data URL and set it as the profile picture
    const imageData = canvas.toDataURL('image/png');
    profilePictureInput.value = imageData;
    
    // Show the captured image
    imagePreview.src = imageData;
    imagePreview.style.display = 'block';
    
    // Hide video and show retake button
    video.style.display = 'none';
    captureButton.style.display = 'none';
    retakeButton.style.display = 'inline-block';
});

// Retake photo
retakeButton.addEventListener('click', function() {
    // Show video again
    video.style.display = 'block';
    captureButton.style.display = 'inline-block';
    retakeButton.style.display = 'none';
    imagePreview.style.display = 'none';
    
    // Clear the profile picture value
    profilePictureInput.value = '';
});

// Function to search hospital
function searchHospital() {
    let query = document.getElementById('hospital_search').value;
    if (query.length > 0) {
        $.ajax({
            url: '', // Current file for hospital search
            type: 'GET',
            data: { query: query },
            success: function(response) {
                $('#hospital_list').html(response).show();
                $('.hospital-option').click(function() {
                    let hospital_id = $(this).data('id');
                    $('#hospital_search').val($(this).text());
                    $('#hospital_id').val(hospital_id);
                    $('#hospital_list').hide();
                });
            },
            error: function() {
                alert("Error: Could not retrieve hospital list.");
            }
        });
    } else {
        $('#hospital_list').hide();
    }
}
</script>
</body>
</html>
