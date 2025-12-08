<?php
// Fix the path to dompdf
require_once __DIR__ . '/../vendor/autoload.php';

use Dompdf\Dompdf;
use Dompdf\Options;

require '../PHPMailer/src/Exception.php';
require '../PHPMailer/src/PHPMailer.php';
require '../PHPMailer/src/SMTP.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

session_start();

include '../connection.php';
$db = $conn;
if (!isset($_SESSION['user_id']) || $_SESSION['user_type'] !== 'doctor') {
    header("Location: ../login.php");
    exit;
}

$success_message = '';
$error_message = '';

// Get doctor information
$doctor_id = $_SESSION['user_id'];
$doctor_query = $db->prepare("SELECT first_name, last_name, hospital_id, signature FROM doctors WHERE id = ?");
$doctor_query->bind_param("i", $doctor_id);
$doctor_query->execute();
$doctor_result = $doctor_query->get_result();
$doctor = $doctor_result->fetch_assoc();
$doctor_name = $doctor['first_name'] . ' ' . $doctor['last_name'];
$doctor_hospital_id = $doctor['hospital_id'];
$doctor_signature_blob = $doctor['signature'];

// Convert BLOB to base64 for doctor signature
$doctor_signature = '';
if ($doctor_signature_blob) {
    $doctor_signature = 'data:image/png;base64,' . base64_encode($doctor_signature_blob);
} else {
    $doctor_signature = 'images/signatures/default.png';
}

// Get immunization ID from URL
$immunization_id = isset($_GET['immunization_id']) ? intval($_GET['immunization_id']) : 0;

// Get immunization and patient information
$patient_info = null;
$immunization_info = null;
if ($immunization_id > 0) {
    // Get immunization details
    $immunization_query = $db->prepare("
        SELECT i.*, p.first_name, p.last_name, p.date_of_birth, p.gender, p.email 
        FROM immunizations i
        JOIN patients p ON i.patient_id = p.id
        WHERE i.id = ?
        LIMIT 1
    ");
    $immunization_query->bind_param("i", $immunization_id);
    $immunization_query->execute();
    $immunization_result = $immunization_query->get_result();
    $immunization_info = $immunization_result->fetch_assoc();
    
    if ($immunization_info) {
        $patient_id = $immunization_info['patient_id'];
        $patient_info = [
            'id' => $patient_id,
            'first_name' => $immunization_info['first_name'],
            'last_name' => $immunization_info['last_name'],
            'date_of_birth' => $immunization_info['date_of_birth'],
            'gender' => $immunization_info['gender'],
            'email' => $immunization_info['email'],
            'hospital_id' => $immunization_info['hospital_id']
        ];
    }
}

// Check if form is submitted
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Process form data
    if (!$immunization_info) {
        $error_message = "Error: Immunization record not found.";
    } else {
        $patient_id = $immunization_info['patient_id'];
        $hospital_id = $immunization_info['hospital_id'];
        
        // Begin transaction
        $db->begin_transaction();
        
        try {
            // Update immunization record if provided
            if (!empty($_POST['vaccine_name'])) {
                // Set status to "Completed" when vaccine name is provided
                $immunization_status = "Completed";
                $current_date = date('Y-m-d'); // Get current date
                
                // Fix 1: Ensure dose_number is treated as integer and immunization_date is properly set
                $dose_number = !empty($_POST['dose_number']) ? intval($_POST['dose_number']) : 1;
                
                $stmt = $db->prepare("UPDATE immunizations 
                    SET vaccine_name = ?, dose_number = ?, status = ?, immunization_date = ? 
                    WHERE id = ?");
                $stmt->bind_param("sissi", 
                    $_POST['vaccine_name'], 
                    $dose_number, 
                    $immunization_status,
                    $current_date,
                    $immunization_id
                );
                
                if (!$stmt->execute()) {
                    throw new Exception("Failed to update immunization record: " . $stmt->error);
                }
            }
            
            // Insert or update lab results if provided
            if (!empty($_POST['test_name'])) {
                // Check if lab result exists for this immunization
                $check_stmt = $db->prepare("SELECT id FROM labresults WHERE immunization_id = ?");
                $check_stmt->bind_param("i", $immunization_id);
                $check_stmt->execute();
                $check_result = $check_stmt->get_result();
                
                if ($check_result->num_rows > 0) {
                    // Update existing lab result
                    $lab_id = $check_result->fetch_assoc()['id'];
                    $stmt = $db->prepare("UPDATE labresults 
                        SET test_name = ?, result_value = ?, result_unit = ?, result_status = ?, test_date = CURDATE() 
                        WHERE id = ?");
                    $stmt->bind_param("ssssi", 
                        $_POST['test_name'], 
                        $_POST['result_value'], 
                        $_POST['result_unit'], 
                        $_POST['result_status'],
                        $lab_id
                    );
                } else {
                    // Insert new lab result
                    $stmt = $db->prepare("INSERT INTO labresults 
                        (patient_id, doctor_id, hospital_id, immunization_id, test_name, result_value, result_unit, result_status, test_date) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURDATE())");
                    $stmt->bind_param("iiisssss", 
                        $patient_id, 
                        $doctor_id, 
                        $hospital_id, 
                        $immunization_id,
                        $_POST['test_name'], 
                        $_POST['result_value'], 
                        $_POST['result_unit'], 
                        $_POST['result_status']
                    );
                }
                
                if (!$stmt->execute()) {
                    throw new Exception("Failed to update lab results: " . $stmt->error);
                }
            }
            
            // Insert or update allergies if provided
            if (!empty($_POST['allergen'])) {
                // Check if allergy exists for this immunization
                $check_stmt = $db->prepare("SELECT id FROM allergies WHERE immunization_id = ?");
                $check_stmt->bind_param("i", $immunization_id);
                $check_stmt->execute();
                $check_result = $check_stmt->get_result();
                
                $allergy_status = "Active"; // Default status
                
                if ($check_result->num_rows > 0) {
                    // Update existing allergy
                    $allergy_id = $check_result->fetch_assoc()['id'];
                    $stmt = $db->prepare("UPDATE allergies 
                        SET allergen = ?, reaction = ?, severity = ? 
                        WHERE id = ?");
                    $stmt->bind_param("sssi", 
                        $_POST['allergen'], 
                        $_POST['reaction'], 
                        $_POST['severity'],
                        $allergy_id
                    );
                } else {
                    // Insert new allergy
                    $stmt = $db->prepare("INSERT INTO allergies 
                        (patient_id, doctor_id, hospital_id, immunization_id, allergen, reaction, severity, status) 
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                    $stmt->bind_param("iiiissss", 
                        $patient_id, 
                        $doctor_id, 
                        $hospital_id, 
                        $immunization_id,
                        $_POST['allergen'], 
                        $_POST['reaction'], 
                        $_POST['severity'], 
                        $allergy_status
                    );
                }
                
                if (!$stmt->execute()) {
                    throw new Exception("Failed to update allergies: " . $stmt->error);
                }
            }
            
            // Generate PDF report
            $patient_name = $patient_info['first_name'] . ' ' . $patient_info['last_name'];
            
            // Set PDF options
            $options = new Options();
            $options->set('isHtml5ParserEnabled', true);
            $options->set('isPhpEnabled', true);
            
            $dompdf = new Dompdf($options);
            
            // Get hospital info
            $hospital_name = getHospitalName($hospital_id, $db);
            $hospital_logo = getHospitalLogo($hospital_id, $db);
            $hospital_seal = getHospitalSeal($hospital_id, $db);
            
            // Create PDF content
            $html = '
            <!DOCTYPE html>
            <html>
            <head>
                <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
                <style>
                    @page { 
                        margin: 100px 50px; 
                        size: A4; 
                    }
                    body {
                        font-family: "Helvetica", "Arial", sans-serif;
                        color: #333;
                        line-height: 1.4;
                    }
                    header { 
                        position: fixed; 
                        top: -60px; 
                        left: 0; 
                        right: 0; 
                        height: 60px; 
                        border-bottom: 1px solid #2a6fd1;
                        padding-bottom: 10px;
                    }
                    footer { 
                        position: fixed; 
                        bottom: -60px; 
                        left: 0; 
                        right: 0; 
                        height: 40px; 
                        border-top: 1px solid #eee;
                        padding-top: 5px;
                    }
                    .content { 
                        margin: 20px 0; 
                        page-break-after: always;
                    }
                    .section { 
                        margin-bottom: 25px; 
                        border-bottom: 1px solid #eee; 
                        padding-bottom: 15px; 
                    }
                    .hospital-header { 
                        color: #2a6fd1; 
                        font-size: 24px; 
                        margin-bottom: 10px; 
                        font-weight: bold;
                    }
                    .patient-info {
                        background-color: #f9f9f9;
                        padding: 15px;
                        border-radius: 5px;
                        margin-bottom: 20px;
                    }
                    .patient-info h3 {
                        margin-top: 0;
                        color: #2a6fd1;
                    }
                    table { 
                        width: 100%; 
                        border-collapse: collapse; 
                        margin: 15px 0; 
                    }
                    th { 
                        background: #2a6fd1; 
                        color: white;
                        padding: 10px; 
                        text-align: left; 
                    }
                    td { 
                        padding: 8px; 
                        border-bottom: 1px solid #eee; 
                    }
                    tr:nth-child(even) {
                        background-color: #f9f9f9;
                    }
                    .section-title {
                        background-color: #f3f7fb;
                        padding: 8px 15px;
                        color: #2a6fd1;
                        border-left: 4px solid #2a6fd1;
                        font-size: 18px;
                        margin: 20px 0 15px 0;
                    }
                    .status-normal {
                        color: green;
                        font-weight: bold;
                    }
                    .status-high, .status-low, .status-critical {
                        color: red;
                        font-weight: bold;
                    }
                    .status-pending {
                        color: orange;
                        font-weight: bold;
                    }
                    .severity-mild {
                        color: green;
                    }
                    .severity-moderate {
                        color: orange;
                    }
                    .severity-severe {
                        color: red;
                    }
                    .watermark {
                        position: fixed;
                        top: 50%;
                        left: 50%;
                        transform: translate(-50%, -50%) rotate(-45deg);
                        font-size: 100px;
                        color: rgba(200, 200, 200, 0.1);
                        z-index: -1;
                    }
                </style>
            </head>
            <body>
                <div class="watermark">'.$hospital_name.'</div>
                <header>
                    <table style="border:none; margin:0;">
                        <tr style="background:none;">
                            <td style="border:none; padding:0; width:50%;">
                                <img src="'.$hospital_logo.'" style="height:50px;">
                            </td>
                            <td style="border:none; padding:0; text-align:right; width:50%;">
                                <div style="font-size:12px; color:#777;">Report Date: '.date('Y-m-d').'</div>
                                <div style="font-size:12px; color:#777;">Report ID: '.uniqid().'</div>
                            </td>
                        </tr>
                    </table>
                </header>
                
                <footer>
                    <div style="text-align:center; color:#666; font-size:12px;">
                        Confidential Medical Document - Dr. '.$doctor_name.', MD
                    </div>
                    <div style="text-align:center; color:#999; font-size:10px;">
                        Page <span class="pagenum"></span>
                    </div>
                </footer>
                
                <div class="content">
                    <div class="hospital-header">'.$hospital_name.' Medical Report</div>
                    
                    <div class="patient-info">
                        <h3>Patient Information</h3>
                        <table style="border:none;">
                            <tr style="background:none;">
                                <td style="border:none; width:50%;"><strong>Name:</strong> '.htmlspecialchars($patient_name).'</td>
                                <td style="border:none; width:50%;"><strong>DOB:</strong> '.htmlspecialchars($patient_info['date_of_birth']).'</td>
                            </tr>
                            <tr style="background:none;">
                                <td style="border:none;"><strong>Gender:</strong> '.htmlspecialchars($patient_info['gender']).'</td>
                                <td style="border:none;"><strong>Doctor:</strong> Dr. '.htmlspecialchars($doctor_name).'</td>
                            </tr>
                        </table>
                    </div>
                    
                    <div class="section">
                        <div class="section-title">Lab Results</div>
                        '.generateLabResultsTable($patient_id, $hospital_id, $immunization_id, $db).'
                    </div>
                    
                    <div class="section">
                        <div class="section-title">Allergies</div>
                        '.generateAllergiesTable($patient_id, $hospital_id, $immunization_id, $db).'
                    </div>
                    
                    <div class="section">
                        <div class="section-title">Immunizations</div>
                        '.generateImmunizationsTable($patient_id, $hospital_id, $immunization_id, $db).'
                    </div>
                    
                    <div style="margin-top:30px; padding-top:20px; border-top:1px dashed #ccc;">
                        <table style="border:none;">
                            <tr style="background:none;">
                                <td style="border:none; width:50%;">
                                    <strong>Doctor\'s Signature:</strong><br>
                                    <img src="'.$doctor_signature.'" style="height:60px;">
                                </td>
                                <td style="border:none; width:20%;">
                                    <strong>Hospital Seal:</strong><br>
                                    <img src="'.$hospital_seal.'" style="height:60px;">
                                </td>
                            </tr>
                        </table>
                    </div>
                </div>
            </body>
            </html>';
            
            $dompdf->loadHtml($html);
            $dompdf->setPaper('A4', 'portrait');
            $dompdf->render();
            
            // Get PDF content
            $pdf_content = $dompdf->output();
            
            // Create uploads/pdfs directory if it doesn't exist
            $upload_dir = '../patient/uploads/pdfs/';
            if (!file_exists($upload_dir)) {
                mkdir($upload_dir, 0755, true);
            }
            
            // Create filename: vaccinetype_patientname_date.pdf
            $vaccine_name = !empty($_POST['vaccine_name']) ? $_POST['vaccine_name'] : $immunization_info['vaccine_name'];
            $vaccine_name = preg_replace('/[^a-zA-Z0-9]/', '', $vaccine_name); // Remove special characters
            $patient_name_clean = preg_replace('/[^a-zA-Z0-9]/', '', str_replace(' ', '', $patient_name)); // Remove spaces and special characters
            $current_date = date('Y-m-d');
            $filename = $vaccine_name . '_' . $patient_name_clean . '_' . $current_date . '.pdf';
            $file_path = $upload_dir . $filename;
            
            // Save PDF to file system
            if (!file_put_contents($file_path, $pdf_content)) {
                throw new Exception("Failed to save PDF file to: " . $file_path);
            }
            
            // Update immunization record with PDF file path instead of BLOB
            $pdf_stmt = $db->prepare("UPDATE immunizations SET pdf_file = ? WHERE id = ?");
            if (!$pdf_stmt) {
                throw new Exception("Failed to prepare PDF update statement: " . $db->error);
            }
            
            $pdf_stmt->bind_param("si", $file_path, $immunization_id);
            
            if (!$pdf_stmt->execute()) {
                throw new Exception("Failed to update PDF file path: " . $pdf_stmt->error);
            }
            
            // Get patient email
            $patient_email = $patient_info['email'];
            
            // Send email with PDF using PHPMailer
            $mail = new PHPMailer(true);
            
            try {
                // Server settings
                $mail->isSMTP();
                $mail->Host = 'smtp.gmail.com';
                $mail->SMTPAuth = true;
                $mail->Username = ''; //replace email
                $mail->Password = ''; //replace pass
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port = 587;
                
                // Recipients
                $mail->setFrom('your@gmail.com', $hospital_name . ' Medical Center');
                $mail->addAddress($patient_email, $patient_name);
                
                // Content
                $mail->isHTML(true);
                $mail->Subject = 'Your Updated Medical Report from ' . $hospital_name;
                
                // Get current date in a nice format
                $current_date_formatted = date('F j, Y');
                
                // Create a beautiful HTML email template
                $mail->Body = '
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Medical Report Update</title>
                    <style>
                        @import url(\'https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap\');
                        
                        body {
                            font-family: \'Roboto\', Arial, sans-serif;
                            line-height: 1.6;
                            color: #4a4a4a;
                            margin: 0;
                            padding: 0;
                            background-color: #f9f9f9;
                        }
                        
                        .email-container {
                            max-width: 600px;
                            margin: 0 auto;
                            background-color: #ffffff;
                            border-radius: 8px;
                            overflow: hidden;
                            box-shadow: 0 4px 10px rgba(0, 0, 0, 0.1);
                        }
                        
                        .email-header {
                            background: linear-gradient(135deg, #2a6fd1, #1e5bb0);
                            color: white;
                            padding: 30px;
                            text-align: center;
                        }
                        
                        .email-header img {
                            max-height: 80px;
                            margin-bottom: 15px;
                        }
                        
                        .email-header h1 {
                            margin: 0;
                            font-size: 28px;
                            font-weight: 700;
                        }
                        
                        .email-header p {
                            margin: 5px 0 0;
                            opacity: 0.9;
                            font-size: 16px;
                        }
                        
                        .email-body {
                            padding: 30px;
                            background-color: #ffffff;
                        }
                        
                        .greeting {
                            font-size: 20px;
                            font-weight: 500;
                            color: #2a6fd1;
                            margin-bottom: 20px;
                        }
                        
                        .message {
                            font-size: 16px;
                            margin-bottom: 25px;
                            color: #555;
                        }
                        
                        .highlight-box {
                            background-color: #f3f7fc;
                            border-left: 4px solid #2a6fd1;
                            padding: 15px 20px;
                            margin: 25px 0;
                            border-radius: 4px;
                        }
                        
                        .highlight-box h3 {
                            margin-top: 0;
                            color: #2a6fd1;
                            font-size: 18px;
                        }
                        
                        .highlight-box ul {
                            margin: 10px 0 0;
                            padding-left: 20px;
                        }
                        
                        .highlight-box li {
                            margin-bottom: 8px;
                        }
                        
                        .button-container {
                            text-align: center;
                            margin: 30px 0;
                        }
                        
                        .button {
                            display: inline-block;
                            background-color: #2a6fd1;
                            color: white;
                            text-decoration: none;
                            padding: 12px 30px;
                            border-radius: 50px;
                            font-weight: 500;
                            font-size: 16px;
                            transition: background-color 0.3s;
                        }
                        
                        .button:hover {
                            background-color: #1e5bb0;
                        }
                        
                        .doctor-info {
                            margin-top: 30px;
                            padding-top: 20px;
                            border-top: 1px solid #eee;
                        }
                        
                        .doctor-name {
                            color: #2a6fd1;
                            font-weight: 500;
                            font-size: 18px;
                            margin: 0;
                        }
                        
                        .doctor-title {
                            color: #777;
                            margin: 5px 0 0;
                        }
                        
                        .email-footer {
                            background-color: #f3f7fc;
                            padding: 20px 30px;
                            text-align: center;
                            font-size: 14px;
                            color: #777;
                        }
                        
                        .contact-info {
                            margin-bottom: 15px;
                        }
                        
                        .social-icons {
                            margin-bottom: 15px;
                        }
                        
                        .social-icons a {
                            display: inline-block;
                            margin: 0 8px;
                            color: #2a6fd1;
                            text-decoration: none;
                        }
                        
                        .copyright {
                            margin-top: 15px;
                            font-size: 12px;
                            color: #999;
                        }
                        
                        @media screen and (max-width: 600px) {
                            .email-container {
                                width: 100%;
                                border-radius: 0;
                            }
                            
                            .email-header, .email-body, .email-footer {
                                padding: 20px;
                            }
                        }
                    </style>
                </head>
                <body>
                    <div class="email-container">
                        <div class="email-header">
                            <h1>'.$hospital_name.'</h1>
                            <p>Medical Report Update</p>
                        </div>
                        
                        <div class="email-body">
                            <div class="greeting">Dear '.htmlspecialchars($patient_name).',</div>
                            
                            <div class="message">
                                We are pleased to inform you that your medical records have been successfully updated. Dr. '.htmlspecialchars($doctor_name).' has completed your treatment and prepared a comprehensive medical report for your records.
                            </div>
                            
                            <div class="highlight-box">
                                <h3>Your Medical Report Includes:</h3>
                                <ul>
                                    <li><strong>Updated Lab Results</strong> - Detailed analysis of your recent tests</li>
                                    <li><strong>Allergy Information</strong> - Any new allergies or reactions</li>
                                    <li><strong>Immunization Records</strong> - Your latest vaccination details</li>
                                </ul>
                            </div>
                            
                            <div class="message">
                                <strong>Please find your complete medical report attached to this email.</strong> We recommend saving this document for your personal health records. If you have any questions about your treatment or the information in the report, please don\'t hesitate to contact us.
                            </div>
                            
                            <div class="button-container">
                                <a href="https://electronichealthrecordsystem.kesug.com/patientRecords/login.php" class="button">Access Patient Portal</a>
                            </div>
                            
                            <div class="doctor-info">
                                <p class="doctor-name">Dr. '.htmlspecialchars($doctor_name).'</p>
                                <p class="doctor-title">Medical Practitioner, '.$hospital_name.'</p>
                            </div>
                        </div>
                        
                        <div class="email-footer">
                            <div class="contact-info">
                                <strong>'.$hospital_name.' Medical Center</strong><br>
                                 Email: info@'.$hospital_name.'.com
                            </div>
                            
                            <div class="social-icons">
                                <a href="https://www.linkedin.com/in/milan-m-981369286?utm_source=share&utm_campaign=share_via&utm_content=profile&utm_medium=android_app">LinkedIn</a> | 
                                <a href="https://www.facebook.com/share/16WEA3sYrC/">Facebook</a> | 
                                <a href="https://www.instagram.com/milan_kumar9999?igsh=bHBhbnViYjRlYm0y">Instagram</a>
                            </div>
                            
                            <div class="copyright">
                                &copy; '.date('Y').' '.$hospital_name.' Medical Center. All rights reserved.<br>
                                This email contains confidential medical information intended only for the recipient.
                            </div>
                        </div>
                    </div>
                </body>
                </html>';
                
                // Add PDF attachment from file path
                $mail->addAttachment($file_path, "Medical_Report_" . date('Y-m-d') . ".pdf");
                
                $mail->send();
                
                // Create reports directory if it doesn't exist (for backup)
                if (!file_exists('reports')) {
                    mkdir('reports', 0755, true);
                }
                
                // Save PDF to reports directory as backup
                copy($file_path, 'reports/'.$patient_id.'_'.date('Y-m-d').'.pdf');
                
                // Commit transaction
                $db->commit();
                
                // Set success message in session for display after redirect
                $_SESSION['success_message'] = "Medical records updated and report sent to patient successfully. PDF saved to: " . $file_path;
                
                // Redirect to doctor_profile.php to prevent form resubmission
                header("Location: doctor_profile.php");
                exit;
                
            } catch (Exception $e) {
                $error_message = "Records updated but failed to send email: " . $mail->ErrorInfo;
                // Continue with page display without redirect in case of error
            }
            
        } catch (Exception $e) {
            // Rollback transaction on error
            $db->rollback();
            $error_message = "Error: " . $e->getMessage();
        }
    }
}

// Check for success message in session (will be displayed after redirect)
if (isset($_SESSION['success_message'])) {
    $success_message = $_SESSION['success_message'];
    unset($_SESSION['success_message']); // Clear the message after displaying it
}

// Helper functions
function getHospitalName($hospital_id, $db) {
    $stmt = $db->prepare("SELECT hospital_name FROM hospitals WHERE id = ?");
    $stmt->bind_param("i", $hospital_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $hospital = $result->fetch_assoc();
    return $hospital['hospital_name'];
}

function getHospitalLogo($hospital_id, $db) {
    $stmt = $db->prepare("SELECT hospital_logo FROM hospitals WHERE id = ?");
    $stmt->bind_param("i", $hospital_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $hospital = $result->fetch_assoc();
    
    if ($hospital && $hospital['hospital_logo']) {
        return 'data:image/png;base64,' . base64_encode($hospital['hospital_logo']);
    }
    return 'images/default_hospital_logo.png';
}

function getHospitalSeal($hospital_id, $db) {
    $stmt = $db->prepare("SELECT hospital_seal FROM hospitals WHERE id = ?");
    $stmt->bind_param("i", $hospital_id);
    $stmt->execute();
    $result = $stmt->get_result();
    $hospital = $result->fetch_assoc();
    
    if ($hospital && $hospital['hospital_seal']) {
        return 'data:image/png;base64,' . base64_encode($hospital['hospital_seal']);
    }
    return 'images/default_hospital_seal.png';
}

function generateLabResultsTable($patient_id, $hospital_id, $immunization_id, $db) {
    $stmt = $db->prepare("SELECT * FROM labresults WHERE patient_id = ? AND hospital_id = ? AND immunization_id = ? ORDER BY test_date DESC");
    $stmt->bind_param("iii", $patient_id, $hospital_id, $immunization_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        return '<p>No lab results available.</p>';
    }
    
    $html = '<table>
        <tr>
            <th>Test Date</th>
            <th>Test Name</th>
            <th>Result</th>
            <th>Status</th>
        </tr>';
    
    while ($row = $result->fetch_assoc()) {
        $status_class = 'status-' . strtolower($row['result_status']);
        
        $html .= '<tr>
            <td>'.htmlspecialchars($row['test_date']).'</td>
            <td>'.htmlspecialchars($row['test_name']).'</td>
            <td>'.htmlspecialchars($row['result_value']).' '.htmlspecialchars($row['result_unit']).'</td>
            <td class="'.$status_class.'">'.htmlspecialchars($row['result_status']).'</td>
        </tr>';
    }
    
    $html .= '</table>';
    return $html;
}

function generateAllergiesTable($patient_id, $hospital_id, $immunization_id, $db) {
    $stmt = $db->prepare("SELECT * FROM allergies WHERE patient_id = ? AND hospital_id = ? AND immunization_id = ?");
    $stmt->bind_param("iii", $patient_id, $hospital_id, $immunization_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        return '<p>No allergies recorded.</p>';
    }
    
    $html = '<table>
        <tr>
            <th>Allergen</th>
            <th>Reaction</th>
            <th>Severity</th>
            <th>Status</th>
        </tr>';
    
    while ($row = $result->fetch_assoc()) {
        $severity_class = 'severity-' . strtolower($row['severity']);
        
        $html .= '<tr>
            <td>'.htmlspecialchars($row['allergen']).'</td>
            <td>'.htmlspecialchars($row['reaction']).'</td>
            <td class="'.$severity_class.'">'.htmlspecialchars($row['severity']).'</td>
            <td>'.htmlspecialchars($row['status']).'</td>
        </tr>';
    }
    
    $html .= '</table>';
    return $html;
}

function generateImmunizationsTable($patient_id, $hospital_id, $immunization_id, $db) {
    $stmt = $db->prepare("SELECT * FROM immunizations WHERE patient_id = ? AND hospital_id = ? AND id = ? ORDER BY immunization_date DESC");
    $stmt->bind_param("iii", $patient_id, $hospital_id, $immunization_id);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($result->num_rows === 0) {
        return '<p>No immunization records available.</p>';
    }
    
    $html = '<table>
        <tr>
            <th>Date</th>
            <th>Vaccine</th>
            <th>Dose</th>
            <th>Status</th>
        </tr>';
    
    while ($row = $result->fetch_assoc()) {
        $html .= '<tr>
            <td>'.htmlspecialchars($row['immunization_date'] ?? date('Y-m-d')).'</td>
            <td>'.htmlspecialchars($row['vaccine_name']).'</td>
            <td>'.htmlspecialchars($row['dose_number']).'</td>
            <td>'.htmlspecialchars($row['status']).'</td>
        </tr>';
    }
    
    $html .= '</table>';
    return $html;
}
?>


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Update Patient Medical Records</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        
        body {
            font-family: 'Poppins', sans-serif;
            background-color: #f5f7fa;
            color: #333;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 30px auto;
            padding: 20px;
        }
        
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #e0e0e0;
            background: linear-gradient(to right, #ffffff, #f5f7fa);
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
        }
        
        .header h1 {
            color: #2a6fd1;
            font-weight: 600;
        }
        
        .doctor-info {
            text-align: right;
            color: #666;
            background-color: #fff;
            padding: 10px 15px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .doctor-name {
            font-weight: 600;
            color: #2a6fd1;
        }
        
        .alert {
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .alert-success {
            background-color: #d4edda;
            color: #155724;
            border-left: 4px solid #28a745;
        }
        
        .alert-danger {
            background-color: #f8d7da;
            color: #721c24;
            border-left: 4px solid #dc3545;
        }
        
        .medical-form {
            background-color: white;
            border-radius: 12px;
            box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
            padding: 30px;
        }
        
        .patient-banner {
            background: linear-gradient(135deg, #2a6fd1, #1e5bb0);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .patient-banner h2 {
            margin: 0;
            font-weight: 500;
        }
        
        .patient-details {
            font-size: 14px;
            opacity: 0.9;
        }
        
        .form-header {
            margin-bottom: 25px;
        }
        
        .form-header h2 {
            color: #2a6fd1;
            font-weight: 500;
            margin-bottom: 10px;
        }
        
        .form-header p {
            color: #666;
        }
        
        .form-row {
            display: flex;
            margin-bottom: 20px;
            gap: 15px;
        }
        
        .form-group {
            flex: 1;
        }
        
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #555;
        }
        
        .form-control {
            width: 100%;
            padding: 12px 15px;
            border: 1px solid #ddd;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s;
            font-family: 'Poppins', sans-serif;
        }
        
        .form-control:focus {
            border-color: #2a6fd1;
            outline: none;
            box-shadow: 0 0 0 3px rgba(42, 111, 209, 0.1);
        }
        
        select.form-control {
            appearance: none;
            background-image: url('data:image/svg+xml;utf8,<svg fill="%23555" height="24" viewBox="0 0 24 24" width="24" xmlns="http://www.w3.org/2000/svg"><path d="M7 10l5 5 5-5z"/></svg>');
            background-repeat: no-repeat;
            background-position: right 10px center;
        }
        
        .form-section {
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        
        .form-section h3 {
            color: #2a6fd1;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px dashed #e0e0e0;
            font-weight: 500;
        }
        
        .btn {
            display: inline-block;
            padding: 14px 28px;
            background-color: #2a6fd1;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s;
            font-family: 'Poppins', sans-serif;
        }
        
        .btn:hover {
            background-color: #1e5bb0;
            transform: translateY(-2px);
            box-shadow: 0 4px 10px rgba(42, 111, 209, 0.2);
        }
        
        .btn-block {
            display: block;
            width: 100%;
        }
        
        .text-center {
            text-align: center;
        }
        
        .mt-4 {
            margin-top: 20px;
        }
        
        textarea.form-control {
            min-height: 100px;
            resize: vertical;
        }
        
        /* Tabs for different sections */
        .tabs {
            display: flex;
            margin-bottom: 20px;
            border-bottom: 1px solid #ddd;
            overflow-x: auto;
            scrollbar-width: thin;
        }
        
        .tab {
            padding: 12px 24px;
            cursor: pointer;
            border-bottom: 3px solid transparent;
            color: #666;
            font-weight: 500;
            white-space: nowrap;
            transition: all 0.3s;
        }
        
        .tab:hover {
            color: #2a6fd1;
            background-color: #f9f9f9;
        }
        
        .tab.active {
            border-bottom-color: #2a6fd1;
            color: #2a6fd1;
            background-color: #f5f7fa;
        }
        
        .tab-content {
            display: none;
            animation: fadeIn 0.5s;
        }
        
        .tab-content.active {
            display: block;
        }
        
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .form-row {
                flex-direction: column;
            }
            
            .container {
                padding: 10px;
            }
            
            .medical-form {
                padding: 20px;
            }
            
            .patient-banner {
                flex-direction: column;
                text-align: center;
            }
            
            .patient-details {
                margin-top: 10px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Patient Medical Records</h1>
            <div class="doctor-info">
                <div>Today: <?= date('F j, Y') ?></div>
                <div class="doctor-name">Dr. <?= htmlspecialchars($doctor_name) ?></div>
            </div>
        </div>
        
        <?php if ($success_message): ?>
        <div class="alert alert-success">
            <?= $success_message ?>
        </div>
        <?php endif; ?>
        
        <?php if ($error_message): ?>
        <div class="alert alert-danger">
            <?= $error_message ?>
        </div>
        <?php endif; ?>
        
        <?php if ($patient_info): ?>
        <div class="patient-banner">
            <h2>Patient: <?= htmlspecialchars($patient_info['first_name'] . ' ' . $patient_info['last_name']) ?></h2>
            <div class="patient-details">
                <div>DOB: <?= htmlspecialchars($patient_info['date_of_birth']) ?></div>
                <div>Gender: <?= htmlspecialchars($patient_info['gender']) ?></div>
            </div>
        </div>
        
        <form method="POST" class="medical-form">
            <div class="form-header">
                <h2>Update Medical Records</h2>
                <p>Add new medical information and generate a PDF report</p>
            </div>
            
            <div class="tabs">
                <div class="tab active" data-tab="lab-results">Lab Results</div>
                <div class="tab" data-tab="allergies">Allergies</div>
                <div class="tab" data-tab="immunizations">Immunizations</div>
            </div>
            
            <div id="lab-results" class="tab-content active">
                <div class="form-section">
                    <h3>Lab Results</h3>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="test_name">Test Name</label>
                            <input type="text" id="test_name" name="test_name" class="form-control" placeholder="e.g., Blood Glucose">
                        </div>
                        
                        <div class="form-group">
                            <label for="result_value">Result Value</label>
                            <input type="text" id="result_value" name="result_value" class="form-control" placeholder="e.g., 120">
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="result_unit">Unit</label>
                            <input type="text" id="result_unit" name="result_unit" class="form-control" placeholder="e.g., mg/dL">
                        </div>
                        
                        <div class="form-group">
                            <label for="result_status">Status</label>
                            <select id="result_status" name="result_status" class="form-control">
                                <option value="Normal">Normal</option>
                                <option value="High">High</option>
                                <option value="Low">Low</option>
                                <option value="Critical">Critical</option>
                                <option value="Pending">Pending</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="allergies" class="tab-content">
                <div class="form-section">
                    <h3>Allergies</h3>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="allergen">Allergen</label>
                            <input type="text" id="allergen" name="allergen" class="form-control" placeholder="e.g., Penicillin">
                        </div>
                        
                        <div class="form-group">
                            <label for="severity">Severity</label>
                            <select id="severity" name="severity" class="form-control">
                                <option value="Mild">Mild</option>
                                <option value="Moderate">Moderate</option>
                                <option value="Severe">Severe</option>
                            </select>
                        </div>
                    </div>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="reaction">Reaction</label>
                            <textarea id="reaction" name="reaction" class="form-control" placeholder="Describe the allergic reaction"></textarea>
                        </div>
                    </div>
                </div>
            </div>
            
            <div id="immunizations" class="tab-content">
                <div class="form-section">
                    <h3>Immunizations</h3>
                    
                    <div class="form-row">
                        <div class="form-group">
                            <label for="vaccine_name">Vaccine Name</label>
                            <input type="text" id="vaccine_name" name="vaccine_name" class="form-control" placeholder="e.g., Influenza" value="<?= htmlspecialchars($immunization_info['vaccine_name'] ?? '') ?>">
                        </div>
                        
                        <div class="form-group">
                            <label for="dose_number">Dose Number</label>
                            <input type="number" id="dose_number" name="dose_number" class="form-control" min="1" placeholder="e.g., 1" value="<?= htmlspecialchars($immunization_info['dose_number'] ?? '') ?>">
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="text-center mt-4">
                <button type="submit" class="btn btn-block">Update Records & Send Report</button>
            </div>
        </form>
        <?php else: ?>
        <div class="alert alert-danger">
            No immunization record found for the provided ID. Please check the immunization ID.
        </div>
        <?php endif; ?>
    </div>
    
    <script>
        // Tab functionality
        document.querySelectorAll('.tab').forEach(tab => {
            tab.addEventListener('click', () => {
                // Remove active class from all tabs
                document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                
                // Add active class to clicked tab
                tab.classList.add('active');
                document.getElementById(tab.dataset.tab).classList.add('active');
            });
        });
    </script>
</body>
</html>
