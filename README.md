
# Electronic Health Record (EHR) System

A secure, multi-hospital Electronic Health Record platform that streamlines hospital workflows and patient care. The system supports patient registration, appointments, prescriptions, encrypted problem submissions, and full admin control across multiple hospitals. It also exposes hooks for an AI chatbot to assist patients, which you can connect to your own model or any open-source solution.

> Detailed feature descriptions, screenshots, and architecture diagrams are available on the portfolio page linked below.
- Portfolio walkthrough: **(Electronic Health Record (EHR) System)**

***

## Project Summary

This EHR platform digitizes hospital workflows end-to-end: patients register once and access multiple hospitals, doctors manage cases and prescriptions, receptionists handle verification and scheduling, and admins/super admins onboard hospitals and monitor performance. Encrypted messaging and optional AI assistance reduce unnecessary in-person visits and long waiting times.

- Live demo : **([Electronic Health Record (EHR) System](https://electronichealthrecordsystem.kesug.com/patientRecords/login.php))**

***

## Prerequisites

- PHP **8 or higher**
- **XAMPP** (Apache + MySQL) installed
- A mail account that supports **app password** (for PHPMailer)
- Razorpay test or live keys (for payment features, optional)

***

## 1. Clone the Repository

```bash
git clone https://github.com/milan903575/Electronic-Health-Record-System.git
cd Electronic-Health-Record-System
```

Place this cloned folder inside your XAMPP `htdocs` directory, for example:

```text
C:\xampp\htdocs\Electronic-Health-Record-System
```


***

## 2. Database Setup (MySQL)

1. Start **Apache** and **MySQL** from the XAMPP Control Panel.
2. Click **MySQL Admin** to open **phpMyAdmin** in your browser.
3. Create a new database (for example `ehr_milan`).
4. Go to the **Import** tab.
5. Choose the file `ehr_milan.sql` from the project root.
6. Click **Go** to import. This will create all required tables.

### Update database credentials

Open `connection.php` in the project root and update it with your MySQL credentials:

```php
$servername = 'localhost';
$username   = 'your_mysql_username';
$password   = 'your_mysql_password';
$dbname     = 'ehr_milan'; // or the DB name you used
```


***

## 3. Verify Basic Setup

Open the login page in your browser:

```text
http://localhost/Electronic-Health-Record-System/login.php
```

If you see the login screen and no database-related errors, the core PHP + MySQL setup is working.

***

## 4. Email Configuration (PHPMailer)

Several modules use PHPMailer for OTP / notifications. In each of the following files, update the email and app password:

- `patient/verify_face.php`
- `forget_password/forgot_password.php`
- `doctor/confirmation_mail.php`
- `doctor/patient_report_update.php`
- `receptionist/receptionist_dashboard.php`
- `admin/admin_login.php`
- `super_admin/super_admin_dashboard.php`

Look for:

```php
$mail->Username = ''; // Replace with your email
$mail->Password = ''; // Replace with your App Password
```

Fill in:

- `Username` → your email address
- `Password` → your mail provider’s **app password** 

Make sure “less secure apps” (if applicable) or SMTP access is allowed in your mail provider settings.

***

## 5. AI Chatbot Integration (Optional)

The project includes hooks for an AI assistant to help patients describe problems and get basic guidance. By default, you should plug in **your own chatbot backend** (custom code or any open-source model/API). The original prototype used a resource-limited medical model hosted privately, which is not included here.

There are two main integration points:

- `patient/detailed_problem.php`
- `patient/patient_home_page.php`

Update them to point to your own endpoint:

```php
// patient/detailed_problem.php
$hf_url = 'https://your-chatbot-endpoint.example.com/path';

// patient/patient_home_page.php
$api_url = 'https://your-chatbot-endpoint.example.com/path';
```

You can connect this to:

- Your own Flask/Node/PHP service that calls an LLM.
- Any open-source model hosted on your own server or cloud provider.

> If you need the original reference integration used during development, please contact me and I can share that code.

***

## 6. Payment Integration (Razorpay)

To enable online payment features:

1. Open `patient/.env`.
2. Replace with your Razorpay credentials:
```env
RAZORPAY_KEY_ID=your_razorpay_key_id
RAZORPAY_KEY_SECRET=your_razorpay_key_secret
```

You can use Razorpay **test keys** in development.

***

## 7. Secure Messaging / Encryption Key

Private problem submissions use an encryption key stored in `encryption_key.key`.

1. Run the key generation script in your browser:
```text
http://localhost/Electronic-Health-Record-System/patient/patientPrivateProblems/generate_key.php
```

2. Confirm that a file named `encryption_key.key` is created in the expected directory.

If `encryption_key.key` is missing or not readable, secure messaging and viewing will throw “key not found” or similar errors. In that case:

- Re-run `generate_key.php`, and
- Ensure file permissions allow PHP to read the key.

If you choose to move or rename the key file, update any paths that reference it across the patient private-problem and other modules modules.

***

## 8. Roles Overview

The system supports multiple roles, each with its own dashboard and permissions:

- **Patient**
    - Multi-hospital registration and dynamic fees
    - MFA via email OTP + face verification
    - Dashboard for medical history, appointments, PDF reports
    - Encrypted private/public problem submissions
    - Optional AI assistant for basic triage and support
- **Doctor \& Receptionist**
    - Doctor dashboards for case management, prescriptions, and follow-ups
    - Anonymized cross-hospital history access (where allowed)
    - Receptionist tools for verification, scheduling, and tracking overdue patients
- **Admin \& Super Admin**
    - Hospital onboarding and approvals
    - User and role management
    - Performance analytics and audit logging
    - Event publishing (hospital announcements)

***

## 9. Getting Help

If you face any issues setting up the project, integrating your own AI backend, or configuring payments:

- **Email:** *(milan903575@gmail.com)*
