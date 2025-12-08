<?php
include '../connection.php';

// Handle AJAX status update
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_status') {
    $type = $_POST['type'];
    $id = intval($_POST['id']);
    $status = $_POST['status'];

    $table = $type === 'doctor' ? 'doctors' : 'receptionist';
    $column = $type === 'doctor' ? 'registration_status' : 'status';

    $stmt = $conn->prepare("UPDATE $table SET $column = ? WHERE id = ?");
    $stmt->bind_param("si", $status, $id);

    if ($stmt->execute()) {
        echo "Status updated successfully!";
    } else {
        echo "Error updating status: " . $conn->error;
    }
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Receptionist Applications</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- Google Fonts - Modern typography is a key 2025 trend -->
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        :root {
            --primary: #1976d2;
            --primary-light: #e3f2fd;
            --primary-dark: #1565c0;
            --success: #43a047;
            --success-light: #e8f5e9;
            --danger: #e53935;
            --danger-light: #ffebee;
            --background: #f8fafc;
            --card-bg: #fff;
            --text-main: #2d3748;
            --text-secondary: #4a5568;
            --shadow: 0 4px 16px rgba(0,0,0,0.08);
            --shadow-hover: 0 8px 30px rgba(0,0,0,0.12);
            --radius: 16px;
            --radius-sm: 8px;
            --transition: 0.25s cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', sans-serif;
            background: var(--background);
            color: var(--text-main);
            line-height: 1.6;
        }
        
        /* Header styling with minimalist maximalism approach */
        .header {
            padding: 40px 0 20px;
            text-align: center;
        }
        
        h2 {
            font-size: 2.5rem;
            font-weight: 800;
            color: var(--primary-dark);
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .subtitle {
            color: var(--text-secondary);
            font-size: 1.1rem;
            max-width: 600px;
            margin: 0 auto 30px;
        }
        
        /* Bento grid layout - 2025 trend */
        .container {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
            gap: 24px;
            padding: 20px;
            max-width: 1400px;
            margin: 0 auto;
        }
        
        /* Card with 3D elements and morphism - 2025 trends */
        .card {
            background: var(--card-bg);
            border-radius: var(--radius);
            box-shadow: var(--shadow);
            overflow: hidden;
            transition: transform var(--transition), box-shadow var(--transition);
            position: relative;
            display: flex;
            flex-direction: column;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: var(--shadow-hover);
        }
        
        /* Changed to display image in rectangular format */
        .card-header {
            padding: 0;
            position: relative;
        }
        
        .image-container {
            width: 100%;
            height: 200px;
            overflow: hidden;
            background: var(--primary-light);
            position: relative;
        }
        
        .image-container img {
            width: 100%;
            height: 100%;
            object-fit: cover;
        }
        
        .image-overlay {
            position: absolute;
            bottom: 0;
            left: 0;
            right: 0;
            background: linear-gradient(to top, rgba(0,0,0,0.7), transparent);
            padding: 20px;
            color: white;
        }
        
        .image-overlay h4 {
            font-size: 1.5rem;
            font-weight: 700;
            margin-bottom: 4px;
            text-shadow: 0 1px 3px rgba(0,0,0,0.3);
        }
        
        .image-placeholder {
            display: flex;
            align-items: center;
            justify-content: center;
            height: 100%;
            background: linear-gradient(135deg, #e3f2fd, #bbdefb);
        }
        
        .card-body {
            padding: 20px 24px;
            flex: 1;
        }
        
        .info-grid {
            display: grid;
            grid-template-columns: auto 1fr;
            gap: 8px 16px;
            margin-bottom: 20px;
        }
        
        .info-label {
            color: var(--text-secondary);
            font-weight: 500;
        }
        
        .info-value {
            font-weight: 600;
        }
        
        .id-proof {
            margin-bottom: 20px;
        }
        
        .card-actions {
            padding: 16px 24px 24px;
            display: flex;
            gap: 12px;
        }
        
        /* Buttons with morphism effect - 2025 trend */
        button {
            padding: 12px 24px;
            border: none;
            border-radius: var(--radius-sm);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }
        
        button:active {
            transform: scale(0.97);
        }
        
        .approve-btn {
            background: var(--success);
            color: white;
            flex: 1;
        }
        
        .approve-btn:hover {
            background: #388e3c;
            box-shadow: 0 2px 8px rgba(67, 160, 71, 0.3);
        }
        
        .reject-btn {
            background: var(--danger);
            color: white;
            flex: 1;
        }
        
        .reject-btn:hover {
            background: #d32f2f;
            box-shadow: 0 2px 8px rgba(229, 57, 53, 0.3);
        }
        
        .view-pdf-btn {
            background: var(--primary);
            color: white;
            width: 100%;
            margin-bottom: 8px;
        }
        
        .view-pdf-btn:hover {
            background: var(--primary-dark);
            box-shadow: 0 2px 8px rgba(25, 118, 210, 0.3);
        }
        
        /* Enhanced Modal - inspired by 2025 trends */
        .modal {
            display: none;
            position: fixed;
            z-index: 100;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.4);
            align-items: center;
            justify-content: center;
            opacity: 0;
            transition: opacity 0.3s;
        }
        
        .modal.active {
            display: flex;
            opacity: 1;
        }
        
        .modal-content {
            background: var(--card-bg);
            border-radius: var(--radius);
            width: 90%;
            max-width: 480px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.15);
            overflow: hidden;
            transform: scale(0.9);
            transition: transform 0.3s;
        }
        
        .modal.active .modal-content {
            transform: scale(1);
        }
        
        .modal-header {
            padding: 24px 24px 0;
            text-align: center;
        }
        
        .modal-header h3 {
            font-size: 1.8rem;
            font-weight: 700;
            color: var(--primary-dark);
            margin-bottom: 8px;
        }
        
        .modal-body {
            padding: 16px 24px;
            text-align: center;
        }
        
        .modal-body p {
            font-size: 1.1rem;
            margin-bottom: 16px;
        }
        
        .modal-illustration {
            margin: 20px auto;
            width: 120px;
            height: 120px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        
        .modal-illustration img {
            width: 100%;
            height: 100%;
            object-fit: contain;
        }
        
        .modal-actions {
            padding: 0 24px 24px;
            display: flex;
            gap: 16px;
        }
        
        /* Toast notifications - 2025 trend */
        .toast {
            position: fixed;
            top: 24px;
            right: 24px;
            background: var(--card-bg);
            color: var(--text-main);
            padding: 16px 24px;
            border-radius: var(--radius-sm);
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            font-size: 1rem;
            font-weight: 600;
            z-index: 200;
            opacity: 0;
            transform: translateY(-20px);
            transition: opacity 0.3s, transform 0.3s;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .toast.show {
            opacity: 1;
            transform: translateY(0);
        }
        
        .toast-icon {
            width: 24px;
            height: 24px;
            background: var(--success-light);
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            color: var(--success);
        }
        
        /* Empty state styling */
        .empty-state {
            grid-column: 1 / -1;
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-illustration {
            width: 180px;
            margin: 0 auto 24px;
            opacity: 0.8;
        }
        
        .empty-state h3 {
            font-size: 1.6rem;
            font-weight: 700;
            margin-bottom: 12px;
            color: var(--primary-dark);
        }
        
        .empty-state p {
            color: var(--text-secondary);
            font-size: 1.1rem;
            max-width: 500px;
            margin: 0 auto;
        }
        
        /* Responsive design */
        @media (max-width: 768px) {
            .container {
                grid-template-columns: 1fr;
                padding: 16px;
            }
            
            .modal-content {
                width: 95%;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h2>Receptionist Applications</h2>
        <p class="subtitle">Review and manage pending applications</p>
    </div>
    
    <div class="container" id="cardsContainer">
    <?php
    $query = "SELECT id, first_name, last_name, email, created_at, hospital_id_proof 
              FROM receptionist WHERE status = 'pending'";
    $result = mysqli_query($conn, $query);

    if ($result && mysqli_num_rows($result) > 0) {
        while ($row = mysqli_fetch_assoc($result)) {
            $first_name = htmlspecialchars($row['first_name']);
            $last_name = htmlspecialchars($row['last_name']);
            $email = htmlspecialchars($row['email']);
            $created_at = htmlspecialchars($row['created_at']);
            $id = intval($row['id']);
            $hospital_id_proof_path = "../receptionist/" . htmlspecialchars($row['hospital_id_proof']);
            $file_extension = strtolower(pathinfo($hospital_id_proof_path, PATHINFO_EXTENSION));
            
            // Format date and time to be more readable
            $date_obj = new DateTime($created_at);
            $formatted_date = $date_obj->format('F j, Y');
            $formatted_time = $date_obj->format('h:i A');
            
            echo "<div class='card' data-id='{$id}'>
                    <div class='card-header'>
                        <div class='image-container'>";
            
            if (in_array($file_extension, ['jpg', 'jpeg', 'png', 'gif'])) {
                echo "<img src='{$hospital_id_proof_path}' alt='ID Image' loading='lazy'>";
            } else {
                echo "<div class='image-placeholder'>
                        <svg xmlns='http://www.w3.org/2000/svg' width='80' height='80' viewBox='0 0 24 24' fill='none' stroke='#1976d2' stroke-width='1' stroke-linecap='round' stroke-linejoin='round'><path d='M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z'></path><polyline points='14 2 14 8 20 8'></polyline><line x1='16' y1='13' x2='8' y2='13'></line><line x1='16' y1='17' x2='8' y2='17'></line><polyline points='10 9 9 9 8 9'></polyline></svg>
                      </div>";
            }
            
            echo "<div class='image-overlay'>
                    <h4>{$first_name} {$last_name}</h4>
                  </div>
                </div>
              </div>
              <div class='card-body'>
                <div class='info-grid'>
                  <div class='info-label'>Email:</div>
                  <div class='info-value'>{$email}</div>
                  <div class='info-label'>Applied On:</div>
                  <div class='info-value'>{$formatted_date} at {$formatted_time}</div>
                </div>";
            
            if ($file_extension === 'pdf') {
                echo "<div class='id-proof'>
                        <a href='{$hospital_id_proof_path}' target='_blank'><button class='view-pdf-btn'>
                            <svg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'></path><circle cx='12' cy='12' r='3'></circle></svg>
                            View ID Document
                          </button></a>
                      </div>";
            }
            
            echo "</div>
                  <div class='card-actions'>
                    <button class='approve-btn' onclick=\"showModal('receptionist', {$id}, 'approved')\">
                        <svg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M22 11.08V12a10 10 0 1 1-5.93-9.14'></path><polyline points='22 4 12 14.01 9 11.01'></polyline></svg>
                        Approve
                    </button>
                    <button class='reject-btn' onclick=\"showModal('receptionist', {$id}, 'rejected')\">
                        <svg xmlns='http://www.w3.org/2000/svg' width='20' height='20' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'></circle><line x1='15' y1='9' x2='9' y2='15'></line><line x1='9' y1='9' x2='15' y2='15'></line></svg>
                        Reject
                    </button>
                  </div>
                </div>";
        }
    } else {
        echo "<div class='empty-state'>
                <img src='https://cdn-icons-png.flaticon.com/512/4076/4076549.png' alt='No applications' class='empty-illustration'>
                <h3>No Pending Applications</h3>
                <p>You're all caught up! There are no applications waiting for your review.</p>
              </div>";
    }
    ?>
    </div>

    <!-- Enhanced Modal Design -->
    <div class="modal" id="confirmationModal" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
        <div class="modal-content">
            <div class="modal-header">
                <h3 id="modalTitle">Confirm Action</h3>
            </div>
            <div class="modal-body">
                <div class="modal-illustration" id="modalIllustration">
                    <!-- Illustration will be added via JavaScript -->
                </div>
                <p id="modalMessage"></p>
            </div>
            <div class="modal-actions">
                <button id="confirmYes" class="approve-btn">Yes, Confirm</button>
                <button id="confirmNo" class="reject-btn">Cancel</button>
            </div>
        </div>
    </div>
    
    <!-- Toast notification -->
    <div class="toast" id="toast">
        <div class="toast-icon">
            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
        </div>
        <span id="toastMessage"></span>
    </div>

    <script>
    // Modal logic with enhanced visuals
    let actionType = "", recordId = "", statusType = "";
    
    function showModal(type, id, status) {
        actionType = type;
        recordId = id;
        statusType = status;
        
        const modalTitle = document.getElementById("modalTitle");
        const modalMessage = document.getElementById("modalMessage");
        const modalIllustration = document.getElementById("modalIllustration");
        
        if (status === 'approved') {
            modalTitle.innerText = "Approve Application";
            modalMessage.innerText = "Are you sure you want to approve this application? The applicant will be granted access to the system.";
            modalIllustration.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#43a047" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>`;
        } else {
            modalTitle.innerText = "Reject Application";
            modalMessage.innerText = "Are you sure you want to reject this application? This action cannot be undone.";
            modalIllustration.innerHTML = `<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80" viewBox="0 0 24 24" fill="none" stroke="#e53935" stroke-width="1" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line></svg>`;
        }
        
        document.getElementById("confirmationModal").classList.add("active");
        document.getElementById("confirmYes").focus();
    }
    
    document.getElementById("confirmYes").onclick = function () {
        document.getElementById("confirmationModal").classList.remove("active");
        
        // AJAX POST
        const formData = new FormData();
        formData.append('action', 'update_status');
        formData.append('type', actionType);
        formData.append('id', recordId);
        formData.append('status', statusType);

        fetch(window.location.href, {
            method: 'POST',
            body: formData
        })
        .then(res => res.text())
        .then(msg => {
            showToast(statusType === 'approved' ? 
                      "Application approved successfully!" : 
                      "Application rejected successfully!");
                      
            // Remove card from DOM instead of reload
            const card = document.querySelector(`.card[data-id='${recordId}']`);
            if (card) {
                card.style.transform = "translateX(100px)";
                card.style.opacity = "0";
                setTimeout(() => {
                    card.remove();
                    
                    // If no more cards, show empty state
                    if (document.querySelectorAll('.card').length === 0) {
                        document.getElementById('cardsContainer').innerHTML = `
                        <div class='empty-state'>
                            <img src='https://cdn-icons-png.flaticon.com/512/4076/4076549.png' alt='No applications' class='empty-illustration'>
                            <h3>No Pending Applications</h3>
                            <p>You're all caught up! There are no applications waiting for your review.</p>
                        </div>`;
                    }
                }, 300);
            }
        });
    };
    
    document.getElementById("confirmNo").onclick = function () {
        document.getElementById("confirmationModal").classList.remove("active");
    };
    
    window.onclick = function (event) {
        if (event.target === document.getElementById("confirmationModal")) {
            document.getElementById("confirmationModal").classList.remove("active");
        }
    };

    // Toast notification function
    function showToast(message) {
        const toast = document.getElementById('toast');
        const toastMessage = document.getElementById('toastMessage');
        toastMessage.textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), 3000);
    }
    </script>
</body>
</html>
