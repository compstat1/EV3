<?php
// Set page title
$pageTitle = 'Register';

// Include configuration
require_once dirname(__DIR__) . '/config/config.php';
require_once INCLUDES_PATH . 'auth-functions.php';

// Check if user is already logged in
if (isLoggedIn()) {
    redirect('dashboard.php');
}

// Check for form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Validate input
    $name = sanitizeInput($_POST['name'] ?? '');
    $email = sanitizeInput($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';
    $csrf = $_POST['csrf_token'] ?? '';
    
    // Validate CSRF token
    if (!validateCsrfToken($csrf)) {
        setFlashMessage('error', 'Invalid request. Please try again.');
        redirect('register.php');
    }
    
    // Validate required fields
    if (empty($name) || empty($email) || empty($password) || empty($confirm_password)) {
        setFlashMessage('error', 'Please fill in all required fields.');
    } elseif ($password !== $confirm_password) {
        setFlashMessage('error', 'Passwords do not match.');
    } elseif (!isPasswordStrong($password)) {
        setFlashMessage('error', 'Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.');
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        setFlashMessage('error', 'Please enter a valid email address.');
    } else {
        // Attempt to register
        $userId = registerUser($name, $email, $password);

        if ($userId) {
            // Automatically log the user in
            loginUser($email, $password);

            // Redirect to dashboard
            setFlashMessage('success', 'Registration successful! Welcome to EV Charging Station Management System.');
            redirect('dashboard.php');
        } else {
            setFlashMessage('error', 'Email address already exists. Please use a different email or login.');
        }
    }
}

// Generate CSRF token
$csrfToken = generateCsrfToken();

// Include header
require_once dirname(__DIR__) . '/includes/header.php';
?>

<div class="auth-container">
    <div class="auth-card">
        <div class="auth-header">
            <h2>Create a New Account</h2>
            <p>Fill in your details to register</p>
        </div>
        
        <div class="auth-body">
            <form method="POST" action="<?= APP_URL ?>/pages/register.php" class="needs-validation">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                
                <div class="form-group">
                    <label for="name" class="form-label">Full Name</label>
                    <input type="text" id="name" name="name" class="form-control" required autofocus
                           value="<?= isset($_POST['name']) ? htmlspecialchars($_POST['name']) : '' ?>">
                </div>
                
                <div class="form-group">
                    <label for="email" class="form-label">Email Address</label>
                    <input type="email" id="email" name="email" class="form-control" required
                           value="<?= isset($_POST['email']) ? htmlspecialchars($_POST['email']) : '' ?>">
                </div>
                
                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" id="password" name="password" class="form-control" required
                           pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*]).{8,}">
                    <small class="form-text">
                        Password must be at least 8 characters long and include uppercase, lowercase, 
                        number, and special character.
                    </small>
                </div>
                
                <div class="form-group mb-4">
                    <label for="confirm_password" class="form-label">Confirm Password</label>
                    <input type="password" id="confirm_password" name="confirm_password" class="form-control" required>
                </div>
                
                <div class="form-group">
                    <button type="submit" class="btn btn-primary btn-block">
                        <i class="fas fa-user-plus"></i> Register
                    </button>
                </div>
            </form>
        </div>
        
        <div class="auth-footer">
            <p>Already have an account? <a href="<?= APP_URL ?>/pages/login.php">Login</a></p>
        </div>
    </div>
</div>

<style>
    .auth-container {
        display: flex;
        align-items: center;
        justify-content: center;
        min-height: calc(100vh - var(--header-height) - var(--footer-height) - var(--space-16));
        padding: var(--space-6) 0;
    }
    
    .auth-card {
        width: 100%;
        max-width: 450px;
        background-color: var(--white);
        border-radius: var(--radius-lg);
        box-shadow: var(--shadow-lg);
        overflow: hidden;
    }
    
    .auth-header {
        padding: var(--space-6);
        background-color: var(--primary);
        color: var(--white);
        text-align: center;
    }
    
    .auth-header h2 {
        font-size: 1.5rem;
        font-weight: 600;
        margin-bottom: var(--space-2);
    }
    
    .auth-header p {
        opacity: 0.9;
        margin-bottom: 0;
    }
    
    .auth-body {
        padding: var(--space-6);
    }
    
    .auth-footer {
        padding: var(--space-4) var(--space-6);
        border-top: 1px solid var(--gray-200);
        text-align: center;
        background-color: var(--gray-200);
    }
    
    .auth-footer p {
        margin-bottom: 0;
        color: var(--gray-600);
    }
</style>

<?php
// Include footer
require_once dirname(__DIR__) . '/includes/footer.php';
?>