<?php
/**
 * Authentication related functions
 */

/**
 * Register a new user
 *
 * @param string $name User's name
 * @param string $email User's email
 * @param string $password User's password
 * @return int|bool User ID on success, false on failure
 */
function registerUser($name, $email, $password) {
    // Check if email already exists
    $existingUser = fetchOne("SELECT user_id FROM users WHERE email = ?", [$email]);

    if ($existingUser) {
        return false; // Email already exists
    }

    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert user data
    $userData = [
        'name' => $name,
        'email' => $email,
        'password' => $hashedPassword
    ];

    return insert('Users', $userData);
}

/**
 * Login a user
 *
 * @param string $email User's email
 * @param string $password User's password
 * @return bool True on success, false on failure
 */
function loginUser($email, $password) {
    // Get user by email
    $user = fetchOne("SELECT * FROM users WHERE email = ?", [$email]);

    if (!$user) {
        return false; // User not found
    }

    // Verify password
    if (password_verify($password, $user['password'])) {
        // Set user session
        $_SESSION['user_id'] = $user['user_id'];
        $_SESSION['user_name'] = $user['name'];
        $_SESSION['user_email'] = $user['email'];

        return true;
    }

    return false; // Invalid password
}

/**
 * Change user password
 *
 * @param int $userId User ID
 * @param string $currentPassword Current password
 * @param string $newPassword New password
 * @return bool True on success, false on failure
 */
function changePassword($userId, $currentPassword, $newPassword) {
    // Get user data
    $user = fetchOne("SELECT * FROM users WHERE user_id = ?", [$userId]);

    if (!$user) {
        return false; // User not found
    }

    // Verify current password
    if (!password_verify($currentPassword, $user['password'])) {
        return false; // Current password is incorrect
    }

    // Hash new password
    $hashedNewPassword = password_hash($newPassword, PASSWORD_DEFAULT);

    // Update password
    return update('Users', ['password' => $hashedNewPassword], 'user_id = ?', [$userId]);
}

/**
 * Update user profile
 *
 * @param int $userId User ID
 * @param array $data Profile data to update
 * @return bool True on success, false on failure
 */
function updateUserProfile($userId, $data) {
    // Filter data to ensure only allowed fields are updated
    $allowedFields = ['name', 'email'];
    $filteredData = array_intersect_key($data, array_flip($allowedFields));

    // If updating email, check if it's already taken by another user
    if (isset($filteredData['email'])) {
        $existingUser = fetchOne("SELECT user_id FROM users WHERE email = ? AND user_id != ?",
            [$filteredData['email'], $userId]);

        if ($existingUser) {
            return false; // Email already taken
        }
    }

    return update('Users', $filteredData, 'user_id = ?', [$userId]);
}

/**
 * Validate password strength
 *
 * @param string $password Password to validate
 * @return bool True if password is strong enough, false otherwise
 */
function isPasswordStrong($password) {
    // Password must be at least 8 characters long
    if (strlen($password) < 8) {
        return false;
    }

    // Password must contain at least one uppercase letter
    if (!preg_match('/[A-Z]/', $password)) {
        return false;
    }

    // Password must contain at least one lowercase letter
    if (!preg_match('/[a-z]/', $password)) {
        return false;
    }

    // Password must contain at least one number
    if (!preg_match('/[0-9]/', $password)) {
        return false;
    }

    // Password must contain at least one special character
    if (!preg_match('/[!@#$%^&*(),.?":{}|<>]/', $password)) {
        return false;
    }

    return true;
}

/**
 * Get user's booking history
 *
 * @param int $userId User ID
 * @param int $limit Maximum number of records to return (default: 10)
 * @param int $offset Offset for pagination (default: 0)
 * @return array Array of booking history records
 */
function getUserBookingHistory($userId, $limit = 10, $offset = 0) {
    $sql = "SELECT b.*, cp.charging_point_id, cp.slots_num,
                  s.address_street, s.address_city,
                  cl.energy_consumed, cl.cost
            FROM bookings b
            LEFT JOIN charging_points cp ON b.charging_point_id = cp.charging_point_id
            LEFT JOIN stations s ON cp.station_id = s.station_id
            LEFT JOIN charging_logs cl ON b.booking_id = cl.logs_id
            WHERE b.user_id = ?
            ORDER BY b.booking_datetime DESC
            LIMIT ? OFFSET ?";

    return fetchAll($sql, [$userId, $limit, $offset]);
}

/**
 * Get user's charging statistics
 *
 * @param int $userId User ID
 * @return array Statistics including total and monthly costs and energy
 */
function getUserChargingStats($userId) {
    // Get total statistics
    $totalStats = fetchOne("SELECT 
                            COUNT(*) as total_charges,
                            SUM(energy_consumed) as total_energy,
                            SUM(cost) as total_cost
                        FROM charging_logs
                        WHERE user_id = ? AND end_time IS NOT NULL",
        [$userId]);

    // Get monthly statistics (current month)
    $currentMonth = date('Y-m');
    $monthlyStats = fetchOne("SELECT 
                            SUM(energy_consumed) as monthly_energy,
                            SUM(cost) as monthly_cost
                        FROM charging_logs
                        WHERE user_id = ? 
                        AND end_time IS NOT NULL
                        AND DATE_FORMAT(start_time, '%Y-%m') = ?",
        [$userId, $currentMonth]);

    // Combine statistics
    return [
        'total' => [
            'charges' => $totalStats['total_charges'] ?? 0,
            'energy' => $totalStats['total_energy'] ?? 0,
            'cost' => $totalStats['total_cost'] ?? 0
        ],
        'monthly' => [
            'energy' => $monthlyStats['monthly_energy'] ?? 0,
            'cost' => $monthlyStats['monthly_cost'] ?? 0
        ]
    ];
}