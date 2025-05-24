<?php
/**
 * Booking related functions
 */

/**
 * Create a new booking
 * 
 * @param int $userId User ID
 * @param int $chargingPointId Charging point ID
 * @param string $bookingDate Booking date (Y-m-d format)
 * @param string $startTime Start time (H:i format)
 * @param string $endTime End time (H:i format)
 * @return int|bool Booking ID on success, false on failure
 */
function createBooking($userId, $chargingPointId, $bookingDate, $startTime, $endTime) {
    // Check if the time slot is available
    if (!isTimeSlotAvailable($chargingPointId, $bookingDate, $startTime, $endTime)) {
        return false;
    }
    
    // Insert booking data
    $bookingData = [
        'user_id' => $userId,
        'charging_point_id' => $chargingPointId,
        'booking_date' => $bookingDate,
        'start_time' => $startTime,
        'end_time' => $endTime,
        'status' => 'scheduled'
    ];
    
    $bookingId = insert('bookings', $bookingData);
    
    if ($bookingId) {
        // Update charging point status to reserved
        update('charging_points', ['status' => 'reserved'], 'id = ?', [$chargingPointId]);
        
        // Create notification for the user
        $message = "You have successfully booked a charging session for " . 
                  formatDate($bookingDate) . " at " . formatTime($startTime) . 
                  ". Please arrive on time to avoid cancellation.";
        createNotification($userId, $message, 'booking');
        
        return $bookingId;
    }
    
    return false;
}

/**
 * Cancel a booking
 * 
 * @param int $bookingId Booking ID
 * @param int $userId User ID (for verification)
 * @return bool True on success, false on failure
 */
function cancelBooking($bookingId, $userId) {
    // Verify that the booking belongs to the user
    $booking = fetchOne("SELECT * FROM bookings WHERE id = ? AND user_id = ?", [$bookingId, $userId]);
    
    if (!$booking) {
        return false; // Booking not found or doesn't belong to the user
    }
    
    // Check if the booking can be cancelled (not active or completed)
    if ($booking['status'] !== 'scheduled') {
        return false; // Booking can't be cancelled
    }
    
    // Update booking status
    $updated = update('bookings', ['status' => 'cancelled'], 'id = ?', [$bookingId]);
    
    if ($updated) {
        // Update charging point status to available
        update('charging_points', ['status' => 'available'], 'id = ?', [$booking['charging_point_id']]);
        
        // Create notification for the user
        $message = "Your booking for " . formatDate($booking['booking_date']) . 
                  " at " . formatTime($booking['start_time']) . " has been cancelled.";
        createNotification($userId, $message, 'booking');
        
        return true;
    }
    
    return false;
}

/**
 * Get booking details
 * 
 * @param int $bookingId Booking ID
 * @return array|null Booking details or null if not found
 */
function getBookingDetails($bookingId) {
    $sql = "SELECT b.*, cp.id as charging_point_id, cp.point_number, 
                  c.column_number, c.power_output, c.connector_type,
                  s.id as station_id, s.name as station_name, s.address,
                  u.name as user_name, u.email as user_email
            FROM bookings b
            JOIN charging_points cp ON b.charging_point_id = cp.id
            JOIN columns c ON cp.column_id = c.id
            JOIN stations s ON c.station_id = s.id
            JOIN users u ON b.user_id = u.id
            WHERE b.id = ?";
    
    return fetchOne($sql, [$bookingId]);
}

/**
 * Get current and upcoming bookings for a user
 * 
 * @param int $userId User ID
 * @return array Array of current and upcoming bookings
 */
function getUserUpcomingBookings($userId) {
    $currentDate = date('Y-m-d');
    $currentTime = date('H:i:s');
    
    $sql = "SELECT b.*, cp.id as charging_point_id, cp.point_number, 
                  c.column_number, s.name as station_name, s.address
            FROM bookings b
            JOIN charging_points cp ON b.charging_point_id = cp.id
            JOIN columns c ON cp.column_id = c.id
            JOIN stations s ON c.station_id = s.id
            WHERE b.user_id = ? 
            AND b.status IN ('scheduled', 'active')
            AND (b.booking_date > ? OR (b.booking_date = ? AND b.end_time >= ?))
            ORDER BY b.booking_date, b.start_time";
    
    return fetchAll($sql, [$userId, $currentDate, $currentDate, $currentTime]);
}

/**
 * Start a charging session
 * 
 * @param int $bookingId Booking ID
 * @return int|bool Charging log ID on success, false on failure
 */
function startChargingSession($bookingId) {
    // Get booking details
    $booking = getBookingDetails($bookingId);
    
    if (!$booking || $booking['status'] !== 'scheduled') {
        return false;
    }
    
    // Update booking status
    $updated = update('bookings', ['status' => 'active'], 'id = ?', [$bookingId]);
    
    if (!$updated) {
        return false;
    }
    
    // Update charging point status
    update('charging_points', ['status' => 'in_use'], 'id = ?', [$booking['charging_point_id']]);
    
    // Create charging log
    $logData = [
        'booking_id' => $bookingId,
        'user_id' => $booking['user_id'],
        'charging_point_id' => $booking['charging_point_id'],
        'start_time' => date('Y-m-d H:i:s'),
        'status' => 'in_progress'
    ];
    
    return insert('charging_logs', $logData);
}

/**
 * End a charging session
 * 
 * @param int $chargingLogId Charging log ID
 * @param float $energyConsumed Energy consumed in kWh
 * @return bool True on success, false on failure
 */
function endChargingSession($chargingLogId, $energyConsumed) {
    // Get charging log details
    $log = fetchOne("SELECT * FROM charging_logs WHERE id = ?", [$chargingLogId]);
    
    if (!$log || $log['status'] !== 'in_progress') {
        return false;
    }
    
    // Calculate cost
    $cost = calculateChargingCost($energyConsumed);
    
    // Update charging log
    $logData = [
        'end_time' => date('Y-m-d H:i:s'),
        'energy_consumed' => $energyConsumed,
        'cost' => $cost,
        'status' => 'completed'
    ];
    
    $updated = update('charging_logs', $logData, 'id = ?', [$chargingLogId]);
    
    if (!$updated) {
        return false;
    }
    
    // Update booking status
    update('bookings', ['status' => 'completed'], 'id = ?', [$log['booking_id']]);
    
    // Update charging point status
    update('charging_points', ['status' => 'available'], 'id = ?', [$log['charging_point_id']]);
    
    // Create notification for the user
    $message = "Your charging session has ended. You consumed " . 
              formatEnergy($energyConsumed) . " at a cost of " . 
              formatCurrency($cost) . ". Thank you for using our service.";
    createNotification($log['user_id'], $message, 'system');
    
    return true;
}

/**
 * Get active charging session for a booking
 * 
 * @param int $bookingId Booking ID
 * @return array|null Charging session details or null if not found
 */
function getActiveChargingSession($bookingId) {
    $sql = "SELECT * FROM charging_logs 
            WHERE booking_id = ? AND status = 'in_progress'";
    
    return fetchOne($sql, [$bookingId]);
}

/**
 * Check if a user has an active booking at a specific station
 * 
 * @param int $userId User ID
 * @param int $stationId Station ID
 * @return array|null Active booking details or null if not found
 */
function getUserActiveBookingAtStation($userId, $stationId) {
    $currentDate = date('Y-m-d');
    $currentTime = date('H:i:s');
    
    $sql = "SELECT b.*, cp.id as charging_point_id, cp.point_number, 
                  c.column_number, c.power_output, c.connector_type
            FROM bookings b
            JOIN charging_points cp ON b.charging_point_id = cp.id
            JOIN columns c ON cp.column_id = c.id
            WHERE b.user_id = ? 
            AND c.station_id = ?
            AND b.status IN ('scheduled', 'active')
            AND b.booking_date = ?
            AND b.start_time <= ?
            AND b.end_time >= ?
            LIMIT 1";
    
    return fetchOne($sql, [$userId, $stationId, $currentDate, $currentTime, $currentTime]);
}

/**
 * Find all bookings that need to be processed for auto-expiration
 * 
 * @return array Array of bookings that need to be processed
 */
function getBookingsForExpirationCheck() {
    $currentDate = date('Y-m-d');
    $currentTime = date('H:i:s');
    
    $sql = "SELECT b.*, u.id as user_id
            FROM bookings b
            JOIN users u ON b.user_id = u.id
            WHERE b.status = 'scheduled'
            AND b.booking_date = ?
            AND b.start_time <= ?";
    
    return fetchAll($sql, [$currentDate, $currentTime]);
}