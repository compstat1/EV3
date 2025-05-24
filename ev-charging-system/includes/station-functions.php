<?php
/**
 * Station related functions
 */

/**
 * Get all stations
 * 
 * @param bool $activeOnly If true, return only active stations
 * @return array Array of stations
 */
function getAllStations($activeOnly = true) {
    $sql = "SELECT * FROM stations";
    $params = [];
    
    
    
    $sql .= " ORDER BY address_street";
    
    return fetchAll($sql, $params);
}

/**
 * Get station details
 * 
 * @param int $stationId Station ID
 * @return array|null Station details or null if not found
 */
function getStationDetails($stationId) {
    return fetchOne("SELECT * FROM stations WHERE station_id = ?", [$stationId]);
}

/**
 * Get all columns for a station
 *
 * @param int $stationId Station ID
 * @return array Array of columns
 */
function getStationChargingPoints($stationId) {
    $sql = "SELECT *, charging_point_state AS status FROM charging_points WHERE station_id = ?";

    return fetchAll($sql, [$stationId]);
}

/**
 * Get charging point details
 * 
 * @param int $chargingPointId Charging point ID
 * @return array|null Charging point details or null if not found
 */
function getChargingPointDetails($chargingPointId) {
    $sql = "SELECT cp.*, s.station_id, s.name as station_name, s.address
            FROM charging_points cp
            JOIN stations s ON cp.station_id = s.station_id
            WHERE cp.charging_point_id = ?";

    return fetchOne($sql, [$chargingPointId]);
}

/**
 * Get current status of a station
 * 
 * @param int $stationId Station ID
 * @return array Station status including available columns and points
 */
function getStationStatus($stationId) {
    // Get station details
    $station = getStationDetails($stationId);

    if (!$station) {
        return null;
    }

    // Get all charging points for the station
    $points = getStationChargingPoints($stationId);

    $availablePoints = 0;
    $totalPoints = count($points);

    foreach ($points as $point) {
        if ($point['status'] === 'available') {
            $availablePoints++;
        }
    }

    return [
        'station' => $station,
        'points' => $points,
        'available_points' => $availablePoints,
        'total_points' => $totalPoints,
        'availability_percentage' => ($totalPoints > 0) ? round(($availablePoints / $totalPoints) * 100) : 0
    ];
}

/**
 * Get stations with available charging points
 *
 * @return array Array of stations with availability information
 */
function getAvailableStations() {
    $stations = getAllStations(true);
    $result = [];

    foreach ($stations as $station) {
        $status = getStationStatus($station['station_id']);

        if ($status['available_points'] > 0) {
            $result[] = [
                'id' => $station['station_id'],
                'name' => $station['address_street'] ?? 'Unknown',
                'address' => ($station['address_street'] ?? '') . ' ' . ($station['address_civic_num'] ?? ''),
                'city' => $station['address_city'] ?? 'Unknown',
                'municipality' => $station['address_municipality'] ?? 'Unknown',
                'available_points' => $status['available_points'],
                'total_points' => $status['total_points'],
                'availability_percentage' => $status['availability_percentage']
            ];
        }
    }

    return $result;
}

/**
 * Get all available charging points at a station
 * 
 * @param int $stationId Station ID
 * @return array Array of available charging points
 */
function getAvailableChargingPoints($stationId) {
    $sql = "SELECT cp.*, c.column_number, c.power_output, c.connector_type
            FROM charging_points cp
            JOIN columns c ON cp.column_id = c.id
            WHERE c.station_id = ?
            AND cp.status = 'available'
            AND c.status = 'available'
            ORDER BY c.column_number, cp.point_number";
    
    return fetchAll($sql, [$stationId]);
}

/**
 * Check if a station has any active bookings
 * 
 * @param int $stationId Station ID
 * @return bool True if the station has active bookings, false otherwise
 */
function stationHasActiveBookings($stationId) {
    $currentDate = date('Y-m-d');
    
    $sql = "SELECT COUNT(*) as count
            FROM bookings b
            JOIN charging_points cp ON b.charging_point_id = cp.id
            JOIN columns c ON cp.column_id = c.id
            WHERE c.station_id = ?
            AND b.status IN ('scheduled', 'active')
            AND (b.booking_date > ? OR 
                (b.booking_date = ? AND b.end_time >= ?))";
    
    $result = executeQuery($sql, [$stationId, $currentDate, $currentDate, date('H:i:s')]);
    $row = $result->fetch_assoc();
    
    return $row['count'] > 0;
}