<?php

require_once __DIR__ . '/../includes/station-functions.php';

// Set page title
$pageTitle = 'Charging Stations';

// Include configuration
require_once dirname(__DIR__) . '/config/config.php';

// Get available stations
$stations = getAllStations(true);

// Include header
require_once dirname(__DIR__) . '/includes/header.php';


?>

<div class="container">
    <div class="page-header">
        <h1 class="page-title">Charging Stations</h1>
        <p class="page-subtitle">Find and book available charging stations</p>
    </div>
    
    
    <div class="station-filter-container">
        <div class="card">
            <div class="card-body">
                <form id="station-filter-form" class="form-inline">
                    <div class="form-group">
                        <label for="location">Location</label>
                        <input type="text" id="location" name="location" class="form-control" placeholder="City or zip code">
                    </div>
                    
                    <div class="form-group">
                        <label for="connector-type">Connector Type</label>
                        <select id="connector-type" name="connector_type" class="form-control form-select">
                            <option value="">All Connectors</option>
                            <option value="Type1">Type 1</option>
                            <option value="Type2">Type 2</option>
                            <option value="CCS">CCS</option>
                            <option value="CHAdeMO">CHAdeMO</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="power-output">Min Power</label>
                        <select id="power-output" name="power_output" class="form-control form-select">
                            <option value="">Any Power</option>
                            <option value="7.4">7.4 kW+</option>
                            <option value="11">11 kW+</option>
                            <option value="22">22 kW+</option>
                        </select>
                    </div>
                    
                    <div class="form-group">
                        <label for="availability">Availability</label>
                        <select id="availability" name="availability" class="form-control form-select">
                            <option value="">Any Status</option>
                            <option value="available" selected>Available Now</option>
                            <option value="soon">Available Soon</option>
                        </select>
                    </div>
                    
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-filter"></i> Filter Stations
                    </button>
                </form>
            </div>
        </div>
    </div>
    
    <div class="station-map-container">
        <div class="card">
            <div class="card-body p-0">
                <div id="station-map" class="station-map">
                    <div class="rounded-iframe-container">
                        <iframe src="https://www.google.com/maps/embed?pb=!1m14!1m12!1m3!1d27116.334422518736!2d8.93859901112898!3d44.407442547269085!2m3!1f0!2f0!3f0!3m2!1i1024!2i768!4f13.1!5e0!3m2!1sit!2sit!4v1747332788287!5m2!1sit!2sit" width="600" height="450" style="border:0;" allowfullscreen="" loading="lazy" referrerpolicy="no-referrer-when-downgrade"></iframe>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <div class="section-header">
        <h2>Available Stations</h2>
        <p>Found <?= count($stations) ?> charging stations</p>
    </div>
    
    <div class="station-grid">
        <?php foreach ($stations as $station): ?>
            <?php $status = getStationStatus($station['station_id']); ?>
            <div class="station-card">
                <div class="station-header">
                    <h3 class="station-title"><?= htmlspecialchars($station['address_street']) ?></h3>
                    <p class="station-address">
                    <h3><?= htmlspecialchars($stationStatus['station']['station_street'] ?? 'N/A') ?></h3>
                    <p><strong>Address:</strong> <?= htmlspecialchars(($stationStatus['station']['address_street'] ?? '') . ' ' . ($stationStatus['station']['address_civic_num'] ?? '')) ?></p>
                    <p><strong>City:</strong> <?= htmlspecialchars($stationStatus['station']['address_city'] ?? 'N/A') ?></p>
                    <p><strong>Municipality:</strong> <?= htmlspecialchars($stationStatus['station']['address_municipality'] ?? 'N/A') ?></p>
                    <p><strong>ZIP Code:</strong> <?= htmlspecialchars($stationStatus['station']['address_zipcode'] ?? 'N/A') ?></p>
                    </p>
                </div>
                <div class="station-body">
                    <div class="station-availability">
                        <span><?= $status['available_points'] ?> of <?= $status['total_points'] ?> available</span>
                        <div class="availability-bar">
                            <div class="availability-progress" 
                                 data-percentage="<?= $status['availability_percentage'] ?>" 
                                 style="width: <?= $status['availability_percentage'] ?>%"></div>
                        </div>
                        <span><?= round($status['availability_percentage']) ?>%</span>
                    </div>
                    
                    <div class="columns-grid">
                        <?php if (!empty($stationStatus['points'])): ?>
                            <h4>Charging Points</h4>
                            <ul>
                                <?php foreach ($stationStatus['points'] as $point): ?>
                                    <li>
                                        ID: <?= htmlspecialchars($point['charging_point_id'] ?? 'N/A') ?> -
                                        Status: <?= ucfirst(htmlspecialchars($point['status'] ?? 'unknown')) ?>
                                    </li>
                                <?php endforeach; ?>
                            </ul>
                        <?php else: ?>
                            <p>No charging points available.</p>
                        <?php endif; ?>
                    </div>
                </div>
                <div class="station-footer">
                    <div class="station-features">
                        <span class="badge badge-light" title="Power Output">
                            <i class="fas fa-bolt"></i> 7.4-22kW
                        </span>
                        <span class="badge badge-light" title="Connector Types">
                            <i class="fas fa-plug"></i> Type2, CCS
                        </span>
                    </div>
                    <div class="station-actions">
                        <a href="<?= APP_URL ?>/pages/station-details.php?id=<?= $station['station_id'] ?>" class="btn btn-outline btn-sm view-details-btn" data-station-id="<?= $station['station_id'] ?>">
                            <i class="fas fa-info-circle"></i> Details
                        </a>
                        <a href="<?= APP_URL ?>/pages/book.php?station_id=<?= $station['station_id'] ?>" class="btn btn-primary btn-sm book-now-btn" data-station-id="<?= $station['station_id'] ?>">
                            <i class="fas fa-calendar-check"></i> Book
                        </a>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
</div>

<style>
    .page-header {
        margin-bottom: var(--space-6);
    }
    
    .page-title {
        font-size: 2rem;
        font-weight: 700;
        color: var(--gray-900);
        margin-bottom: var(--space-2);
    }
    
    .page-subtitle {
        font-size: 1.1rem;
        color: var(--gray-600);
    }
    
    .station-filter-container {
        margin-bottom: var(--space-6);
    }
    
    .station-map-container {
        margin-bottom: var(--space-6);
    }
    
    .station-map {
        height: 400px;
        background-color: var(--gray-100);
        border-radius: var(--radius-lg);
        overflow: hidden;
    }
    
    .section-header {
        margin-bottom: var(--space-6);
    }
    
    .section-header h2 {
        font-size: 1.5rem;
        font-weight: 600;
        color: var(--gray-900);
        margin-bottom: var(--space-1);
    }
    
    .section-header p {
        color: var(--gray-600);
    }

    .rounded-iframe-container {
        display: block;
        width: 75vw;
        max-width: 100%;
        border-radius: 20px;
        overflow: hidden;
        margin: 25px auto;
        height: 60vh;
    }
    
    .rounded-iframe-container iframe {
        width: 100%;
        height: 100%;
        display: block;
        border: none;
    }
    
    /* Form inline for filters */
    #station-filter-form {
        display: flex;
        flex-wrap: wrap;
        gap: var(--space-4);
    }
    
    #station-filter-form .form-group {
        flex: 1;
        min-width: 200px;
    }
    
    #station-filter-form button {
        margin-top: 1.85rem;
    }
    
    @media (max-width: 768px) {
        #station-filter-form button {
            margin-top: var(--space-3);
            width: 100%;
        }
    }
    
    /* Station features */
    .station-features {
        display: flex;
        gap: var(--space-2);
    }
    
    /* Station actions */
    .station-actions {
        display: flex;
        gap: var(--space-2);
    }
</style>

<!-- Include required scripts -->
<script src="<?= APP_URL ?>/assets/js/bookings.js"></script>

<?php
// Include footer
require_once dirname(__DIR__) . '/includes/footer.php';
?>