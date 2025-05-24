/**
 * Bookings JavaScript file
 * Handles booking-related functionality
 */

document.addEventListener('DOMContentLoaded', function() {
    initializeBookingForm();
    initializeBookingFilters();
    setupBookingCancellation();
    setupChargingControls();
    initializeAvailabilityChecker();
});

/**
 * Initialize the booking form
 */
function initializeBookingForm() {
    const bookingForm = document.getElementById('booking-form');
    if (!bookingForm) return;
    
    // Station selection affects available charging points
    const stationSelect = document.getElementById('station-id');
    const chargingPointSelect = document.getElementById('charging-point-id');
    const dateInput = document.getElementById('booking-date');
    const startTimeInput = document.getElementById('start-time');
    const endTimeInput = document.getElementById('end-time');
    const durationInput = document.getElementById('duration');
    const submitButton = document.querySelector('#booking-form button[type="submit"]');
    
    if (stationSelect) {
        stationSelect.addEventListener('change', function() {
            const stationId = this.value;
            if (!stationId) return;
            
            // Clear current charging points and time slots
            if (chargingPointSelect) {
                chargingPointSelect.innerHTML = '<option value="">Select a charging point</option>';
                chargingPointSelect.disabled = true;
            }
            
            if (startTimeInput) startTimeInput.disabled = true;
            if (endTimeInput) endTimeInput.disabled = true;
            if (submitButton) submitButton.disabled = true;
            
            // Show loading state
            const loadingElement = document.createElement('div');
            loadingElement.className = 'loading-indicator';
            loadingElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading charging points...';
            bookingForm.insertBefore(loadingElement, chargingPointSelect.parentNode.nextSibling);
            
            // Fetch available charging points for this station
            // In a real implementation, this would be an AJAX call
            setTimeout(() => {
                // Remove loading indicator
                loadingElement.remove();
                
                // Simulate API response
                const mockChargingPoints = [
                    { id: 1, name: 'Column 1 - Point 1', power: '7.4 kW', type: 'Type 2' },
                    { id: 2, name: 'Column 1 - Point 2', power: '7.4 kW', type: 'Type 2' },
                    { id: 3, name: 'Column 2 - Point 1', power: '11 kW', type: 'CCS' },
                    { id: 4, name: 'Column 2 - Point 2', power: '11 kW', type: 'CCS' },
                    { id: 5, name: 'Column 3 - Point 1', power: '22 kW', type: 'Type 2' },
                ];
                
                // Populate charging points dropdown
                if (chargingPointSelect) {
                    mockChargingPoints.forEach(point => {
                        const option = document.createElement('option');
                        option.value = point.id;
                        option.textContent = `${point.name} (${point.power}, ${point.type})`;
                        chargingPointSelect.appendChild(option);
                    });
                    
                    chargingPointSelect.disabled = false;
                }
            }, 500);
        });
    }
    
    // Charging point and date selection affects available time slots
    if (chargingPointSelect && dateInput) {
        function updateTimeSlots() {
            const chargingPointId = chargingPointSelect.value;
            const date = dateInput.value;
            
            if (!chargingPointId || !date) return;
            
            // Disable time inputs while loading
            if (startTimeInput) startTimeInput.disabled = true;
            if (endTimeInput) endTimeInput.disabled = true;
            if (submitButton) submitButton.disabled = true;
            
            // Show loading state
            const loadingElement = document.createElement('div');
            loadingElement.className = 'loading-indicator';
            loadingElement.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading available times...';
            const timeFieldset = document.querySelector('.time-slots-container') || startTimeInput.parentNode;
            timeFieldset.appendChild(loadingElement);
            
            // In a real implementation, this would be an AJAX call
            setTimeout(() => {
                // Remove loading indicator
                loadingElement.remove();
                
                // Simulate API response
                const mockTimeSlots = [
                    { start: '09:00', end: '10:00' },
                    { start: '10:00', end: '11:00' },
                    { start: '11:00', end: '12:00' },
                    { start: '13:00', end: '14:00' },
                    { start: '14:00', end: '15:00' },
                    { start: '15:00', end: '16:00' },
                ];
                
                // Create time slot selector
                const timeSlotContainer = document.querySelector('.time-slots-container');
                if (timeSlotContainer) {
                    timeSlotContainer.innerHTML = '<h4>Available Time Slots</h4>';
                    
                    const timeSlotGrid = document.createElement('div');
                    timeSlotGrid.className = 'time-slot-grid';
                    
                    mockTimeSlots.forEach(slot => {
                        const timeSlot = document.createElement('div');
                        timeSlot.className = 'time-slot';
                        timeSlot.textContent = `${formatTime(slot.start)} - ${formatTime(slot.end)}`;
                        timeSlot.dataset.start = slot.start;
                        timeSlot.dataset.end = slot.end;
                        
                        timeSlot.addEventListener('click', function() {
                            // Remove selected class from all time slots
                            document.querySelectorAll('.time-slot').forEach(s => s.classList.remove('selected'));
                            
                            // Add selected class to clicked time slot
                            this.classList.add('selected');
                            
                            // Update form inputs
                            if (startTimeInput) startTimeInput.value = this.dataset.start;
                            if (endTimeInput) endTimeInput.value = this.dataset.end;
                            
                            // Calculate duration
                            if (durationInput) {
                                const duration = calculateDurationInMinutes(this.dataset.start, this.dataset.end);
                                durationInput.value = duration;
                            }
                            
                            // Enable submit button
                            if (submitButton) submitButton.disabled = false;
                        });
                        
                        timeSlotGrid.appendChild(timeSlot);
                    });
                    
                    timeSlotContainer.appendChild(timeSlotGrid);
                } else {
                    // Enable time inputs
                    if (startTimeInput) startTimeInput.disabled = false;
                    if (endTimeInput) endTimeInput.disabled = false;
                }
            }, 800);
        }
        
        chargingPointSelect.addEventListener('change', updateTimeSlots);
        dateInput.addEventListener('change', updateTimeSlots);
    }
    
    // Handle form submission
    if (bookingForm) {
        bookingForm.addEventListener('submit', function(e) {
            // In a real implementation, this would be an AJAX call
            // For demo purposes, just redirect to a success page
            
            // Optionally handle validation or submission via AJAX
            // e.preventDefault();
            // submitFormAjax(this, 
            //    data => { window.location.href = 'booking-confirmation.php?id=' + data.bookingId; },
            //    error => { showNotification(error, 'error'); }
            // );
        });
    }
    
    // Calculate duration when manually selecting times
    if (startTimeInput && endTimeInput && durationInput) {
        function updateDuration() {
            const startTime = startTimeInput.value;
            const endTime = endTimeInput.value;
            
            if (startTime && endTime) {
                const duration = calculateDurationInMinutes(startTime, endTime);
                durationInput.value = duration;
            }
        }
        
        startTimeInput.addEventListener('change', updateDuration);
        endTimeInput.addEventListener('change', updateDuration);
    }
    
    // Calculate duration in minutes
    function calculateDurationInMinutes(startTime, endTime) {
        const [startHours, startMinutes] = startTime.split(':').map(Number);
        const [endHours, endMinutes] = endTime.split(':').map(Number);
        
        const startTotalMinutes = (startHours * 60) + startMinutes;
        const endTotalMinutes = (endHours * 60) + endMinutes;
        
        return endTotalMinutes - startTotalMinutes;
    }
}

/**
 * Initialize the booking filters
 */
function initializeBookingFilters() {
    const bookingFilters = document.querySelectorAll('.booking-filter');
    if (bookingFilters.length === 0) return;
    
    bookingFilters.forEach(filter => {
        filter.addEventListener('change', function() {
            const form = this.closest('form');
            if (form) {
                form.submit();
            }
        });
    });
}

/**
 * Set up booking cancellation
 */
function setupBookingCancellation() {
    const cancelButtons = document.querySelectorAll('.cancel-booking-btn');
    if (cancelButtons.length === 0) return;
    
    cancelButtons.forEach(button => {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const bookingId = this.dataset.bookingId;
            const bookingDate = this.dataset.bookingDate;
            const bookingTime = this.dataset.bookingTime;
            
            confirmAction(
                `Are you sure you want to cancel your booking for ${formatDate(bookingDate)} at ${formatTime(bookingTime)}?`,
                () => {
                    // Show loading state
                    this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Cancelling...';
                    this.disabled = true;
                    
                    // In a real implementation, this would be an AJAX call
                    setTimeout(() => {
                        // Simulate successful cancellation
                        const bookingElement = this.closest('.booking-item') || this.closest('tr');
                        if (bookingElement) {
                            bookingElement.style.opacity = '0.5';
                            bookingElement.style.textDecoration = 'line-through';
                            this.innerHTML = 'Cancelled';
                        }
                        
                        showNotification('Booking has been successfully cancelled.', 'success');
                    }, 800);
                }
            );
        });
    });
}

/**
 * Set up charging controls (start/end charging)
 */
function setupChargingControls() {
    // Start charging button
    const startButtons = document.querySelectorAll('.start-charging-btn');
    if (startButtons.length > 0) {
        startButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                
                const bookingId = this.dataset.bookingId;
                
                // Show loading state
                this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Starting...';
                this.disabled = true;
                
                // In a real implementation, this would be an AJAX call
                setTimeout(() => {
                    // Simulate successful start
                    const controlsContainer = this.closest('.booking-controls') || this.parentNode;
                    
                    // Update UI to show charging in progress
                    if (controlsContainer) {
                        controlsContainer.innerHTML = `
                            <div class="charging-status">
                                <div class="status-indicator">
                                    <div class="status-dot pulse"></div>
                                    <span>Charging in progress</span>
                                </div>
                                <div class="charging-stats">
                                    <div>Time: <span id="charging-time-${bookingId}">00:00:00</span></div>
                                    <div>Energy: <span id="charging-energy-${bookingId}">0.00 kWh</span></div>
                                    <div>Cost: <span id="charging-cost-${bookingId}">€0.00</span></div>
                                </div>
                                <button class="btn btn-danger end-charging-btn" data-booking-id="${bookingId}">
                                    <i class="fas fa-stop-circle"></i> End Charging
                                </button>
                            </div>
                        `;
                        
                        // Set up the end charging button
                        const endButton = controlsContainer.querySelector('.end-charging-btn');
                        if (endButton) {
                            setupEndChargingButton(endButton);
                        }
                        
                        // Start the charging timer and stats update
                        startChargingTimer(bookingId);
                    }
                    
                    showNotification('Charging session started successfully.', 'success');
                }, 1000);
            });
        });
    }
    
    // Set up end charging buttons that already exist
    const endButtons = document.querySelectorAll('.end-charging-btn');
    if (endButtons.length > 0) {
        endButtons.forEach(setupEndChargingButton);
    }
    
    function setupEndChargingButton(button) {
        button.addEventListener('click', function(e) {
            e.preventDefault();
            
            const bookingId = this.dataset.bookingId;
            
            confirmAction(
                'Are you sure you want to end the charging session?',
                () => {
                    // Show loading state
                    this.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Ending...';
                    this.disabled = true;
                    
                    // In a real implementation, this would be an AJAX call
                    setTimeout(() => {
                        // Get the current charging stats
                        const energyElement = document.getElementById(`charging-energy-${bookingId}`);
                        const costElement = document.getElementById(`charging-cost-${bookingId}`);
                        
                        const energy = energyElement ? parseFloat(energyElement.textContent) : 0;
                        const cost = costElement ? parseFloat(costElement.textContent.replace('€', '')) : 0;
                        
                        // Simulate successful end
                        const controlsContainer = this.closest('.booking-controls') || this.closest('.charging-status').parentNode;
                        
                        // Update UI to show charging completed
                        if (controlsContainer) {
                            controlsContainer.innerHTML = `
                                <div class="charging-completed">
                                    <div class="alert alert-success">
                                        <h4><i class="fas fa-check-circle"></i> Charging Completed</h4>
                                        <p>You have successfully charged your vehicle.</p>
                                        <div class="charging-summary">
                                            <div>Energy consumed: <strong>${energy.toFixed(2)} kWh</strong></div>
                                            <div>Total cost: <strong>€${cost.toFixed(2)}</strong></div>
                                        </div>
                                    </div>
                                </div>
                            `;
                        }
                        
                        showNotification('Charging session ended successfully.', 'success');
                    }, 1000);
                }
            );
        });
    }
    
    function startChargingTimer(bookingId) {
        const timeElement = document.getElementById(`charging-time-${bookingId}`);
        const energyElement = document.getElementById(`charging-energy-${bookingId}`);
        const costElement = document.getElementById(`charging-cost-${bookingId}`);
        
        if (!timeElement || !energyElement || !costElement) return;
        
        let seconds = 0;
        let energyRate = 0.1; // kWh per minute (simulated)
        let costRate = 0.35; // € per kWh (simulated)
        
        const timerInterval = setInterval(() => {
            seconds++;
            
            // Update time display
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = seconds % 60;
            
            timeElement.textContent = `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
            
            // Update energy and cost (every minute)
            if (seconds % 60 === 0) {
                const minutes = seconds / 60;
                const energy = minutes * energyRate;
                const cost = energy * costRate;
                
                energyElement.textContent = `${energy.toFixed(2)} kWh`;
                costElement.textContent = `€${cost.toFixed(2)}`;
            }
        }, 1000);
        
        // Store the interval ID for cleanup
        window.chargingTimers = window.chargingTimers || {};
        window.chargingTimers[bookingId] = timerInterval;
    }
}

/**
 * Initialize the availability checker
 */
function initializeAvailabilityChecker() {
    const availabilityForm = document.getElementById('availability-checker-form');
    if (!availabilityForm) return;
    
    availabilityForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const dateInput = document.getElementById('check-date');
        const timeInput = document.getElementById('check-time');
        const resultsContainer = document.getElementById('availability-results');
        
        if (!dateInput || !timeInput || !resultsContainer) return;
        
        const date = dateInput.value;
        const time = timeInput.value;
        
        if (!date || !time) {
            showNotification('Please select both date and time to check availability.', 'warning');
            return;
        }
        
        // Show loading state
        resultsContainer.innerHTML = `
            <div class="loading-indicator text-center p-4">
                <i class="fas fa-spinner fa-spin fa-2x mb-2"></i>
                <p>Checking availability...</p>
            </div>
        `;
        
        // In a real implementation, this would be an AJAX call
        setTimeout(() => {
            // Simulate API response
            const mockStations = [
                { id: 1, name: 'Downtown Charging Hub', address: '123 Main St', available: 6, total: 10 },
                { id: 2, name: 'Westside EV Station', address: '456 Park Ave', available: 3, total: 10 },
                { id: 3, name: 'Northgate Power Center', address: '789 Broadway', available: 0, total: 10 }
            ];
            
            // Display results
            resultsContainer.innerHTML = `
                <h3 class="mb-3">Available Stations for ${formatDate(date)} at ${formatTime(time)}</h3>
                <div class="station-grid">
                    ${mockStations.map(station => `
                        <div class="station-card ${station.available === 0 ? 'unavailable' : ''}">
                            <div class="station-header">
                                <h3 class="station-title">${station.name}</h3>
                                <p class="station-address">${station.address}</p>
                            </div>
                            <div class="station-body">
                                <div class="station-availability">
                                    <span>${station.available} of ${station.total} available</span>
                                    <div class="availability-bar">
                                        <div class="availability-progress" style="width: ${(station.available / station.total) * 100}%"></div>
                                    </div>
                                    <span>${Math.round((station.available / station.total) * 100)}%</span>
                                </div>
                                ${station.available > 0 ? `
                                    <a href="book.php?station_id=${station.id}&date=${date}&time=${time}" class="btn btn-primary btn-block">
                                        <i class="fas fa-calendar-check"></i> Book Now
                                    </a>
                                ` : `
                                    <button class="btn btn-secondary btn-block" disabled>
                                        <i class="fas fa-times-circle"></i> Fully Booked
                                    </button>
                                `}
                            </div>
                        </div>
                    `).join('')}
                </div>
            `;
        }, 1000);
    });
}

/**
 * Format time for display
 * 
 * @param {string} timeString Time in HH:MM format
 * @returns {string} Formatted time
 */
function formatTime(timeString) {
    if (!timeString) return '';
    
    const [hours, minutes] = timeString.split(':');
    const date = new Date();
    date.setHours(parseInt(hours, 10));
    date.setMinutes(parseInt(minutes, 10));
    
    return date.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
        hour12: true
    });
}

/**
 * Format date for display
 * 
 * @param {string} dateString Date in YYYY-MM-DD format
 * @returns {string} Formatted date
 */
function formatDate(dateString) {
    if (!dateString) return '';
    
    const date = new Date(dateString);
    
    return date.toLocaleDateString(undefined, {
        weekday: 'short',
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}