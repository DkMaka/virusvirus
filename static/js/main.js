/**
 * Virus Scanner - Main JS file
 */

document.addEventListener('DOMContentLoaded', function() {
    // Track scan progress if on scan page
    const scanProgressCard = document.getElementById('scan-progress-card');
    if (scanProgressCard && !scanProgressCard.classList.contains('d-none')) {
        trackScanProgress();
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

/**
 * Track scan progress by polling the API
 */
function trackScanProgress() {
    // Get scan ID from URL
    const urlParams = new URLSearchParams(window.location.search);
    const scanId = urlParams.get('scan_id');
    
    if (!scanId) return;
    
    const progressBar = document.getElementById('scan-progress-bar');
    const filesScannedCount = document.getElementById('files-scanned-count');
    const threatsFoundCount = document.getElementById('threats-found-count');
    const currentFilePath = document.getElementById('current-file-path');
    
    let lastProgress = -1;
    
    // Poll progress every second
    const progressInterval = setInterval(() => {
        fetch(`/api/scan-progress/${scanId}`)
            .then(response => response.json())
            .then(data => {
                // Update progress bar
                progressBar.style.width = `${data.progress}%`;
                progressBar.setAttribute('aria-valuenow', data.progress);
                progressBar.textContent = `${data.progress}%`;
                
                // Update other elements
                filesScannedCount.textContent = data.files_scanned;
                currentFilePath.textContent = data.current_file;
                
                // If scan is complete, redirect to results page
                if (data.progress === 100 && lastProgress !== 100) {
                    clearInterval(progressInterval);
                    window.location.href = `/results/${scanId}`;
                }
                
                lastProgress = data.progress;
            })
            .catch(error => {
                console.error('Error fetching scan progress:', error);
            });
    }, 1000);
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
