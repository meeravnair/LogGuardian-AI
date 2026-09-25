/**
 * LogGuardian AI Frontend JavaScript.
 * Implements interactive drag-and-drop log file uploads,
 * real-time historical search, alerts table filtering,
 * GeoIP simulated lookups, and Plotly.js chart rendering.
 */

document.addEventListener("DOMContentLoaded", () => {
    initDragAndDrop();
    initGlobalSearch();
    initDashboard();
});

/**
 * 1. Drag and Drop log uploader implementation
 */
function initDragAndDrop() {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("log_file_input");
    const fileInfo = document.getElementById("file-info");
    const fileNameSpan = document.getElementById("selected-file-name");
    const fileSizeSpan = document.getElementById("selected-file-size");

    if (!dropZone || !fileInput) return;

    // Handle click to browse
    dropZone.addEventListener("click", () => {
        fileInput.click();
    });

    // Handle file selected via explorer
    fileInput.addEventListener("change", (e) => {
        if (fileInput.files.length > 0) {
            displaySelectedFile(fileInput.files[0]);
        }
    });

    // Handle drag events
    ["dragenter", "dragover"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.classList.remove("dragover");
        }, false);
    });

    dropZone.addEventListener("drop", (e) => {
        const dt = e.dataTransfer;
        const files = dt.files;
        if (files.length > 0) {
            fileInput.files = files;
            displaySelectedFile(files[0]);
        }
    });

    function displaySelectedFile(file) {
        fileNameSpan.textContent = file.name;
        fileSizeSpan.textContent = `(${formatBytes(file.size)})`;
        fileInfo.classList.remove("d-none");
        
        // Add visual animation glow
        dropZone.style.borderColor = "var(--green-glow)";
        dropZone.style.boxShadow = "0 0 15px rgba(16, 185, 129, 0.15)";
    }
}

/**
 * Format bytes to readable string
 */
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return "0 Bytes";
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + " " + sizes[i];
}

/**
 * 2. Search & Filter panel in homepage archive
 */
function initGlobalSearch() {
    const searchInput = document.getElementById("search-input");
    const scansTable = document.getElementById("scans-table");
    
    if (!searchInput || !scansTable) return;

    const tbody = document.getElementById("scans-list-body");

    searchInput.addEventListener("input", debounce(() => {
        const query = searchInput.value.toLowerCase().trim();
        
        // Fetch from API for broad backend search
        fetch(`/search_history?query=${encodeURIComponent(query)}`)
            .then(res => res.json())
            .then(data => {
                tbody.innerHTML = "";
                if (data.length === 0) {
                    tbody.innerHTML = `
                        <tr>
                            <td colspan="7" class="text-center py-5 text-secondary">
                                <i class="fa-solid fa-folder-open d-block fs-1 mb-3"></i>
                                No investigations found matching "${escapeHtml(query)}"
                            </td>
                        </tr>
                    `;
                    return;
                }

                data.forEach(s => {
                    const timestamp = s.timestamp.split("T")[0];
                    const timePart = s.timestamp.includes("T") ? s.timestamp.split("T")[1].substring(0, 5) : "";
                    const sizeFormatted = formatBytes(s.file_size);
                    const riskClass = s.risk_rating.toLowerCase();
                    const scoreClass = s.security_score >= 85 ? 'score-success' : (s.security_score >= 60 ? 'score-warning' : 'score-danger');
                    
                    const alertsTd = s.total_alerts > 0 
                        ? `<span class="text-danger font-monospace fw-bold"><i class="fa-solid fa-triangle-exclamation me-1"></i>${s.total_alerts} Alerts</span>`
                        : `<span class="text-success font-monospace fw-bold"><i class="fa-solid fa-circle-check me-1"></i>Clean</span>`;

                    const row = document.createElement("tr");
                    row.setAttribute("data-scan-id", s.id);
                    row.innerHTML = `
                        <td>${timestamp} <span class="text-secondary small">${timePart}</span></td>
                        <td><strong>${escapeHtml(s.filename)}</strong> <span class="text-secondary small">(${sizeFormatted})</span></td>
                        <td><span class="badge badge-cyber text-uppercase">${escapeHtml(s.log_type.replace('_', ' '))}</span></td>
                        <td><span class="score-badge ${scoreClass}">${s.security_score}/100</span></td>
                        <td><span class="badge badge-risk badge-risk-${riskClass}">${s.risk_rating}</span></td>
                        <td>${alertsTd}</td>
                        <td class="text-end">
                            <div class="btn-group">
                                <a href="/dashboard/${s.id}" class="btn btn-sm btn-cyber-outline"><i class="fa-solid fa-chart-column me-1"></i>Dashboard</a>
                                <button type="button" class="btn btn-sm btn-cyber-danger" onclick="confirmDelete('${s.id}', '${escapeJs(s.filename)}')"><i class="fa-solid fa-trash-can"></i></button>
                            </div>
                        </td>
                    `;
                    tbody.appendChild(row);
                });
            })
            .catch(err => console.error("Search API failed:", err));
    }, 250));
}

/**
 * Debounce helper to prevent excessive API requests
 */
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

/**
 * Confirm delete modal trigger
 */
function confirmDelete(scanId, filename) {
    const filenameLabel = document.getElementById("delete-filename");
    const deleteForm = document.getElementById("delete-form");
    if (filenameLabel && deleteForm) {
        filenameLabel.textContent = filename;
        deleteForm.action = `/delete/${scanId}`;
        const modal = new bootstrap.Modal(document.getElementById("deleteModal"));
        modal.show();
    }
}

/**
 * 3. Individual Scan analysis Dashboard visualizations & UI controllers
 */
function initDashboard() {
    const metaElement = document.getElementById("plotly-metrics-meta");
    if (!metaElement) return;

    const scanId = metaElement.getAttribute("data-scan-id");
    
    // Fetch Metrics for this scan run
    fetch(`/api/scan_details/${scanId}`)
        .then(res => res.json())
        .then(data => {
            renderPlotlyCharts(data.metrics);
            resolveGeoIPSimulations();
        })
        .catch(err => console.error("Failed to load dashboard metrics:", err));

    // Bootstrap Tooltips initialization
    const tooltipTriggerList = document.querySelectorAll('[data-bs-toggle="tooltip"]');
    [...tooltipTriggerList].map(tooltipTriggerEl => new bootstrap.Tooltip(tooltipTriggerEl));

    // Filter dashboard alerts table
    const alertSearch = document.getElementById("alerts-search-input");
    const alertsTable = document.getElementById("alerts-table");
    if (alertSearch && alertsTable) {
        alertSearch.addEventListener("input", () => {
            const query = alertSearch.value.toLowerCase().trim();
            const rows = alertsTable.querySelectorAll("tbody tr.alert-row");
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                const nextRow = row.nextElementSibling; // the collapse drawer row
                
                if (text.includes(query)) {
                    row.classList.remove("d-none");
                } else {
                    row.classList.add("d-none");
                    // Close collapse if it was open
                    if (nextRow && nextRow.classList.contains("collapse-row")) {
                        const collapseEl = nextRow.querySelector(".collapse");
                        if (collapseEl && collapseEl.classList.contains("show")) {
                            bootstrap.Collapse.getInstance(collapseEl).hide();
                        }
                    }
                }
            });
        });
    }
}

/**
 * Renders Plotly.js charts using retrieved scan metrics
 */
function renderPlotlyCharts(metrics) {
    const severityDiv = document.getElementById("severity-chart");
    const detectorDiv = document.getElementById("detector-chart");

    // Dark-mode text layout settings
    const darkLayoutConfig = {
        paper_bgcolor: "rgba(0,0,0,0)",
        plot_bgcolor: "rgba(0,0,0,0)",
        font: {
            color: "#f8fafc",
            family: "Outfit, sans-serif",
            size: 11
        },
        margin: { t: 30, b: 30, l: 30, r: 30 },
        showlegend: true,
        legend: {
            orientation: "h",
            yanchor: "bottom",
            y: -0.2,
            xanchor: "center",
            x: 0.5
        }
    };

    // 1. Severity Share Donut Chart
    if (severityDiv && metrics.severities) {
        const severityColors = {
            "CRITICAL": "#ef4444", // red
            "HIGH": "#f97316",     // orange
            "MEDIUM": "#eab308",   // yellow
            "LOW": "#3b82f6",      // blue
            "INFO": "#10b981"      // green
        };

        const labels = Object.keys(metrics.severities);
        const values = Object.values(metrics.severities);
        const colors = labels.map(l => severityColors[l] || "#94a3b8");

        const data = [{
            values: values,
            labels: labels,
            type: "pie",
            hole: 0.55,
            marker: { colors: colors },
            textinfo: "label+percent",
            hoverinfo: "label+value",
            textposition: "outside"
        }];

        const layout = {
            ...darkLayoutConfig,
            margin: { t: 10, b: 50, l: 10, r: 10 }
        };

        Plotly.newPlot(severityDiv, data, layout, { displayModeBar: false, responsive: true });
    }

    // 2. Threat Category Volume Horizontal Bar Chart
    if (detectorDiv && metrics.detectors) {
        const cleanLabels = {
            "brute_force": "Brute Force",
            "sql_injection": "SQL Injection",
            "xss": "XSS Payload",
            "directory_traversal": "Path Traversal",
            "command_injection": "Command Injection",
            "file_inclusion": "File Inclusion",
            "scanner_detection": "Recon Scan",
            "user_agents": "User Agent Anomaly",
            "dos_detector": "Denial of Service",
            "auth_anomaly": "Auth Anomaly"
        };

        const rawLabels = Object.keys(metrics.detectors);
        const values = Object.values(metrics.detectors);
        const labels = rawLabels.map(l => cleanLabels[l] || l.replace("_", " ").toUpperCase());

        // Sort data by volume size
        const paired = labels.map((l, idx) => ({ label: l, val: values[idx] }));
        paired.sort((a, b) => a.val - b.val); // Ascending order for horizontal drawing

        const data = [{
            x: paired.map(p => p.val),
            y: paired.map(p => p.label),
            type: "bar",
            orientation: "h",
            marker: {
                color: "#6366f1",
                opacity: 0.85,
                line: {
                    color: "#a5b4fc",
                    width: 1.5
                }
            }
        }];

        const layout = {
            ...darkLayoutConfig,
            margin: { t: 10, b: 30, l: 120, r: 20 },
            showlegend: false,
            xaxis: {
                gridcolor: "rgba(255,255,255,0.06)",
                zeroline: false
            },
            yaxis: {
                tickfont: { size: 10 }
            }
        };

        Plotly.newPlot(detectorDiv, data, layout, { displayModeBar: false, responsive: true });
    }
}

/**
 * 4. Resolves simulated GeoIP lookups dynamically using a hash of the IP
 */
function resolveGeoIPSimulations() {
    const geoContainers = document.querySelectorAll("[id^='geo-info-']");
    if (geoContainers.length === 0) return;

    const countries = [
        { name: "United States", code: "US" },
        { name: "Germany", code: "DE" },
        { name: "China", code: "CN" },
        { name: "Russia", code: "RU" },
        { name: "Netherlands", code: "NL" },
        { name: "United Kingdom", code: "GB" },
        { name: "India", code: "IN" },
        { name: "Brazil", code: "BR" },
        { name: "Ukraine", code: "UA" },
        { name: "France", code: "FR" }
    ];

    geoContainers.forEach(container => {
        const ip = container.getAttribute("data-ip");
        if (!ip) return;

        if (ip === "127.0.0.1" || ip === "::1" || ip === "localhost") {
            container.innerHTML = `<i class="fa-solid fa-earth-americas me-1 text-secondary"></i>Local Loopback`;
            return;
        }

        // Private Ranges
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("172.")) {
            container.innerHTML = `<i class="fa-solid fa-earth-americas me-1 text-secondary"></i>Private Network`;
            return;
        }

        // Generate deterministic country based on simple string hashing
        let hash = 0;
        for (let i = 0; i < ip.length; i++) {
            hash = ip.charCodeAt(i) + ((hash << 5) - hash);
        }
        const idx = Math.abs(hash) % countries.length;
        const country = countries[idx];

        // Format flag and label
        container.innerHTML = `
            <img src="https://flagcdn.com/16x12/${country.code.toLowerCase()}.png" 
                 alt="${country.code}" class="me-1 align-baseline" style="width:14px; height:10px;">
            Origin: <b>${country.name}</b>
        `;
    });
}

/**
 * HTML Escaping Helpers
 */
function escapeHtml(str) {
    return str.replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#039;");
}

function escapeJs(str) {
    return str.replace(/\\/g, "\\\\")
              .replace(/'/g, "\\'")
              .replace(/"/g, '\\"')
              .replace(/\n/g, "\\n");
}
