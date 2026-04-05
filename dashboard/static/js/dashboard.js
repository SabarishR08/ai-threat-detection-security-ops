document.addEventListener("DOMContentLoaded", function () {
    console.log("🔄 Initializing Dashboard Scripts...");

    fetchLogs();
    loadThreatGraph();
    loadThreatChart();
    loadThreatTimeline();
    loadThreatDistribution();
    loadThreatStatistics();
    loadThreatTrends(); // Added Threat Trends
    loadRecentActivity();
    setupDarkModeToggle();
    setupSearchFilter();
    setupLiveUpdates();
    setupDownloadReport(); // Added Download Report Functionality
    setupBookmarkLogs();
    setupLogCleanup();

    console.log("✅ Dashboard Scripts Loaded Successfully!");
});

let liveUpdateTimer = null;

function getChartAnimationOptions() {
    const prefersReducedMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) {
        return false;
    }
    return {
        duration: 250,
        easing: "easeOutQuad"
    };
}

/* ✅ Ensure Socket.IO is loaded */
if (typeof io === "undefined") {
    console.error("❌ Socket.IO is not loaded. Check if it's included in your HTML.");
}

/* ✅ Fetch & Display Logs */
function fetchLogs() {
    console.log("🔄 Fetching logs from server...");

    fetch("/api/logs")
        .then(response => response.json())
        .then(data => {
            if (!Array.isArray(data)) throw new Error("Invalid JSON response");
            displayLogs(data);
            console.log("✅ Logs loaded successfully!");
        })
        .catch(error => console.error("❌ Error fetching logs:", error));
}

/* ✅ Display Logs in Table */
function displayLogs(logs) {
    console.log("🔄 Populating logs into table...");

    const tableBody = document.querySelector("#logs-table tbody");
    if (!tableBody) return;
    tableBody.innerHTML = ""; // Clear existing data

    logs.forEach((log, index) => {
        let row = document.createElement("tr");
        let statusClass = log.status === "Malicious" ? "text-danger fw-bold" :
                          log.status === "Safe" ? "text-success fw-bold" : "text-warning fw-bold";

        row.innerHTML = `
            <td>${index + 1}</td>
            <td>${log.timestamp}</td>
            <td><a href="${log.url}" target="_blank">${log.url}</a></td>
            <td class="${statusClass}">${log.status}</td>
            <td>${log.reason}</td>
            <td><button class="bookmark-btn" data-url="${log.url}">⭐</button></td>
        `;
        tableBody.appendChild(row);
    });

    console.log(`✅ ${logs.length} logs displayed!`);
    setupBookmarkLogs(); // Ensure buttons work after loading logs
}

/* ✅ Real-Time Log Updates */
function setupLiveUpdates() {
    if (typeof io === "undefined") return;

    console.log("🔄 Setting up real-time updates...");

    var socket = io.connect(window.location.origin);
    socket.on("update_logs", function () {
        if (liveUpdateTimer) {
            clearTimeout(liveUpdateTimer);
        }
        liveUpdateTimer = setTimeout(function () {
            console.log("🔄 Live update received! Refreshing dashboard...");
            fetchLogs();
            loadThreatGraph();
            loadThreatChart();
            loadThreatDistribution();
            loadThreatStatistics();
            loadThreatTrends();
        }, 350);
    });
}

/* ✅ Load & Display Threat Graph (Doughnut Chart) */
function loadThreatGraph() {
    console.log("🔄 Loading Threat Graph...");

    const canvas = document.getElementById("threatGraph");
    if (!canvas) {
        console.warn("⚠️ threatGraph canvas not found; skipping graph render");
        return;
    }

    fetch("/api/threat_stats")
        .then(response => response.json())
        .then(data => {
            if (!data || Object.keys(data).length === 0) {
                console.warn("⚠️ Threat stats API returned empty data.");
                return;
            }

            var ctx = canvas.getContext("2d");
            if (window.threatGraph instanceof Chart) {
                window.threatGraph.destroy();
            }
            window.threatGraph = new Chart(ctx, {
                type: "doughnut",
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: "Threat Levels",
                        data: Object.values(data),
                        backgroundColor: ["#ff4d4d", "#ffcc00", "#66cc66", "#3399ff", "#9900cc"],
                        borderColor: ["#b30000", "#cc9900", "#339933", "#0066cc", "#660099"],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: getChartAnimationOptions(),
                    plugins: {
                        legend: { position: "bottom" }
                    }
                }
            });

            console.log("✅ Threat Graph Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat graph:", error));
}

/* ✅ Load & Display Threat Trends (Line Chart) */
function loadThreatTrends() {
    console.log("🔄 Loading Threat Trends...");

    const canvas = document.getElementById("threatTrends");
    if (!canvas) {
        console.warn("⚠️ threatTrends canvas not found; skipping trends render");
        return;
    }

    fetch("/api/threat_trends")
        .then(response => response.json())
        .then(data => {
            if (!data || Object.keys(data).length === 0) {
                console.warn("⚠️ Threat trends API returned empty data.");
                return;
            }

            var ctx = canvas.getContext("2d");
            if (window.threatTrends instanceof Chart) {
                window.threatTrends.destroy();
            }
            window.threatTrends = new Chart(ctx, {
                type: "line",
                data: {
                    labels: Object.keys(data), // Dates or time periods
                    datasets: [{
                        label: "Threats Over Time",
                        data: Object.values(data), // Number of threats
                        borderColor: "#ff4d4d",
                        borderWidth: 2,
                        fill: false
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: getChartAnimationOptions(),
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: "Time"
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: "Number of Threats"
                            },
                            beginAtZero: true
                        }
                    }
                }
            });

            console.log("✅ Threat Trends Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat trends:", error));
}

/* ✅ Load & Display Threat Timeline */
function loadThreatTimeline() {
    console.log("🔄 Loading Threat Timeline...");

    const timelineContainer = document.getElementById("threat-timeline");
    if (!timelineContainer) {
        console.warn("⚠️ threat-timeline container not found; skipping timeline");
        return;
    }

    fetch("/api/threat_timeline")
        .then(response => response.json())
        .then(data => {
            timelineContainer.innerHTML = "";
            data.forEach(event => {
                let eventItem = document.createElement("div");
                eventItem.classList.add("timeline-event");
                eventItem.innerHTML = `<span>${event.timestamp}</span> - <strong>${event.type}</strong>: ${event.details}`;
                timelineContainer.appendChild(eventItem);
            });

            console.log("✅ Threat Timeline Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat timeline:", error));
}

/* ✅ Load & Display Threat Distribution (Pie Chart) */
function loadThreatDistribution() {
    console.log("🔄 Loading Threat Distribution...");

    const canvas = document.getElementById("threatDistributionChart") || document.getElementById("threatDistribution");
    if (!canvas) {
        console.warn("⚠️ threat distribution canvas not found; skipping chart");
        return;
    }

    fetch("/api/threat_distribution")
        .then(response => response.json())
        .then(data => {
            if (!data) {
                console.warn("⚠️ Threat distribution API returned empty data.");
                return;
            }

            var ctx = canvas.getContext("2d");
            if (window.threatDistribution instanceof Chart) {
                window.threatDistribution.destroy();
            }
            window.threatDistribution = new Chart(ctx, {
                type: "pie",
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        data: Object.values(data),
                        backgroundColor: ["#ff5733", "#33ff57", "#3357ff", "#ff33a1", "#a133ff"]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: getChartAnimationOptions()
                }
            });

            console.log("✅ Threat Distribution Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat distribution:", error));
}

/* ✅ Load & Display Threat Statistics (Bar Chart) */
function loadThreatStatistics() {
    console.log("🔄 Loading Threat Statistics...");

    const canvas = document.getElementById("threatStatistics");
    if (!canvas) {
        console.warn("⚠️ threatStatistics canvas not found; skipping stats chart");
        return;
    }

    fetch("/api/threat_statistics")
        .then(response => response.json())
        .then(data => {
            if (!data) {
                console.warn("⚠️ Threat statistics API returned empty data.");
                return;
            }

            var ctx = canvas.getContext("2d");
            if (window.threatStatistics instanceof Chart) {
                window.threatStatistics.destroy();
            }
            window.threatStatistics = new Chart(ctx, {
                type: "bar",
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: "Threat Types",
                        data: Object.values(data),
                        backgroundColor: ["#ff9999", "#99ff99", "#9999ff", "#ffcc99", "#cc99ff"]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: getChartAnimationOptions()
                }
            });

            console.log("✅ Threat Statistics Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat statistics:", error));
}

// Provide a safe fallback for threat chart if HTML lacks a target canvas
function loadThreatChart() {
    const canvas = document.getElementById("threatChart");
    if (!canvas) {
        console.warn("⚠️ threatChart canvas not found; skipping chart render");
        return;
    }

    fetch("/api/threat_stats")
        .then(response => response.json())
        .then(data => {
            if (!data || Object.keys(data).length === 0) {
                console.warn("⚠️ Threat stats API returned empty data.");
                return;
            }

            var ctx = canvas.getContext("2d");
            if (window.threatChart instanceof Chart) {
                window.threatChart.destroy();
            }
            window.threatChart = new Chart(ctx, {
                type: "bar",
                data: {
                    labels: Object.keys(data),
                    datasets: [{
                        label: "Threat Counts",
                        data: Object.values(data),
                        backgroundColor: ["#ff4d4d", "#ffcc00", "#66cc66", "#3399ff", "#9900cc"]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    animation: getChartAnimationOptions(),
                    plugins: { legend: { display: false } }
                }
            });

            console.log("✅ Threat Chart Loaded Successfully!");
        })
        .catch(error => console.error("❌ Error loading threat chart:", error));
}

/* ✅ Setup Download Report Functionality */
function setupDownloadReport() {
    document.getElementById("download-log").addEventListener("click", function () {
        console.log("🔄 Downloading threat log report...");
        window.location.href = "/download-threat-log";
    });
}