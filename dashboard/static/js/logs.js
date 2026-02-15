document.addEventListener("DOMContentLoaded", function () {
    fetchLogs();
    setupLiveUpdates();
    setupSearchFilter();
});

/* ✅ Fetch & Display Logs */
function fetchLogs() {
    fetch("/api/logs")
        .then(response => response.json())
        .then(data => displayLogs(data))
        .catch(error => console.error("Error fetching logs:", error));
}

/* ✅ Display Logs in Table */
function displayLogs(logs) {
    const tableBody = document.getElementById("logs-table");
    if (!tableBody) return;

    tableBody.innerHTML = ""; // Clear previous logs

    logs.forEach(log => {
        let row = document.createElement("tr");
        let statusClass = log.status === "Malicious" ? "text-danger fw-bold" :
                          log.status === "Safe" ? "text-success fw-bold" : "text-warning fw-bold";

        row.innerHTML = `
            <td>${log.timestamp}</td>
            <td><a href="${log.url}" target="_blank">${log.url}</a></td>
            <td class="${statusClass}">${log.status}</td>
            <td>${log.reason}</td>
        `;
        tableBody.appendChild(row);

        // ✅ Show threat popup if malicious
        if (log.status === "Malicious") {
            showThreatPopup(log.url);
        }
    });
}

/* ✅ Search & Filter Logs */
function setupSearchFilter() {
    const searchInput = document.getElementById("search-input");
    if (!searchInput) return;

    searchInput.addEventListener("input", () => {
        let searchText = searchInput.value.toLowerCase();
        let rows = document.querySelectorAll("#logs-table tr");

        rows.forEach(row => {
            row.style.display = row.innerText.toLowerCase().includes(searchText) ? "" : "none";
        });
    });
}

/* ✅ Real-Time Log Updates */
function setupLiveUpdates() {
    var socket = io.connect(window.location.origin);

    socket.on("update_logs", function () {
        fetchLogs();
    });
}

/* ✅ Show Pop-Up Warning for Malicious URLs */
function showThreatPopup(url) {
    let popup = document.createElement("div");
    popup.className = "threat-popup alert alert-danger";
    popup.innerHTML = `
        <strong>⚠️ Malicious URL Detected!</strong><br>
        <span>${url}</span>
        <button class="close-popup">&times;</button>
    `;

    document.body.appendChild(popup);

    // Close the popup when clicking the button
    popup.querySelector(".close-popup").addEventListener("click", () => {
        popup.remove();
    });

    // Auto remove after 5 seconds
    setTimeout(() => popup.remove(), 5000);
}
