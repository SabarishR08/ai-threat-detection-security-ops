document.addEventListener("DOMContentLoaded", function () {
    setupNavigation();
    setupSearchBar();
    setupButtonActions();
});

/* ✅ Smooth Page Navigation */
function setupNavigation() {
    document.querySelectorAll("nav a").forEach(link => {
        link.addEventListener("click", function (event) {
            event.preventDefault();
            let url = this.getAttribute("href");

            fetch(url)
                .then(response => response.text())
                .then(html => {
                    document.body.innerHTML = html;
                    history.pushState(null, "", url);
                    setupNavigation(); // Reattach event listeners
                })
                .catch(err => console.error("Navigation Error:", err));
        });
    });

    /* ✅ Highlight Active Page */
    let currentUrl = window.location.pathname;
    document.querySelectorAll("nav a").forEach(link => {
        if (link.getAttribute("href") === currentUrl) {
            link.classList.add("active");
        } else {
            link.classList.remove("active");
        }
    });

    window.onpopstate = function () {
        location.reload(); // Reload on back/forward navigation
    };
}

/* ✅ Search Bar Enhancements */
function setupSearchBar() {
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

/* ✅ Button Click Actions */
function setupButtonActions() {
    let getStartedBtn = document.querySelector(".btn-get-started");
    if (getStartedBtn) {
        getStartedBtn.addEventListener("click", () => {
            window.location.href = "/dashboard";
        });
    }
}
