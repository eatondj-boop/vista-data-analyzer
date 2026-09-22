class RoutineAnalyzerModule {
    constructor() {
        console.log("RoutineAnalyzerModule initialized.");
        // Automatically trigger initial load when DOM is ready
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", () => this.init());
        } else {
            this.init();
        }
    }

    init() {
        console.log("RoutineAnalyzer initializing default routine list...");
        this.searchRoutines();
    }

    escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    async searchRoutines() {
        const searchInput = document.getElementById("routineSearchInput") || document.getElementById("routineSearch");
        const query = searchInput ? searchInput.value.trim() : "";
        
        try {
            const response = await fetch(`/api/routines/search?q=${encodeURIComponent(query)}`);
            const data = await response.json();
            
            const listContainer = document.getElementById("routineListContainer") || document.getElementById("routineList");
            if (!listContainer) {
                console.error("Routine list container element not found in DOM.");
                return;
            }

            if (data.routines && data.routines.length > 0) {
                listContainer.innerHTML = data.routines.map(r => 
                    `<button onclick="RoutineAnalyzer.loadRoutine('${this.escapeHtml(r)}')" class="w-full text-left px-3 py-2 hover:bg-gray-800 rounded text-xs font-mono text-emerald-400 transition cursor-pointer">${this.escapeHtml(r)}</button>`
                ).join("");
            } else {
                listContainer.innerHTML = `<p class="text-xs text-gray-500 italic p-2">No routines found.</p>`;
            }
        } catch (err) {
            console.error("Failed to search routines:", err);
        }
    }

    async loadRoutine(routineName) {
        const titleEl = document.getElementById("activeRoutineTitle") || document.getElementById("routineTitle");
        if (titleEl) titleEl.innerText = routineName;
        
        const codeBody = document.getElementById("routineCodeBody") || document.getElementById("routineContent");
        if (codeBody) {
            codeBody.innerHTML = `<p class="text-gray-500 italic p-4">Loading routine contents for ${this.escapeHtml(routineName)}...</p>`;
        }

        try {
            const response = await fetch(`/api/routines/inspect/${encodeURIComponent(routineName)}`);
            const data = await response.json();

            if (codeBody && data.lines && data.lines.length > 0) {
                codeBody.innerHTML = data.lines.map(l => 
                    `<div class="flex hover:bg-gray-900/80 px-2 py-0.5 font-mono text-xs">` +
                        `<span class="w-16 text-gray-500 select-none text-right pr-4">${this.escapeHtml(l.line_number)}</span>` +
                        `<span class="text-gray-200 whitespace-pre">${this.escapeHtml(l.line_content)}</span>` +
                    `</div>`
                ).join("");
            } else if (codeBody) {
                codeBody.innerHTML = `<p class="text-xs text-gray-500 italic p-4">No content recorded for this routine.</p>`;
            }
        } catch (err) {
            console.error("Failed to load routine inspector screen:", err);
            if (codeBody) {
                codeBody.innerHTML = `<p class="text-xs text-red-400 italic p-4">Error loading routine source code.</p>`;
            }
        }
    }
}

window.RoutineAnalyzer = new RoutineAnalyzerModule();