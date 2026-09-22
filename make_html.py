html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Schema Inspector - Test Workbench</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-900 text-gray-100 font-sans min-h-screen p-6">
    <div class="max-w-7xl mx-auto">
        <header class="flex justify-between items-center mb-6 pb-4 border-b border-gray-700">
            <div>
                <h1 class="text-2xl font-bold text-emerald-400">Schema Inspector</h1>
                <p class="text-sm text-gray-400">VistA Vault Metadata Test Workbench</p>
            </div>
            <div class="flex gap-3">
                <button id="modeBtn" onclick="toggleMode()" class="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 font-semibold rounded shadow transition">
                    Mode: DD
                </button>
            </div>
        </header>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6 bg-gray-800 p-4 rounded-lg border border-gray-700">
            <div>
                <label class="block text-xs uppercase tracking-wider text-gray-400 mb-1">File Number</label>
                <input type="text" id="fileFilter" placeholder="e.g. 0, 2" oninput="debounceFetch()" class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
            </div>
            <div id="fieldFilterContainer">
                <label class="block text-xs uppercase tracking-wider text-gray-400 mb-1">Field Number</label>
                <input type="text" id="fieldFilter" placeholder="e.g. .01" oninput="debounceFetch()" class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
            </div>
            <div class="md:col-span-2">
                <label class="block text-xs uppercase tracking-wider text-gray-400 mb-1">Keyword Search</label>
                <input type="text" id="textFilter" placeholder="Search keys or values..." oninput="debounceFetch()" class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm focus:outline-none focus:border-emerald-500">
            </div>
        </div>

        <div class="bg-gray-800 rounded-lg border border-gray-700 overflow-hidden shadow-lg">
            <div class="overflow-x-auto">
                <table class="w-full text-left border-collapse">
                    <thead>
                        <tr id="tableHeaders" class="bg-gray-700 text-xs uppercase text-gray-300 tracking-wider">
                            </tr>
                    </thead>
                    <tbody id="tableBody" class="divide-y divide-gray-700 text-sm">
                        </tbody>
                </table>
            </div>

            <div class="flex justify-between items-center p-4 bg-gray-800 border-t border-gray-700 text-sm">
                <span id="paginationInfo" class="text-gray-400">Loading...</span>
                <div class="flex gap-2">
                    <button onclick="changePage(-1)" class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded transition">Previous</button>
                    <button onclick="changePage(1)" class="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded transition">Next</button>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentMode = 'DD';
        let currentPage = 0;
        const pageSize = 20;
        let debounceTimer = null;

        function toggleMode() {
            currentMode = currentMode === 'DD' ? 'DIC' : 'DD';
            document.getElementById('modeBtn').innerText = `Mode: ${currentMode}`;
            
            const fieldContainer = document.getElementById('fieldFilterContainer');
            if (currentMode === 'DIC') {
                fieldContainer.style.display = 'none';
                document.getElementById('fieldFilter').value = '';
            } else {
                fieldContainer.style.display = 'block';
            }
            currentPage = 0;
            fetchData();
        }

        function debounceFetch() {
            clearTimeout(debounceTimer);
            debounceTimer = setTimeout(() => {
                currentPage = 0;
                fetchData();
            }, 300);
        }

        function changePage(direction) {
            if (direction === -1 && currentPage > 0) {
                currentPage--;
                fetchData();
            } else if (direction === 1) {
                currentPage++;
                fetchData();
            }
        }

        async function fetchData() {
            const fileNum = document.getElementById('fileFilter').value.trim();
            const fieldNum = document.getElementById('fieldFilter').value.trim();
            const query = document.getElementById('textFilter').value.trim();
            const offset = currentPage * pageSize;

            let url = `http://127.0.0.1:8000/api/schema/search?mode=${currentMode}&limit=${pageSize}&offset=${offset}`;
            if (fileNum) url += `&file_num=${encodeURIComponent(fileNum)}`;
            if (fieldNum && currentMode === 'DD') url += `&field_num=${encodeURIComponent(fieldNum)}`;
            if (query) url += `&q=${encodeURIComponent(query)}`;

            try {
                const response = await fetch(url);
                const data = await response.json();
                renderTable(data);
            } catch (err) {
                console.error('API fetch error:', err);
                document.getElementById('tableBody').innerHTML = `<tr><td colspan="5" class="p-4 text-center text-red-400">Failed to connect to Schema Inspector API. Ensure uvicorn is running.</td></tr>`;
            }
        }

        function renderTable(data) {
            const headersEl = document.getElementById('tableHeaders');
            const bodyEl = document.getElementById('tableBody');
            const infoEl = document.getElementById('paginationInfo');

            if (currentMode === 'DD') {
                headersEl.innerHTML = `
                    <th class="p-3">ID</th>
                    <th class="p-3">File #</th>
                    <th class="p-3">Field #</th>
                    <th class="p-3">Node / Value Syntax</th>
                `;
            } else {
                headersEl.innerHTML = `
                    <th class="p-3">ID</th>
                    <th class="p-3">File #</th>
                    <th class="p-3">Node Key / Definition Value</th>
                `;
            }

            if (data.rows.length === 0) {
                bodyEl.innerHTML = `<tr><td colspan="4" class="p-6 text-center text-gray-500">No matching records found.</td></tr>`;
                infoEl.innerText = `Showing 0 of 0 records`;
                return;
            }

            bodyEl.innerHTML = data.rows.map(row => {
                if (currentMode === 'DD') {
                    return `
                        <tr class="hover:bg-gray-700/50 transition">
                            <td class="p-3 text-gray-400 font-mono text-xs">${row.id}</td>
                            <td class="p-3 font-semibold text-emerald-400">${row.file_number || ''}</td>
                            <td class="p-3 font-semibold text-blue-400">${row.field_number || ''}</td>
                            <td class="p-3 font-mono text-xs text-gray-300 break-all">${escapeHtml(row.value)}</td>
                        </tr>
                    `;
                } else {
                    return `
                        <tr class="hover:bg-gray-700/50 transition">
                            <td class="p-3 text-gray-400 font-mono text-xs">${row.id}</td>
                            <td class="p-3 font-semibold text-emerald-400">${row.file_number || ''}</td>
                            <td class="p-3 font-mono text-xs text-gray-300 break-all">${escapeHtml(row.value)}</td>
                        </tr>
                    `;
                }
            }).join('');

            const startIdx = (currentPage * pageSize) + 1;
            const endIdx = Math.min((currentPage + 1) * pageSize, data.total);
            infoEl.innerText = `Showing ${startIdx}-${endIdx} of ${data.total} matches (Page ${currentPage + 1})`;
        }

        function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        }

        fetchData();
    </script>
</body>
</html>
"""

with open('test_inspector.html', 'w') as f:
    f.write(html_content)
print("test_inspector.html created safely!")
