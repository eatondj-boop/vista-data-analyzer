module_code = """/**
 * VistA Schema & Routine Inspector Add-On Module
 * Encapsulated UI and logic for analyzing DD and DIC globals.
 */
class SchemaInspectorModule {
    constructor(containerId = 'app') {
        this.containerId = containerId;
        this.isOpen = false;
    }

    // Inject the trigger button into your main app toolbar/header
    mountButton(targetElementId) {
        const target = document.getElementById(targetElementId);
        if (!target) {
            console.warn(`SchemaInspector: Target element #${targetElementId} not found.`);
            return;
        }

        const btn = document.createElement('button');
        btn.id = 'schemaInspectorBtn';
        btn.innerHTML = `
            <svg class="w-4 h-4 inline-block mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4"></path>
            </svg>
            Schema Inspector
        `;
        btn.className = "px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-semibold rounded shadow transition flex items-center";
        btn.onclick = () => this.toggleModal();
        
        target.appendChild(btn);
        this.injectModalHtml();
    }

    // Inject the standalone modal HTML structure into the DOM
    injectModalHtml() {
        if (document.getElementById('schemaInspectorModal')) return;

        const modalDiv = document.createElement('div');
        modalDiv.id = 'schemaInspectorModal';
        modalDiv.className = 'fixed inset-0 z-50 bg-black/70 backdrop-blur-sm hidden flex items-center justify-center p-4';
        modalDiv.innerHTML = `
            <div class="bg-gray-900 border border-gray-700 w-full max-w-6xl h-[90vh] rounded-xl shadow-2xl flex flex-col overflow-hidden text-gray-100">
                <div class="bg-gray-800 border-b border-gray-700 px-6 py-4 flex justify-between items-center">
                    <div>
                        <h2 class="text-lg font-bold text-emerald-400">VistA Vault Schema & Routine Inspector</h2>
                        <p class="text-xs text-gray-400">Level 1 Metadata & Level 2 Touchpoint Analysis</p>
                    </div>
                    <button onclick="window.schemaInspector.toggleModal()" class="text-gray-400 hover:text-white font-bold text-xl px-2">&times;</button>
                </div>

                <div class="flex-1 flex overflow-hidden">
                    <aside class="w-72 bg-gray-800/50 border-r border-gray-700 p-4 flex flex-col gap-3">
                        <div>
                            <label class="block text-xs uppercase tracking-wider text-gray-400 mb-1">File Number</label>
                            <div class="flex gap-2">
                                <input type="text" id="siFileInput" placeholder="e.g. 2, 200" class="w-full bg-gray-900 border border-gray-700 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-emerald-500">
                                <button onclick="window.schemaInspector.fetchInspection()" class="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-sm font-semibold rounded">Go</button>
                            </div>
                        </div>
                        <div class="text-xs font-semibold text-gray-400 uppercase tracking-wider mt-2">Quick Targets</div>
                        <div class="space-y-1 flex-1 overflow-y-auto">
                            <button onclick="window.schemaInspector.quickLoad('2')" class="w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-sm flex justify-between"><span>Patient</span><span class="font-mono text-emerald-400">2</span></button>
                            <button onclick="window.schemaInspector.quickLoad('200')" class="w-full text-left px-3 py-2 rounded hover:bg-gray-700 text-sm flex justify-between"><span>New Person</span><span class="font-mono text-emerald-400">200</span></button>
                        </div>
                    </aside>

                    <main class="flex-1 overflow-y-auto p-6 bg-gray-950 space-y-6">
                        <div id="siWelcome" class="h-full flex flex-col items-center justify-center text-gray-500">
                            <p class="text-base font-medium text-gray-400">Enter or select a VistA file number to begin analysis.</p>
                        </div>
                        <div id="siContent" class="hidden space-y-6">
                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-5">
                                <div class="flex justify-between items-start">
                                    <div>
                                        <span id="siFileBadge" class="px-2 py-0.5 bg-emerald-900 text-emerald-300 text-xs font-mono rounded">File</span>
                                        <h3 id="siTitle" class="text-xl font-bold mt-1 text-gray-100">-</h3>
                                    </div>
                                    <div class="text-right">
                                        <span class="block text-xs text-gray-400 uppercase">Global Root</span>
                                        <span id="siGlobalRoot" class="font-mono text-emerald-400 text-lg font-semibold">-</span>
                                    </div>
                                </div>
                                <div class="mt-3 pt-3 border-t border-gray-800">
                                    <h4 class="text-xs uppercase text-gray-400 mb-1">Description (%D)</h4>
                                    <p id="siDesc" class="text-xs font-mono bg-gray-950 p-2.5 rounded border border-gray-800 text-gray-300 whitespace-pre-wrap">-</p>
                                </div>
                            </div>

                            <div class="bg-gray-900 border border-gray-700 rounded-lg p-5">
                                <h4 class="text-xs uppercase font-bold tracking-wider text-blue-400 mb-3">Level 2 Routine Code Touchpoints</h4>
                                <div id="siTouchpoints" class="space-y-2"></div>
                            </div>

                            <div class="bg-gray-900 border border-gray-700 rounded-lg overflow-hidden">
                                <div class="px-4 py-3 bg-gray-800/80 border-b border-gray-700 flex justify-between items-center">
                                    <h4 class="text-xs uppercase font-bold text-emerald-400">Field Definitions (^DD)</h4>
                                    <span id="siFieldCount" class="text-xs text-gray-400">0 fields</span>
                                </div>
                                <table class="w-full text-left border-collapse text-xs font-mono">
                                    <thead>
                                        <tr class="bg-gray-800 text-gray-400">
                                            <th class="p-2.5">Field #</th>
                                            <th class="p-2.5">Node Key</th>
                                            <th class="p-2.5">Definition Value</th>
                                        </tr>
                                    </thead>
                                    <tbody id="siFieldsBody" class="divide-y divide-gray-800 text-gray-300"></tbody>
                                </table>
                            </div>
                        </div>
                    </main>
                </div>
            </div>
        `;
        document.body.appendChild(modalDiv);
    }

    toggleModal() {
        this.isOpen = !this.isOpen;
        const modal = document.getElementById('schemaInspectorModal');
        if (this.isOpen) {
            modal.classList.remove('hidden');
        } else {
            modal.classList.add('hidden');
        }
    }

    quickLoad(fileNum) {
        document.getElementById('siFileInput').value = fileNum;
        this.fetchInspection();
    }

    async fetchInspection() {
        const fileNum = document.getElementById('siFileInput').value.trim();
        if (!fileNum) return;

        try {
            const res = await fetch(`http://127.0.0.1:8000/api/schema/inspect/${fileNum}`);
            if (!res.ok) throw new Error('Failed to fetch file metadata.');
            const data = await res.json();
            this.render(data);
        } catch (err) {
            alert(err.message);
        }
    }

    render(data) {
        document.getElementById('siWelcome').classList.add('hidden');
        document.getElementById('siContent').classList.remove('hidden');

        document.getElementById('siFileBadge').innerText = `File #${data.file_number}`;

        let title = 'Unknown File';
        let globalRoot = 'N/A';
        let desc = [];

        data.file_definitions.forEach(def => {
            if (def.node_key.endsWith(',0') && !def.node_key.includes('"')) {
                title = def.value.split('^')[0];
            }
            if (def.node_key.endsWith(',"GL"')) {
                globalRoot = def.value;
            }
            if (def.node_key.includes('"%D"')) {
                desc.push(def.value);
            }
        });

        document.getElementById('siTitle').innerText = title;
        document.getElementById('siGlobalRoot').innerText = globalRoot;
        document.getElementById('siDesc').innerText = desc.length ? desc.join('\n') : 'No description found.';

        // Touchpoints
        const tpContainer = document.getElementById('siTouchpoints');
        if (data.routine_touchpoints && data.routine_touchpoints.length > 0) {
            tpContainer.innerHTML = data.routine_touchpoints.map(tp => `
                <div class="bg-gray-950 p-2.5 rounded border border-gray-800 flex justify-between items-center text-xs">
                    <div><span class="font-bold text-blue-300 font-mono">${tp.routine}</span> <span class="text-gray-400 ml-2">${tp.type}</span></div>
                    <code class="text-emerald-400 font-mono">${tp.line}</code>
                </div>
            `).join('');
        } else {
            tpContainer.innerHTML = '<p class="text-xs text-gray-500 italic">No routine touchpoints logged.</p>';
        }

        // Fields
        const tbody = document.getElementById('siFieldsBody');
        document.getElementById('siFieldCount').innerText = `${data.fields.length} fields`;
        tbody.innerHTML = data.fields.map(f => `
            <tr class="hover:bg-gray-900/50">
                <td class="p-2.5 text-emerald-400 font-bold">${f.field_number}</td>
                <td class="p-2.5 text-gray-500">${f.node_key}</td>
                <td class="p-2.5 text-gray-300 break-all">${this.escapeHtml(f.value)}</td>
            </tr>
        `).join('');
    }

    escapeHtml(str) {
        if (!str) return '';
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
}

// Export global instance reference
window.schemaInspector = new SchemaInspectorModule();
"""

with open('schema_inspector_module.js', 'w') as f:
    f.write(module_code)
print("schema_inspector_module.js created safely and cleanly!")
