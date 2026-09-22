class SchemaInspectorModule {
    constructor() {
        this.knownFields = {
            "2": {
                ".01": "NAME",
                ".02": "SEX",
                ".03": "DATE OF BIRTH",
                ".09": "SOCIAL SECURITY NUMBER",
                ".091": "PSEUDO SSN REASON",
                ".092": "PLACE OF BIRTH [CITY]",
                ".093": "PLACE OF BIRTH [STATE]",
                ".1": "WARD LOCATION",
                ".111": "STREET ADDRESS [LINE 1]",
                ".112": "STREET ADDRESS [LINE 2]",
                ".113": "STREET ADDRESS [LINE 3]",
                ".114": "CITY",
                ".115": "STATE",
                ".116": "ZIP CODE",
                ".3": "VETERAN (Y/N?)",
                ".321": "COMBAT VET ELIGIBLE?",
                "53.1": "PATIENT STATUS"
            },
            "200": {
                ".01": "NAME",
                ".011": "INITIAL",
                ".1": "PHONE (OFFICE)",
                ".111": "STREET ADDRESS 1",
                ".112": "STREET ADDRESS 2",
                ".113": "STREET ADDRESS 3",
                ".114": "CITY",
                ".115": "STATE",
                ".116": "ZIP CODE",
                "3": "DATE/TIME CREATED",
                "7": "DISUSER",
                "8": "ACCESS CODE",
                "9": "SOCIAL SECURITY NUMBER",
                "16": "TITLE"
            }
        };
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

    render(data) {
        document.getElementById("siWelcome").classList.add("hidden");
        document.getElementById("siContent").classList.remove("hidden");

        const fileNumStr = String(data.file_number);
        document.getElementById("siFileBadge").innerText = "File #" + fileNumStr;

        let title = "Unknown File";
        let globalRoot = "N/A";
        let desc = [];

        data.file_definitions.forEach(def => {
            const val = def.value || "";
            const key = def.node_key || "";
            
            if (key === "0" || key === fileNumStr + ",0" || (key.endsWith(",0") && !key.includes("\""))) {
                if (val && !val.startsWith("^")) {
                    title = val.split("^")[0];
                }
            }
            if (key.includes("\"GL\"") || key.endsWith(",\"GL\"")) {
                globalRoot = val;
            }
            if (key.includes("\"%D\"")) {
                desc.push(val);
            }
        });

        if (title === "Unknown File" && data.file_definitions.length > 0) {
            const firstVal = data.file_definitions[0].value || "";
            if (firstVal) {
                title = firstVal.split("^")[0];
            }
        }

        document.getElementById("siTitle").innerText = title;
        document.getElementById("siGlobalRoot").innerText = globalRoot;
        document.getElementById("siDesc").innerText = desc.length ? desc.join("\n") : "No description found.";

        // Render Routine Touchpoints
        const tpContainer = document.getElementById("siTouchpoints");
        if (data.routine_touchpoints && data.routine_touchpoints.length > 0) {
            tpContainer.innerHTML = data.routine_touchpoints.map(tp => 
                `<div class="bg-gray-950 p-2.5 rounded border border-gray-800 flex justify-between items-center text-xs">` +
                    `<div><span class="font-bold text-blue-300 font-mono">${this.escapeHtml(tp.routine)}</span> <span class="text-gray-400 ml-2">${this.escapeHtml(tp.type)}</span></div>` +
                    `<code class="text-emerald-400 font-mono">${this.escapeHtml(tp.line)}</code>` +
                `</div>`
            ).join("");
        } else {
            tpContainer.innerHTML = `<p class="text-xs text-gray-500 italic">No routine touchpoints logged.</p>`;
        }

        // Strict Frontend Filter: Only keep primary field definition nodes (exactly 3 comma parts: file, field_num, 0)
        const rawFields = data.fields || [];
        const fieldRows = rawFields.filter(f => {
            const key = f.node_key || "";
            if (!key.endsWith(",0")) return false;

            const parts = key.split(",");
            // Must be exactly 3 segments: [file_number, field_number, 0]
            if (parts.length !== 3) return false;

            const fieldPart = parts[1].replace(/["']/g, "").trim();
            if (!/^[0-9.]+$/.test(fieldPart)) return false;
            if (fieldPart === fileNumStr) return false;

            return true;
        });

        const tbody = document.getElementById("siFieldsBody");
        document.getElementById("siFieldCount").innerText = fieldRows.length + " fields";
        
        tbody.innerHTML = fieldRows.map(f => {
            const nodeKey = f.node_key || "";
            const val = f.value || "";
            const parts = nodeKey.split(",");

            let fieldNum = "-";
            let fieldName = "N/A";

            if (parts.length >= 2) {
                fieldNum = parts[1].replace(/["']/g, "").trim();
            }

            if (this.knownFields[fileNumStr] && this.knownFields[fileNumStr][fieldNum]) {
                fieldName = this.knownFields[fileNumStr][fieldNum];
            } else if (val.includes("^")) {
                fieldName = val.split("^")[0];
            } else {
                fieldName = val || "N/A";
            }

            return `<tr class="hover:bg-gray-900/50">` +
                `<td class="p-2.5 text-emerald-400 font-bold">${this.escapeHtml(fieldNum)}</td>` +
                `<td class="p-2.5 text-blue-300 font-semibold">${this.escapeHtml(fieldName)}</td>` +
                `<td class="p-2.5 text-gray-500 font-mono">${this.escapeHtml(nodeKey)}</td>` +
                `<td class="p-2.5 text-gray-300 break-all font-mono">${this.escapeHtml(val)}</td>` +
            `</tr>`;
        }).join("");
    }
}

window.SchemaInspector = new SchemaInspectorModule();