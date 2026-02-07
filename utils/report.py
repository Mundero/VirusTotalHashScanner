from datetime import datetime
import csv


def generate_report(scan_results: list,title="Virus Scan Report",path_to_scan="") -> str:

    html = f"""
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
body {{
  font-family: "Segoe UI", Arial, sans-serif;
  background: #f5f7fa;
  padding: 30px;
  color: #222;
}}

/* HEADER */
.header-card {{
  max-width: 900px;
  margin: 0 auto 25px auto;
  background: white;
  border-radius: 14px;
  padding: 22px 28px;
  text-align: center;
  box-shadow: 0 10px 30px rgba(0,0,0,0.08);
}}

.header-card h1 {{
  margin-top: 0;
  margin-bottom: 12px;
  font-size: 1.8em;
  letter-spacing: 0.3px;
}}

.header-card p {{
  margin: 4px 0;
  color: #4b5563;
  font-size: 0.95em;
}}


/* TABLE */
table {{ border-collapse: collapse; width:100%; background:white;  }}
th, td {{ border:1px solid #ccc; padding:8px;}}
th {{ 
  background: #1f2933;
  color: white;
  font-weight: 600;
  letter-spacing: 0.3px; 
    color:white;
    cursor: pointer; 
    user-select: none; }}
.sort-indicator {{
    font-size: 0.8em;
    margin-left: 6px;
    opacity: 0.8;
}}
.container {{
  margin: auto;
  background: white;
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0,0,0,0.08);
  padding: 24px 28px;
}}

/* If gemini exists */
.col-gemini {{
    min-width: 350px;
    width: 350px;
    word-break: break-word;
}}

td.wrap {{
  white-space: normal;
  word-break: break-word;
}}

.col-sha {{
  max-width: 400px;
  word-break: break-all;
}}
.row-caution {{
    background: rgba(255, 0, 0, 0.7);
}}
.row-suspicious {{
    background: rgba(255, 165, 0, 0.7);
}}
.row-archive {{
    background: #2a8bdb;
    
}}

.row-unknown {{
    background: rgba(184, 184, 184, 0.7);
}}
</style>
</head>
<body>
<div class="header-card">
<h1>{title}</h1>
<p><strong>Scanned path:</strong> {path_to_scan}</p>

"""

    run_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    html += f"<p><strong>Run date:</strong> {run_date}</p>\n"
    html += "</div>\n"
    html += "<div class='container'>\n"
    html += "<table id='scan-table'>\n"

    show_gemini = any(getattr(res, "gemini", None) for res in scan_results)
    show_error = any(getattr(res, "error", None) for res in scan_results)

    html += (
        "<thead><tr>"
        "<th  data-type='string'>Name<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Path<span class='sort-indicator'></span></th>"
        "<th data-type='number'>Malicious<span class='sort-indicator'></span></th>"
        "<th data-type='number'>Suspicious<span class='sort-indicator'></span></th>"
        "<th data-type='number'>Undetected<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Severity<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Label<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Type<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Sandbox<span class='sort-indicator'></span></th>"
        "<th data-type='string'>Result<span class='sort-indicator'></span></th>"
        + ("<th class='col-gemini' data-type='string'>Gemini<span class='sort-indicator'></span></th>" if show_gemini else "")
        + ("<th data-type='string'>Error<span class='sort-indicator'></span></th>" if show_error else "")
        + "<th class='col-sha' data-type='string'>SHA256<span class='sort-indicator'></span></th>"
        "</tr></thead>\n<tbody>\n"
    )
    for res in scan_results:
        error = res.error or ""
        result = res.result or ""
        if error.startswith("Archive"):
            row_class = " class='row-archive'"
        elif result == "CAUTION":
            row_class = " class='row-caution'"
        elif result == "SUSPICIOUS":
            row_class = " class='row-suspicious'"
        elif result == "UNKNOWN":
            row_class = " class='row-unknown'"
        else:
            row_class = ""
        
        html += (
            f"<tr{row_class}>"
            f"<td class='wrap'>{res.name or res.filename}</td>"
            f"<td class='wrap'>{res.path}</td>"
            f"<td>{res.malicious}</td>"
            f"<td>{res.suspicious}</td>"
            f"<td>{res.undetected}</td>"
            f"<td>{res.severity or ''}</td>"
            f"<td>{res.label or ''}</td>"
            f"<td class='wrap'>{res.file_type or ''}</td>"
            f"<td>{res.sandbox or ''}</td>"
            f"<td>{res.result or ''}</td>"
            + (f"<td class='col-gemini'>{res.gemini or ''}</td>" if show_gemini else "")
            + (f"<td class='wrap'>{res.error or ''}</td>" if show_error else "")
            + f"<td class='col-sha'>{res.sha256 or ''}</td>"
            "</tr>\n"
        )

        # Script for sortable table
    html += (
        "</tbody></table>\n"
        "</div>\n"
        "<script>\n"
        "const table = document.getElementById('scan-table');\n"
        "const headers = table.querySelectorAll('thead th');\n"
        "const getCell = (row, idx) => (row.children[idx]?.innerText || '').trim();\n"
        "const isNumericColumn = (rows, idx) => rows.every(r => {\n"
        "  const v = getCell(r, idx);\n"
        "  return v !== '' && !Number.isNaN(Number(v));\n"
        "});\n"
        "headers.forEach(th => {\n"
        "  th.addEventListener('click', () => {\n"
        "    const tbody = table.tBodies[0];\n"
        "    const rows = Array.from(tbody.querySelectorAll('tr'));\n"
        "    const idx = th.cellIndex;\n"
        "    const type = th.dataset.type || (isNumericColumn(rows, idx) ? 'number' : 'string');\n"
        "    const asc = !th.classList.contains('asc');\n"
        "    headers.forEach(h => { h.classList.remove('asc', 'desc'); h.querySelector('.sort-indicator').textContent = ''; });\n"
        "    th.classList.add(asc ? 'asc' : 'desc');\n"
        "    th.querySelector('.sort-indicator').textContent = asc ? '▲' : '▼';\n"
        "    rows.sort((a, b) => {\n"
        "      const va = getCell(a, idx);\n"
        "      const vb = getCell(b, idx);\n"
        "      if (type === 'number') {\n"
        "        return (Number(va) - Number(vb)) * (asc ? 1 : -1);\n"
        "      }\n"
        "      return va.localeCompare(vb) * (asc ? 1 : -1);\n"
        "    });\n"
        "    rows.forEach(r => tbody.appendChild(r));\n"
        "  });\n"
        "});\n"
        "</script>\n"
        "</body>\n</html>"
    )
    html += f"<p>VirusTotalHashScanner powered by Mundero</p>\n"
    html += "<p><a href=\"https://github.com/Mundero\">Github</a></p>\n"
    return html



def export_to_csv(scan_results: list, csv_path: str):
    fieldnames = ["name", "path", "malicious", "suspicious", "undetected", "severity", "label", "file_type", "sandbox", "result", "gemini", "error", "sha256"]
    seen_paths = set()
    with open(csv_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for res in scan_results:
            path_value = str(res.path or "")
            if path_value in seen_paths:
                continue
            seen_paths.add(path_value)
            writer.writerow({
                "name": res.filename or "",
                "path": path_value,
                "malicious": res.malicious,
                "suspicious": res.suspicious,
                "undetected": res.undetected,
                "severity": res.severity or "",
                "label": res.label or "",
                "file_type": res.file_type or "",
                "sandbox": res.sandbox or "",
                "result": res.result or "",
                "gemini": getattr(res, 'gemini', '') or "",
                "error": getattr(res, 'error', '') or "",
                "sha256": res.sha256 or ""
            })

