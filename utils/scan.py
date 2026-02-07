import asyncio
from typing import Any

import requests
from utils.hash import FileScanResult

def check_api_key(api_key: str) -> bool:
    url = "https://www.virustotal.com/api/v3/users/me"
    headers = {
        "x-apikey": api_key
    }

    response = requests.get(url, headers=headers)

    return response.status_code == 200

def scan_file(api_key: str, file_res: FileScanResult) -> FileScanResult:
    if file_res.error:
        return file_res
    if not file_res.sha256:
        file_res.error = "Missing SHA256"
        return file_res

    url = f"https://www.virustotal.com/api/v3/files/{file_res.sha256}"
    headers = {"x-apikey": api_key}

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data: Any = response.json()
            attr = data["data"]["attributes"]

            # --- stats ---
            stats = attr.get("last_analysis_stats", {})
            mal = stats.get("malicious", 0)
            susp = stats.get("suspicious", 0)
            und = stats.get("undetected", 0)

            # --- severity ---
            severity = (
                attr.get("threat_severity", {})
                .get("threat_severity_level", "UNKNOWN")
                .replace("SEVERITY_", "")
            )

            # --- label ---
            label = (
                attr.get("popular_threat_classification", {})
                .get("suggested_threat_label", "unknown")
            )

            # --- type ---
            type_desc = attr.get("type_description", "unknown")
            type_ext = attr.get("type_extension", "")
            file_type = f"{type_desc} (.{type_ext})" if type_ext else type_desc

            # --- sandbox verdict ---
            sandbox_dict = attr.get("sandbox_verdicts", {})
            sandbox_verdict = "unknown"
            for sb in sandbox_dict.values():
                cat = sb.get("category")
                if cat == "malicious":
                    sandbox_verdict = "malicious"
                    break
                sandbox_verdict = cat or sandbox_verdict

            # --- name ---
            name = attr.get("meaningful_name", file_res.filename)

            #is_harmless = mal < 4 and susp < 4 and sandbox_verdict != "malicious"

         

            file_res.name = file_res.filename# name
            file_res.malicious = mal
            file_res.suspicious = susp
            file_res.undetected = und
            file_res.severity = severity
            file_res.label = label
            file_res.file_type = file_type
            file_res.sandbox = sandbox_verdict
           # file_res.result = "HARMLESS" if is_harmless else "CAUTION"
            if (mal > 2 or susp > 2) and sandbox_verdict == "malicious":
                file_res.result = "CAUTION"
            elif mal < 1 and sandbox_verdict == "malicious":
                file_res.result = "SUSPICIOUS"
            else:
                file_res.result = "HARMLESS"

            return file_res

        elif response.status_code == 404:
            file_res.error = "Not found in VirusTotal"
            file_res.result = "UNKNOWN"
            return file_res

        else:
            file_res.error = f"HTTP {response.status_code}"
            return file_res

    except requests.RequestException as e:
        file_res.error = str(e)
        return file_res


async def scan_file_async(api_key: str, file_res: FileScanResult) -> FileScanResult:
    return await asyncio.to_thread(scan_file, api_key, file_res)
