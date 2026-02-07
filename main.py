from utils import config,hash,logger,parser,scan,report,AI
import asyncio
from collections import deque
import os
import sys
import time
from pathlib import Path
from alive_progress import alive_bar



# ===========================
#functions
# ===========================

# Get variables from config and args
def get_variables(configuration):
    virustotal_api = configuration.get("CONFIG", "virus_total_api", fallback="")
    send_to_gemini = configuration.getboolean("CONFIG", "send_to_gemini", fallback=False)
    gemini_api = configuration.get("CONFIG", "gemini_api", fallback="")
    default_results_dir = str(get_app_dir() / "Results")
    result_directory = configuration.get("CONFIG", "result_directory", fallback=default_results_dir)
    export_csv = configuration.getboolean("CONFIG", "export_csv", fallback=False)
    target_path = parser.get_args()
    include_archives = configuration.getboolean("CONFIG", "include_archives", fallback=False)
    vt_max_concurrency = configuration.getint("CONFIG", "vt_max_concurrency", fallback=6)
    hash_max_concurrency = configuration.getint(
        "CONFIG",
        "hash_max_concurrency",
        fallback=vt_max_concurrency,
    )
    vt_requests_per_min = configuration.getint("CONFIG", "vt_requests_per_min", fallback=0)
    gemini_max_concurrency = configuration.getint("CONFIG", "gemini_max_concurrency", fallback=2)
    gemini_requests_per_min = configuration.getint("CONFIG", "gemini_requests_per_min", fallback=0)
    archive_max_files = configuration.getint("CONFIG", "archive_max_files", fallback=5000)
    archive_max_megabytes = configuration.getint("CONFIG", "archive_max_mb", fallback=500)
    archive_max_mb = max(0, archive_max_megabytes) * 1024 * 1024
    archive_max_depth = configuration.getint("CONFIG", "archive_max_depth", fallback=2)
    archive_limits = hash.ArchiveLimits(
        max_files=archive_max_files,
        max_mb=archive_max_mb,
        max_depth=archive_max_depth,
    )
    return (
        virustotal_api,
        send_to_gemini,
        gemini_api,
        result_directory,
        export_csv,
        target_path,
        include_archives,
        vt_max_concurrency,
        hash_max_concurrency,
        vt_requests_per_min,
        gemini_max_concurrency,
        gemini_requests_per_min,
        archive_limits,
    )    

# Load application directory
def get_app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

# Load bundle directory
def get_bundle_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def save_report(html_content: str, result_directory: str, filename: str) -> None:
    os.makedirs(result_directory, exist_ok=True)
    with open(os.path.join(result_directory, filename), "w", encoding="utf-8") as f:
        f.write(html_content)


class RateLimiter:
    def __init__(self, max_per_minute: int):
        self._max_per_minute = max_per_minute
        self._events = deque()
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if self._max_per_minute <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            window = 60.0
            while self._events and now - self._events[0] >= window:
                self._events.popleft()
            if len(self._events) >= self._max_per_minute:
                sleep_for = window - (now - self._events[0])
                await asyncio.sleep(max(sleep_for, 0.0))
                now = time.monotonic()
                while self._events and now - self._events[0] >= window:
                    self._events.popleft()
            self._events.append(time.monotonic())


async def scan_files_async(
    virustotal_api: str,
    files: list,
    max_concurrency: int,
    requests_per_min: int,
    send_to_gemini: bool,
    gemini_api: str,
    gemini_max_concurrency: int,
    gemini_requests_per_min: int,
    bar,
):
    results = []
    not_found_files = []
    caution_files = []
    limiter = RateLimiter(requests_per_min) if requests_per_min > 0 else None
    gemini_limiter = RateLimiter(gemini_requests_per_min) if gemini_requests_per_min > 0 else None
    semaphore = asyncio.Semaphore(max_concurrency)
    gemini_semaphore = asyncio.Semaphore(gemini_max_concurrency)

    async def worker(file_res):
        try:
            if limiter:
                await limiter.wait()
            async with semaphore:
                updated = await scan.scan_file_async(virustotal_api, file_res)
            if send_to_gemini and (updated.result == "CAUTION" or updated.result == "SUSPICIOUS"):
                try:
                    if gemini_limiter:
                        await gemini_limiter.wait()
                    async with gemini_semaphore:
                        updated.gemini = await AI.analyze_result_async(
                            gemini_api,
                            updated,
                        )
                except Exception as exc:
                    updated.gemini = f"Gemini error: {exc}"
            return updated
        except Exception as exc:
            file_res.error = f"Async scan error: {exc}"
            return file_res

    tasks = [asyncio.create_task(worker(file_res)) for file_res in files]
    for task in asyncio.as_completed(tasks):
        updated = await task
        if updated.result == "CAUTION" or updated.result == "SUSPICIOUS":
            caution_files.append(updated)
        if updated.result == "UNKNOWN" and updated.error == "Not found in VirusTotal":
            not_found_files.append(updated)
        results.append(updated)
        bar()

    return results, not_found_files, caution_files




# ==================
# MAIN
# ==================

def main():    
    
    # Logger
    current_date = time.strftime("%Y_%m_%d")
    main_logger = logger.setup_logger(name=f"VirusTotal_{current_date}")

    # Check config and exit if problem
    config_file, early_exit_code = config.load_and_validate_config(main_logger, app_dir=get_app_dir(),bundle_dir=get_bundle_dir())
    if early_exit_code is not None:
        main_logger.info("VirusTotalHashScanner exited while loading configuration.")
        main_logger.info("--------------------------------")
        return early_exit_code

    # Get variables from config and args
    (
        virustotal_api,
        send_to_gemini,
        gemini_api,
        result_directory,
        export_csv,
        target_path,
        include_archives,
        vt_max_concurrency,
        hash_max_concurrency,
        vt_requests_per_min,
        gemini_max_concurrency,
        gemini_requests_per_min,
        archive_limits,
    ) = get_variables(config_file)

    vt_max_concurrency = max(1, vt_max_concurrency)
    hash_max_concurrency = max(1, hash_max_concurrency)
    vt_requests_per_min = max(0, vt_requests_per_min)
    gemini_max_concurrency = max(1, gemini_max_concurrency)
    gemini_requests_per_min = max(0, gemini_requests_per_min)

    # Check API key
    if not scan.check_api_key(virustotal_api):
        main_logger.error("VirusTotal API key is invalid. Please check your configuration.")
        main_logger.info("VirusTotalHashScanner exited due to invalid VirusTotal API key.")
        main_logger.info("--------------------------------")
        return 1


    seven_zip_path = None
    if include_archives:
        try:
            seven_zip_path = hash.ensure_7z_available()
        except Exception as e:
            main_logger.error(str(e))
            main_logger.info("VirusTotalHashScanner exited due to missing 7-Zip.")
            main_logger.info("--------------------------------")
            return 1

    # Count files
    total_files = hash.count_files(
        target_path,
        include_archives=include_archives,
        archive_limits=archive_limits,
        seven_zip_path=seven_zip_path,
    )

    # Start main process
    main_logger.info("--------------------------------")
    main_logger.info("VirusTotal Scanner started.")
    main_logger.info(f"Target path: {target_path}")
    main_logger.info(f"Results directory: {result_directory}")
    main_logger.info(f"Include archives: {include_archives}")
    main_logger.info(f"Hash concurrency: {hash_max_concurrency}")
    main_logger.info(f"Scan concurrency: {vt_max_concurrency}")
    main_logger.info(f"Scan requests per minute: {vt_requests_per_min if vt_requests_per_min > 0 else 'unlimited'}")
    main_logger.info(f"Gemini concurrency: {gemini_max_concurrency}")
    main_logger.info(f"Gemini requests per minute: {gemini_requests_per_min if gemini_requests_per_min > 0 else 'unlimited'}")
    main_logger.info(
        "Archive limits - files: %s | megabytes: %s | depth: %s",
        archive_limits.max_files,
        archive_limits.max_mb,
        archive_limits.max_depth,
    )
    main_logger.info(f"Total files to scan: {total_files}")
    main_logger.info("--------------------------------")


    # Initialize lists
    hashed_files = []
    results = []
    not_found_files = []
    caution_files = []

    # Hash files
    main_logger.info("Hashing files...")
    
    try:
        with alive_bar(total_files, title="Hashing") as bar:
            hashed_files = asyncio.run(
                hash.walk_and_hash_async(
                    target_path,
                    include_archives=include_archives,
                    archive_limits=archive_limits,
                    seven_zip_path=seven_zip_path,
                    max_concurrency=hash_max_concurrency,
                    progress_cb=bar,
                )
            )
    except Exception as e:
        main_logger.error(f"Error during hashing files: {e}")
        return 1
    main_logger.info("Hashing completed.")

    # Scan files
    main_logger.info("Scanning files...")
    try:
        with alive_bar(total_files, title="Scanning") as bar:
            results, not_found_files, caution_files = asyncio.run(
                scan_files_async(
                    virustotal_api=virustotal_api,
                    files=hashed_files,
                    max_concurrency=vt_max_concurrency,
                    requests_per_min=vt_requests_per_min,
                    send_to_gemini=send_to_gemini,
                    gemini_api=gemini_api,
                    gemini_max_concurrency=gemini_max_concurrency,
                    gemini_requests_per_min=gemini_requests_per_min,
                    bar=bar,
                )
            )
    except Exception as e:
        main_logger.error(f"Error during scanning files: {e}")
        return 1
    
    main_logger.info("Scanning completed.")

    # Generate full report
    main_logger.info("Generating reports...")
    try:
        # Generate full report
        html_report = report.generate_report(results, path_to_scan=target_path, title="VirusTotalHashScanner - Full Report")
                
        save_report(html_report, result_directory, f"scan_report_full_{current_date}.html")
            
    except Exception as e:
        main_logger.error(f"Error during generating report: {e}")
        return 1
    

    # Generate not found report
    if not_found_files:
        try:
            html_report_nf = report.generate_report(not_found_files, path_to_scan=target_path, title="VirusTotalHashScanner - Not Found Files")
            save_report(html_report_nf, result_directory, f"scan_report_not_found_{current_date}.html")
        except Exception as e:
            main_logger.error(f"Error during generating [not found report]: {e}")
            
    
    # Generate caution report
    if caution_files:
        try:
            html_report_caution = report.generate_report(caution_files, path_to_scan=target_path, title="VirusTotalHashScanner - Caution Files")
            save_report(html_report_caution, result_directory, f"scan_report_caution_{current_date}.html")
        except Exception as e:
            main_logger.error(f"Error during generating [caution report]: {e}")
            

    main_logger.info(f"Reports generated in: {result_directory}")

    # Export to CSV if enabled
    if export_csv:
        csv_path = os.path.join(result_directory, f"scan_report_{current_date}.csv")
        try:
            report.export_to_csv(results, csv_path)
            main_logger.info(f"CSV report exported to: {csv_path}")
        except Exception as e:
            main_logger.error(f"Error during exporting CSV report: {e}")



    main_logger.info("VirusTotal Scanner finished.")
    main_logger.info("--------------------------------")
    return 0 #success


if __name__ == "__main__":
    raise SystemExit(main())


# To ADD
# Repoert HTML name and scanned location
