import configparser
import shutil
from pathlib import Path
import sys


class ConfigCreatedError(Exception):
    """Raised when a default config file is generated on first run."""


DEFAULT_CONFIG_CONTENT = """
# Example configuration file for VirusTotalHashScanner
#VirusTotal API is mandatory to use the application.
#Gemini API is required only if you want to use the AI analysis feature.
#Result directory is optional. If not specified, results will be saved in the "Results" folder next to the application.
#Archive limits are in megabytes and apply when INCLUDE_ARCHIVES is true.

[CONFIG]
VIRUS_TOTAL_API = PasteYourVirusTotalAPIKeyHere
SEND_TO_GEMINI = false
# GEMINI_API = PasteYourGeminiAPIKeyHere
# RESULT_DIRECTORY= C:/path/to/save/results
INCLUDE_ARCHIVES = true
HASH_MAX_CONCURRENCY = 24
VT_MAX_CONCURRENCY = 8
VT_REQUESTS_PER_MIN = 0 
# 0 means no limit
GEMINI_MAX_CONCURRENCY = 4
GEMINI_REQUESTS_PER_MIN = 5 
# 0 means no limit
ARCHIVE_MAX_FILES = 5000 
# maximum number of files to scan within an archive
ARCHIVE_MAX_MB = 500 
# maximum size of files to scan within an archive in megabytes
ARCHIVE_MAX_DEPTH = 2 
# maximum depth of nested archives to scan
EXPORT_CSV = true 
# set to true to export results to CSV file
"""


def load_config(file_path, template_path="config_example.ini"):
    config_path = Path(file_path)
    template = Path(template_path)

    if not config_path.exists():
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # if template.exists():
        #     shutil.copy(template, config_path)
        # else:
        config_path.write_text(DEFAULT_CONFIG_CONTENT, encoding="utf-8")

        raise ConfigCreatedError(
            f"Configuration file not found. "
            f"A default config has been created at {config_path}. "
            f"Please update it with your settings and rerun the program."
        )

    config = configparser.ConfigParser()
    config.read(config_path, encoding="utf-8")
    return config




def load_and_validate_config(main_logger, app_dir=None, bundle_dir=None):
    try:
        config_file = load_config(
            str(app_dir / "config.ini"),
            str(bundle_dir / "config_example.ini"),
        )

        # ---- validation ----
        errors = []

        virustotal_api = config_file.get("CONFIG", "virus_total_api", fallback="")
        send_to_gemini = config_file.getboolean("CONFIG", "send_to_gemini", fallback=False)
        gemini_api = config_file.get("CONFIG", "gemini_api", fallback="")
        vt_max_concurrency = config_file.getint("CONFIG", "vt_max_concurrency", fallback=6)
        hash_max_concurrency = config_file.getint(
            "CONFIG",
            "hash_max_concurrency",
            fallback=vt_max_concurrency,
        )
        vt_requests_per_min = config_file.getint("CONFIG", "vt_requests_per_min", fallback=0)
        gemini_max_concurrency = config_file.getint("CONFIG", "gemini_max_concurrency", fallback=2)
        gemini_requests_per_min = config_file.getint("CONFIG", "gemini_requests_per_min", fallback=0)
        archive_max_files = config_file.getint("CONFIG", "archive_max_files", fallback=5000)
        archive_max_mb = config_file.getint("CONFIG", "archive_max_mb", fallback=500)
        archive_max_depth = config_file.getint("CONFIG", "archive_max_depth", fallback=2)
        include_archives = config_file.getboolean("CONFIG", "include_archives", fallback=False)
        export_csv = config_file.getboolean("CONFIG", "export_csv", fallback=False)

        if not virustotal_api:
            errors.append("virus_total_api is empty or missing.")

        if send_to_gemini and not gemini_api:
            errors.append("gemini_api required when send_to_gemini is true.")

        if vt_max_concurrency < 1:
            errors.append("vt_max_concurrency must be >= 1.")

        if vt_requests_per_min < 0:
            errors.append("vt_requests_per_min must be >= 0.")

        if hash_max_concurrency < 1:
            errors.append("hash_max_concurrency must be >= 1.")

        if gemini_max_concurrency < 1:
            errors.append("gemini_max_concurrency must be >= 1.")

        if gemini_requests_per_min < 0:
            errors.append("gemini_requests_per_min must be >= 0.")

        if errors:
            raise ValueError(" | ".join(errors))

        return config_file, None

    except ConfigCreatedError as exc:
        main_logger.error("First run setup")
        main_logger.error(exc)
        return None, 0

    except ValueError as exc:
        main_logger.error("Invalid config values:")
        main_logger.error(exc)
        return None, 1

    except Exception as exc:
        main_logger.error(f"Failed to load configuration: {exc}")
        return None, 1

