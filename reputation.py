import argparse
import glob
import json
import logging
import os
import sys

from dotenv import load_dotenv

from reputation.cache import ReputationCache
from reputation.engine import process_email

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="URL and attachment reputation checker.")
    parser.add_argument("--input-dir", required=True, help="Directory of parsed email JSON files.")
    parser.add_argument("--output-dir", required=True, help="Directory to write reputation JSON files.")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    cache = ReputationCache()

    input_files = sorted(glob.glob(os.path.join(args.input_dir, "*.json")))
    if not input_files:
        print(f"No JSON files found in {args.input_dir}")
        sys.exit(0)

    for filepath in input_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            logger.error("Could not read %s: %s", filepath, exc)
            continue

        try:
            result = process_email(data, cache)
        except Exception as exc:
            logger.error("Failed to process %s: %s", filepath, exc)
            continue

        filename = os.path.basename(filepath)
        out_path = os.path.join(args.output_dir, filename)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        flag = result["overall_reputation_flag"]
        print(
            f"Processed {filename}: {flag.upper()} "
            f"({len(result['url_checks'])} URLs, "
            f"{len(result['attachment_checks'])} attachments)"
        )


if __name__ == "__main__":
    main()
