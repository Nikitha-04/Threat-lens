import argparse
import json
import logging
import os
import sys

from dotenv import load_dotenv

from risk.aggregator import collect_message_ids, load_all
from risk.scoring import compute_risk
from risk.pdf_report import generate_pdf

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PDF_TIERS = {"medium", "high", "critical"}


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Risk scoring and PDF report generator.")
    parser.add_argument("--forensics-dir",   default="./data/forensics")
    parser.add_argument("--geo-dir",         default="./data/geo")
    parser.add_argument("--classified-dir",  default="./data/classified")
    parser.add_argument("--reputation-dir",  default="./data/reputation")
    parser.add_argument("--output-dir",      default="./data/risk")
    parser.add_argument("--reports-dir",     default="./data/reports")
    parser.add_argument("--parsed-dir",      default="./data/parsed",
                        help="Optional: parsed email JSONs for report metadata (from/to/subject)")
    args = parser.parse_args()

    for d in (args.output_dir, args.reports_dir):
        os.makedirs(d, exist_ok=True)

    message_ids = collect_message_ids(
        args.forensics_dir, args.geo_dir, args.classified_dir, args.reputation_dir
    )

    if not message_ids:
        print("No email data found across input directories.")
        sys.exit(0)

    print(f"Processing {len(message_ids)} email(s)...\n")
    pdf_count = 0

    for mid in sorted(message_ids):
        try:
            forensics, geo, classified, reputation, completeness = load_all(
                mid, args.forensics_dir, args.geo_dir,
                args.classified_dir, args.reputation_dir
            )

            result = compute_risk(forensics, geo, classified, reputation)
            result["message_id"] = mid
            result["data_completeness"] = completeness

            out_path = os.path.join(args.output_dir, f"{mid}.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(result, f, indent=2)

            tier = result["risk_tier"]
            score = result["risk_score"]
            print(f"  [{tier.upper():8s}] {score:5.1f}  {mid}")

            # Generate PDF for medium-risk or above
            if tier in PDF_TIERS:
                email_meta = None
                parsed_path = os.path.join(args.parsed_dir, f"{mid}.json")
                if os.path.exists(parsed_path):
                    try:
                        with open(parsed_path, "r", encoding="utf-8") as f:
                            email_meta = json.load(f)
                    except Exception:
                        pass

                pdf_path = os.path.join(args.reports_dir, f"{mid}.pdf")
                generate_pdf(result, forensics, geo, classified, reputation, email_meta, pdf_path)
                size = os.path.getsize(pdf_path)
                print(f"           -> PDF saved: {pdf_path}  ({size:,} bytes)")
                pdf_count += 1

        except Exception as exc:
            logger.error("Failed processing %s: %s", mid, exc, exc_info=True)

    print(f"\nDone. {len(message_ids)} emails scored, {pdf_count} PDF(s) generated.")


if __name__ == "__main__":
    main()
