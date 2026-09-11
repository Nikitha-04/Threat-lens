import argparse
import glob
import json
import os
import sys

from dotenv import load_dotenv


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(description="Phishing email classifier CLI.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--train", action="store_true", help="Train and save the model.")
    group.add_argument("--score-file", metavar="PATH", help="Score a single parsed email JSON file.")
    group.add_argument("--score-dir", metavar="DIR", help="Batch-score all parsed email JSONs in directory.")
    parser.add_argument("--output-dir", default="./data/classified", help="Output directory for batch scoring.")

    args = parser.parse_args()

    if args.train:
        from classifier.train import train_model
        metrics = train_model()
        print("\n--- Training Metrics ---")
        print(f"  Accuracy:  {metrics['accuracy']:.4f}")
        print(f"  Precision: {metrics['precision']:.4f}")
        print(f"  Recall:    {metrics['recall']:.4f}")
        print(f"  F1 Score:  {metrics['f1']:.4f}")
        print(f"  Confusion Matrix: {metrics['confusion_matrix']}")

    elif args.score_file:
        from classifier.scorer import score_email
        with open(args.score_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        subject = data.get("subject", "")
        body_text = data.get("body_text", "")
        message_id = data.get("message_id", "unknown")

        result = score_email(subject, body_text)
        result["message_id"] = message_id

        print(json.dumps(result, indent=2))

    elif args.score_dir:
        from classifier.scorer import score_email
        os.makedirs(args.output_dir, exist_ok=True)

        input_files = sorted(glob.glob(os.path.join(args.score_dir, "*.json")))
        if not input_files:
            print(f"No JSON files found in {args.score_dir}")
            sys.exit(0)

        for filepath in input_files:
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    data = json.load(f)

                subject = data.get("subject", "")
                body_text = data.get("body_text", "")
                message_id = data.get("message_id", "unknown")

                result = score_email(subject, body_text)

                output = {
                    "message_id": message_id,
                    "phishing_probability": result["phishing_probability"],
                    "predicted_label": result["predicted_label"],
                    "model_version": result["model_version"],
                    "top_indicative_terms": result.get("top_indicative_terms", []),
                }

                filename = os.path.basename(filepath)
                out_path = os.path.join(args.output_dir, filename)
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(output, f, indent=2)

                print(f"Scored: {filename} -> {result['predicted_label']} ({result['phishing_probability']:.4f})")

            except Exception as e:
                print(f"Error processing {filepath}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
