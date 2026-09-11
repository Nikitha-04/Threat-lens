import os
import glob
import json
import pytest
import joblib
import shutil
import tempfile


# ── fixtures ────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session", autouse=True)
def trained_model():
    """Ensure a model exists before any test runs. Uses existing or trains a tiny one."""
    model_path = "./data/model/classifier.pkl"
    if os.path.exists(model_path):
        return  # already trained

    from classifier.train import train_model
    train_model()


# ── scorer tests ─────────────────────────────────────────────────────────────

def test_score_phishing_email():
    from classifier.scorer import score_email
    result = score_email(
        subject="Urgent: verify your account",
        body_text="Click here to update your password immediately or your account will be locked.",
    )
    assert isinstance(result, dict)
    assert "phishing_probability" in result
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["predicted_label"] in ("phishing", "legitimate")
    assert result["model_version"] == "baseline_v1.0"


def test_score_legitimate_email():
    from classifier.scorer import score_email
    result = score_email(
        subject="Team standup notes",
        body_text="Hi team, here are the notes from today's standup. We discussed the quarterly roadmap.",
    )
    assert isinstance(result, dict)
    assert 0.0 <= result["phishing_probability"] <= 1.0
    assert result["predicted_label"] in ("phishing", "legitimate")


def test_score_empty_body():
    from classifier.scorer import score_email
    result = score_email(subject="Hello", body_text="")
    assert isinstance(result, dict)
    assert 0.0 <= result["phishing_probability"] <= 1.0


def test_score_none_inputs():
    from classifier.scorer import score_email
    result = score_email(subject=None, body_text=None)
    assert isinstance(result, dict)
    assert 0.0 <= result["phishing_probability"] <= 1.0


# ── model persistence test ───────────────────────────────────────────────────

def test_model_save_load_roundtrip(tmp_path):
    from classifier.scorer import score_email
    import classifier.scorer as scorer_module

    # Force reload from the real model path
    scorer_module._model_pipeline = None
    result = score_email("Test subject", "Some body text")
    assert 0.0 <= result["phishing_probability"] <= 1.0

    # Reload from a copy in tmp_path to verify portability
    src = "./data/model/classifier.pkl"
    dst = str(tmp_path / "classifier.pkl")
    shutil.copy(src, dst)

    loaded = joblib.load(dst)
    preds = loaded.predict(["click here to verify your account"])
    assert preds[0] in (0, 1)


# ── batch scoring test ────────────────────────────────────────────────────────

def test_batch_scoring(tmp_path):
    input_dir = tmp_path / "parsed"
    output_dir = tmp_path / "classified"
    input_dir.mkdir()
    output_dir.mkdir()

    # Write two fake parsed email JSONs
    emails = [
        {"message_id": "msg001", "subject": "Win a prize now!", "body_text": "Click here to claim your reward."},
        {"message_id": "msg002", "subject": "Meeting tomorrow", "body_text": "Can we meet at 10am?"},
    ]
    for email in emails:
        path = input_dir / f"{email['message_id']}.json"
        path.write_text(json.dumps(email), encoding="utf-8")

    # Run batch scoring
    import subprocess, sys
    result = subprocess.run(
        [sys.executable, "classify.py", "--score-dir", str(input_dir), "--output-dir", str(output_dir)],
        capture_output=True, text=True
    )
    assert result.returncode == 0

    output_files = list(output_dir.glob("*.json"))
    assert len(output_files) == 2

    for out_file in output_files:
        data = json.loads(out_file.read_text())
        assert "message_id" in data
        assert "phishing_probability" in data
        assert "predicted_label" in data
        assert "top_indicative_terms" in data
