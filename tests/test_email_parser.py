import os
import shutil
import pytest
from parsers.email_parser import parse_email, extract_links

@pytest.fixture
def sample_eml():
    eml_path = os.path.join(os.path.dirname(__file__), "sample.eml")
    with open(eml_path, "rb") as f:
        return f.read()

@pytest.fixture
def temp_attach_dir(tmpdir):
    return str(tmpdir.mkdir("attachments"))

def test_parse_email_basic_fields(sample_eml, temp_attach_dir):
    parsed = parse_email(sample_eml, temp_attach_dir)
    
    assert parsed["message_id"] == "test12345@example.com"
    assert parsed["subject"] == "Test Email with Attachments and Links"
    assert parsed["from"]["email"] == "alice@example.com"
    assert parsed["from"]["name"] == "Alice Sender"
    assert len(parsed["to"]) == 1
    assert parsed["to"][0]["email"] == "bob@example.com"
    assert parsed["reply_to"] == "alice-alt@example.com"
    
def test_parse_email_received_chain(sample_eml, temp_attach_dir):
    parsed = parse_email(sample_eml, temp_attach_dir)
    
    chain = parsed["received_chain"]
    assert len(chain) == 2
    assert "mail.example.com [192.168.1.1]" in chain[0]
    assert "localhost by mail.example.com" in chain[1]
    
def test_parse_email_links(sample_eml, temp_attach_dir):
    parsed = parse_email(sample_eml, temp_attach_dir)
    
    links = parsed["links"]
    assert "https://example.com/threat" in links
    assert "http://www.test.com" in links
    
def test_parse_email_attachments(sample_eml, temp_attach_dir):
    parsed = parse_email(sample_eml, temp_attach_dir)
    
    attachments = parsed["attachments"]
    assert len(attachments) == 1
    att = attachments[0]
    assert att["filename"] == "malware.txt"
    assert att["content_type"] == "text/plain"
    
    # Check if file was saved
    assert os.path.exists(att["saved_path"])
    with open(att["saved_path"], "r") as f:
        content = f.read()
    assert content.strip() == "This is a dangerous attachment!"
    
def test_parse_malformed_email(temp_attach_dir):
    # Minimal invalid email
    raw = b"Just some garbage bytes with no headers\n\nBody"
    parsed = parse_email(raw, temp_attach_dir)
    
    # Should not crash, fallback message ID to hash
    assert parsed["message_id"] != ""
    assert parsed["subject"] == ""
    assert parsed["body_text"] == "Just some garbage bytes with no headers\n\nBody"
    
def test_extract_links():
    text = "Here is a link https://text.com/path and www.other.com. Also [markdown](https://www.test.com) should not duplicate www.test.com."
    html = '<html><body><a href="https://html.com">link</a></body></html>'
    
    links = extract_links(text, html)
    assert "https://text.com/path" in links
    assert "www.other.com" in links
    assert "https://html.com" in links
    assert "https://www.test.com" in links
    assert "www.test.com" not in links # Should be deduplicated


def test_attachment_sha256_length(sample_eml, temp_attach_dir):
    parsed = parse_email(sample_eml, temp_attach_dir)
    attachments = parsed['attachments']
    assert len(attachments) > 0
    for att in attachments:
        sha256_hash = att['sha256']
        assert len(sha256_hash) == 64
        assert all(c in '0123456789abcdef' for c in sha256_hash)


def test_deduplicate_links_tracking_params():
    from parsers.email_parser import deduplicate_links
    raw_urls = [
        "https://example.com/welcome?utm_source=newsletter&utm_medium=email",
        "https://example.com/welcome?utm_campaign=winter_promo",
        "https://example.com/welcome",
        "https://example.com/other-page?utm_source=twitter",
        "https://example.com/other-page",
        "https://example.com/search?q=threats",
    ]
    deduped = deduplicate_links(raw_urls)
    # The 3 /welcome variants collapse into 1, the 2 /other-page variants collapse into 1, /search?q=threats stays
    assert len(deduped) == 3
    assert deduped[0] == "https://example.com/welcome?utm_source=newsletter&utm_medium=email"
    assert deduped[1] == "https://example.com/other-page?utm_source=twitter"
    assert deduped[2] == "https://example.com/search?q=threats"
