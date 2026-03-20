import os
import hashlib

DANGEROUS_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".msi"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z"
}


def calculate_sha256(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_verdict(score):
    if score >= 75:
        return "High Risk"
    elif score >= 50:
        return "Suspicious"
    elif score >= 25:
        return "Medium Risk"
    return "Low Risk"


def analyze_filename(filename):
    reasons = []
    score = 0

    if not filename:
        return {
            "filename": None,
            "score": 0,
            "reasons": ["No file uploaded"],
            "verdict": "Low Risk"
        }

    filename_lower = filename.lower()
    _, ext = os.path.splitext(filename_lower)

    if ext in DANGEROUS_EXTENSIONS:
        score += 40
        reasons.append(f"Dangerous file extension detected: {ext}")

    if ext in MACRO_EXTENSIONS:
        score += 35
        reasons.append(f"Macro-enabled Office file detected: {ext}")

    if ext in ARCHIVE_EXTENSIONS:
        score += 10
        reasons.append(f"Archive file uploaded: {ext}")

    parts = filename_lower.split(".")
    if len(parts) >= 3:
        score += 25
        reasons.append("Possible double extension detected")

    suspicious_words = ["invoice", "payment", "urgent", "account", "bank", "statement"]
    for word in suspicious_words:
        if word in filename_lower:
            score += 5
            reasons.append(f"Suspicious word in filename: {word}")

    verdict = get_verdict(score)

    return {
        "filename": filename,
        "score": score,
        "reasons": reasons,
        "verdict": verdict
    }


def analyze_file(file_path, original_filename):
    base_result = analyze_filename(original_filename)

    if file_path and os.path.exists(file_path):
        try:
            base_result["sha256"] = calculate_sha256(file_path)
            base_result["size_bytes"] = os.path.getsize(file_path)
        except Exception as e:
            base_result["hash_error"] = str(e)

    return base_result