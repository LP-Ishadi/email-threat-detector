import os
import hashlib
import mimetypes
import filetype

DANGEROUS_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".scr", ".bat", ".cmd", ".ps1", ".msi"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z"
}

EXPECTED_MIME_PREFIXES = {
    ".pdf": ["application/pdf"],
    ".png": ["image/png"],
    ".jpg": ["image/jpeg"],
    ".jpeg": ["image/jpeg"],
    ".gif": ["image/gif"],
    ".zip": ["application/zip", "application/x-zip-compressed"],
    ".docx": ["application/zip"],
    ".xlsx": ["application/zip"],
    ".pptx": ["application/zip"],
    ".docm": ["application/zip"],
    ".xlsm": ["application/zip"],
    ".pptm": ["application/zip"],
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


def detect_real_file_type(file_path):
    kind = filetype.guess(file_path)
    if kind is None:
        return None, None
    return kind.mime, kind.extension


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


def check_mime_consistency(file_path, original_filename, current_score, current_reasons):
    filename_lower = original_filename.lower()
    _, ext = os.path.splitext(filename_lower)

    guessed_mime_by_name, _ = mimetypes.guess_type(original_filename)
    detected_mime, detected_ext = detect_real_file_type(file_path)

    result = {
        "name_based_mime": guessed_mime_by_name,
        "detected_mime": detected_mime,
        "detected_extension": detected_ext,
    }

    if detected_mime:
        if ext in EXPECTED_MIME_PREFIXES:
            expected_mimes = EXPECTED_MIME_PREFIXES[ext]
            if detected_mime not in expected_mimes:
                current_score += 20
                current_reasons.append(
                    f"MIME mismatch detected: extension {ext} does not match detected type {detected_mime}"
                )
        elif guessed_mime_by_name and guessed_mime_by_name != detected_mime:
            current_score += 15
            current_reasons.append(
                f"Possible MIME mismatch: filename suggests {guessed_mime_by_name}, detected type is {detected_mime}"
            )

    return current_score, current_reasons, result


def analyze_file(file_path, original_filename):
    base_result = analyze_filename(original_filename)

    if file_path and os.path.exists(file_path):
        try:
            base_result["sha256"] = calculate_sha256(file_path)
            base_result["size_bytes"] = os.path.getsize(file_path)

            updated_score, updated_reasons, mime_info = check_mime_consistency(
                file_path,
                original_filename,
                base_result["score"],
                base_result["reasons"]
            )

            base_result["score"] = updated_score
            base_result["reasons"] = updated_reasons
            base_result["name_based_mime"] = mime_info["name_based_mime"]
            base_result["detected_mime"] = mime_info["detected_mime"]
            base_result["detected_extension"] = mime_info["detected_extension"]
            base_result["verdict"] = get_verdict(base_result["score"])

        except Exception as e:
            base_result["hash_error"] = str(e)

    return base_result