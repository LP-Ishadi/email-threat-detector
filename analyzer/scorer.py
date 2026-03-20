def get_verdict(score):
    if score >= 100:
        return "High Risk"
    elif score >= 60:
        return "Suspicious"
    elif score >= 25:
        return "Medium Risk"
    return "Low Risk"


def combine_results(url_results, file_result):
    total_score = 0
    all_reasons = []

    for result in url_results:
        total_score += result["score"]
        all_reasons.extend([f"URL: {r}" for r in result["reasons"]])

    if file_result:
        total_score += file_result.get("score", 0)
        all_reasons.extend([f"File: {r}" for r in file_result.get("reasons", [])])

    verdict = get_verdict(total_score)

    return {
        "total_score": total_score,
        "verdict": verdict,
        "reasons": all_reasons
    }