import os
from flask import Flask, render_template, request
from analyzer.url_analyzer import analyze_urls
from analyzer.file_analyzer import analyze_file
from analyzer.scorer import combine_results
from db import init_db, save_scan, get_recent_scans

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

init_db()


@app.route("/", methods=["GET", "POST"])
def index():
    report = None
    url_results = []
    file_result = None
    email_text = ""

    if request.method == "POST":
        email_text = request.form.get("email_text", "")
        url_results = analyze_urls(email_text)

        uploaded_file = request.files.get("attachment")
        saved_file_path = None
        filename = None

        if uploaded_file and uploaded_file.filename:
            filename = uploaded_file.filename
            saved_file_path = os.path.join(app.config["UPLOAD_FOLDER"], uploaded_file.filename)
            uploaded_file.save(saved_file_path)
            file_result = analyze_file(saved_file_path, uploaded_file.filename)

        report = combine_results(url_results, file_result)

        save_scan(
            email_text=email_text,
            filename=filename,
            total_score=report["total_score"],
            verdict=report["verdict"]
        )

    recent_scans = get_recent_scans()

    return render_template(
        "index.html",
        report=report,
        url_results=url_results,
        file_result=file_result,
        email_text=email_text,
        recent_scans=recent_scans
    )


if __name__ == "__main__":
    app.run(debug=True)