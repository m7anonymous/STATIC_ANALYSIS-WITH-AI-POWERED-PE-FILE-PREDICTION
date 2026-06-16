from scanner import run_static_scan
from predict import run_ai_scan
from fusion import fuse_reports

file_path = input("Enter file path: ")

static_result = run_static_scan(file_path)

ai_result = run_ai_scan(file_path)

final_result = fuse_reports(
    static_result,
    ai_result
)

print(
    final_result["final_verdict"]
)