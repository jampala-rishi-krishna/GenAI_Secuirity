import argparse
import json
import math
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional

import pandas as pd
import requests


def map_risk(security_level: Optional[str]) -> str:
	level = (security_level or "").lower()
	if level in ("critical", "high"):
		return "High"
	if level == "medium":
		return "Medium"
	return "Low"


def _none_if_nan(value: Any) -> Optional[Any]:
	if value is None:
		return None
	# pandas empty cells often come as float('nan')
	if isinstance(value, float) and math.isnan(value):
		return None
	# treat empty strings as None where appropriate
	if isinstance(value, str) and value.strip() == "":
		return None
	return value


def call_chat(api_base: str, token: str, prompt: Any, session_id: Optional[Any], user_role: Optional[Any]) -> Dict[str, Any]:
	url = f"{api_base.rstrip('/')}/api/v1/chat/send"
	headers = {
		"Authorization": f"Bearer {token}",
		"Content-Type": "application/json",
		"Accept": "application/json",
	}
	# sanitize incoming values from Excel
	prompt_str = str(_none_if_nan(prompt) or "").strip()
	session_id_clean = _none_if_nan(session_id)
	user_role_clean = _none_if_nan(user_role) or "guest"

	payload: Dict[str, Any] = {
		"message": prompt_str,
		"session_id": session_id_clean,
		"user_role": user_role_clean,
	}
	try:
		resp = requests.post(url, headers=headers, json=payload, timeout=60)
		if not resp.ok:
			return {"status": "error", "error_detail": f"{resp.status_code} {resp.text}"}
		data = resp.json()
		security_report = data.get("security_report") or {}
		advisory = security_report.get("advisory") or {}
		return {
			"status": "ok",
			"response": data.get("response"),
			"session_id": data.get("session_id"),
			"timestamp": data.get("timestamp"),
			"confidence_score": data.get("confidence_score"),
			"security_level": data.get("security_level"),
			"risk_band": map_risk(data.get("security_level")),
			"requires_verification": advisory.get("requires_verification"),
			"medical_disclaimer": data.get("medical_disclaimer"),
			"input_security": security_report.get("input_security"),
			"output_security": security_report.get("output_security"),
		}
	except Exception as e:
		return {"status": "error", "error_detail": str(e)}


def main() -> None:
	parser = argparse.ArgumentParser(description="Batch test chat prompts from an Excel file.")
	parser.add_argument("--api", required=True, help="Backend base URL, e.g. http://127.0.0.1:8000")
	parser.add_argument("--token", required=True, help="Bearer access token for Authorization header")
	parser.add_argument("--in", dest="input_path", required=True, help="Path to input Excel (.xlsx) containing 'prompt' column")
	parser.add_argument("--out", dest="output_path", required=True, help="Path to output Excel (.xlsx)")
	parser.add_argument("--concurrency", type=int, default=5, help="Number of parallel requests (default: 5)")
	args = parser.parse_args()

	# Read input Excel
	df = pd.read_excel(args.input_path)
	if "prompt" not in df.columns:
		raise ValueError("Input Excel must contain a 'prompt' column")

	# Prepare tasks
	results = []
	futures = []
	with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
		for _, row in df.iterrows():
			prompt = row.get("prompt")
			session_id = row.get("session_id") if "session_id" in df.columns else None
			user_role = row.get("user_role") if "user_role" in df.columns else "guest"
			fut = executor.submit(call_chat, args.api, args.token, prompt, session_id, user_role)
			futures.append((prompt, fut))

		# Collect results in the same order as input
		for prompt, fut in futures:
			res = fut.result()
			row_out = {
				"prompt": prompt,
				"response": res.get("response"),
				"session_id": res.get("session_id"),
				"timestamp": res.get("timestamp"),
				"confidence_score": res.get("confidence_score"),
				"security_level": res.get("security_level"),
				"risk_band": res.get("risk_band"),
				"requires_verification": res.get("requires_verification"),
				"medical_disclaimer": res.get("medical_disclaimer"),
				"input_security": json.dumps(res.get("input_security"), ensure_ascii=False) if isinstance(res.get("input_security"), dict) else res.get("input_security"),
				"output_security": json.dumps(res.get("output_security"), ensure_ascii=False) if isinstance(res.get("output_security"), dict) else res.get("output_security"),
				"status": res.get("status"),
				"error_detail": res.get("error_detail"),
			}
			results.append(row_out)

	# Write output Excel
	out_df = pd.DataFrame(results, columns=[
		"prompt",
		"response",
		"session_id",
		"timestamp",
		"confidence_score",
		"security_level",
		"risk_band",
		"requires_verification",
		"medical_disclaimer",
		"input_security",
		"output_security",
		"status",
		"error_detail",
	])
	out_df.to_excel(args.output_path, index=False)


if __name__ == "__main__":
	main()


