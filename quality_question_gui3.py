# quality_app_gui.py
import base64
import json
import os
import random
import threading
import time
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from datetime import datetime
from typing import Dict, Any, List, Optional, Iterable, Tuple

import requests
import pandas as pd
from cryptography.fernet import Fernet
from tkcalendar import DateEntry


import sys

def get_app_data_dir(app_name="QualityExports"):
    # Windows: C:\Users\<user>\AppData\Roaming\QualityExports
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    path = os.path.join(base, app_name)
    os.makedirs(path, exist_ok=True)
    return path


# ----------------------------
# Region mapping (edit if needed)
# ----------------------------
REGION_HOSTS = {
    "de":    {"api": "api.mypurecloud.de",    "login": "login.mypurecloud.de"},
    "ie":    {"api": "api.mypurecloud.ie",    "login": "login.mypurecloud.ie"},
    "au":    {"api": "api.mypurecloud.com.au","login": "login.mypurecloud.com.au"},
    "com":   {"api": "api.mypurecloud.com",   "login": "login.mypurecloud.com"},
    "usw2":  {"api": "api.usw2.pure.cloud",   "login": "login.usw2.pure.cloud"},
    "euw2":  {"api": "api.euw2.pure.cloud",   "login": "login.euw2.pure.cloud"},
    "euc2":  {"api": "api.euc2.pure.cloud",   "login": "login.euc2.pure.cloud"},
    "mec1":  {"api": "api.mec1.pure.cloud",   "login": "login.mec1.pure.cloud"},
    "sae1":  {"api": "api.sae1.pure.cloud",   "login": "login.sae1.pure.cloud"},
    "cac1":  {"api": "api.cac1.pure.cloud",   "login": "login.cac1.pure.cloud"}
}


# ----------------------------
# Local encrypted credential storage
# ----------------------------
APP_DIR = get_app_data_dir("QualityExports")

CRED_FILE = os.path.join(APP_DIR, "secure_credentials.json")
KEY_FILE = os.path.join(APP_DIR, "secret.key")
USERS_CACHE_FILE = os.path.join(APP_DIR, "users_cache.json")



def _get_or_create_key() -> bytes:
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def save_credentials_encrypted(client_id: str, client_secret: str, region: str) -> None:
    key = _get_or_create_key()
    f = Fernet(key)
    payload = {
        "client_id": f.encrypt(client_id.encode()).decode(),
        "client_secret": f.encrypt(client_secret.encode()).decode(),
        "region": region,
    }
    with open(CRED_FILE, "w", encoding="utf-8") as fp:
        json.dump(payload, fp, indent=2)


def load_credentials_encrypted():
    if not (os.path.exists(CRED_FILE) and os.path.exists(KEY_FILE)):
        return None
    key = open(KEY_FILE, "rb").read()
    f = Fernet(key)
    data = json.load(open(CRED_FILE, "r", encoding="utf-8"))
    return {
        "client_id": f.decrypt(data["client_id"].encode()).decode(),
        "client_secret": f.decrypt(data["client_secret"].encode()).decode(),
        "region": data["region"],
    }


# ----------------------------
# HTTP helpers (with backoff)
# ----------------------------
def _request_with_backoff(method: str, url: str, headers: Dict[str, str], *, params=None, payload=None, timeout: int = 90, max_retries: int = 6) -> Dict[str, Any]:
    """Call Genesys Cloud with retry handling for rate limits and transient failures."""
    if params is None:
        params = {}

    last_error = None
    for attempt in range(max_retries + 1):
        try:
            r = requests.request(method, url, headers=headers, params=params, json=payload, timeout=timeout)
        except requests.exceptions.RequestException as exc:
            last_error = exc
            if attempt >= max_retries:
                raise RuntimeError(f"Request failed calling {url}: {exc}") from exc
            sleep_s = min(30.0, (2 ** attempt)) + random.uniform(0.0, 0.5)
            time.sleep(sleep_s)
            continue

        if r.status_code == 429:
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_s = float(retry_after)
                except ValueError:
                    sleep_s = min(60.0, (2 ** attempt)) + random.uniform(0.0, 0.5)
            else:
                sleep_s = min(60.0, (2 ** attempt)) + random.uniform(0.0, 0.5)
            time.sleep(sleep_s)
            continue

        if r.status_code in (408, 409) or 500 <= r.status_code <= 599:
            if attempt >= max_retries:
                break
            sleep_s = min(30.0, (2 ** attempt)) + random.uniform(0.0, 0.5)
            time.sleep(sleep_s)
            continue

        if not r.ok:
            raise RuntimeError(f"HTTP {r.status_code} calling {url}: {r.text[:2000]}")

        if not r.text.strip():
            return {}
        return r.json()

    if last_error:
        raise RuntimeError(f"Failed after retries calling {url}: {last_error}")
    raise RuntimeError(f"Failed after retries calling {url}")


def _csv_sibling_path(path: str, suffix: str) -> str:
    root, ext = os.path.splitext(path)
    if not ext:
        ext = ".csv"
    return f"{root}{suffix}{ext}"


def detect_published_form_type(eval_form: Dict[str, Any], evaluation: Optional[Dict[str, Any]] = None) -> str:
    """Return a conservative, user-facing form type label.

    If Genesys explicitly returns a form type value, use it. Otherwise, only
    infer Agent Auto-Evaluation when the completed evaluation was system
    submitted. Do not infer or label automation-capable forms just because the
    form contains AI/assistance settings.
    """
    if not isinstance(eval_form, dict):
        eval_form = {}
    for key in (
        "formType",
        "evaluationFormType",
        "type",
        "category",
        "evaluationType",
        "agentEvaluationFormType",
    ):
        val = eval_form.get(key)
        if val not in (None, ""):
            return str(val)

    if isinstance(evaluation, dict) and evaluation.get("systemSubmitted") is True:
        return "Agent Auto-Evaluation"
    return "Evaluation"

def authenticate_client_credentials(client_id: str, client_secret: str, login_host: str) -> str:
    token_url = f"https://{login_host}/oauth/token"
    basic = base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
    headers = {
        "Authorization": f"Basic {basic}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    data = "grant_type=client_credentials"

    r = requests.post(token_url, headers=headers, data=data, timeout=60)
    if not r.ok:
        raise RuntimeError(f"Auth failed ({r.status_code}): {r.text[:2000]}")
    return r.json()["access_token"]

def load_users_cache(cache_path: str = USERS_CACHE_FILE) -> Dict[str, Any]:
    if not os.path.exists(cache_path):
        return {}
    with open(cache_path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_users_cache(users: Dict[str, Any], cache_path: str = USERS_CACHE_FILE) -> None:
    with open(cache_path, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2)


def fetch_all_users(api_host: str, token: str) -> Dict[str, Any]:
    """
    GET /api/v2/users with paging
    """
    users: Dict[str, Any] = {}
    headers = {"Authorization": f"Bearer {token}"}
    page = 1
    while True:
        url = f"https://{api_host}/api/v2/users"
        params = {"pageSize": 100, "pageNumber": page}
        data = _request_with_backoff("GET", url, headers, params=params, timeout=120)
        entities = data.get("entities", []) or []
        if not entities:
            break

        for u in entities:
            uid = str(u.get("id", ""))
            if not uid:
                continue
            users[uid] = {
                "name": u.get("name", "") or "",
                "email": (
                        u.get("email")
                        or u.get("username")
                        or ""
                ),
                "managerId": (u.get("manager") or {}).get("id", "") if u.get("manager") else "",
            }

        if len(entities) < 100:
            break
        page += 1

    return users


def build_user_maps(users_cache: Dict[str, Any]) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    id_to_name: Dict[str, str] = {}
    display_items: List[Tuple[str, str]] = []
    for uid, info in users_cache.items():
        name = (info or {}).get("name", "") or ""
        uid_str = str(uid)
        id_to_name[uid_str] = name
        display_items.append((name, uid_str))
    display_items.sort(key=lambda x: (x[0] or "").lower())
    return id_to_name, display_items


def resolve_manager_names(users: Dict[str, Any]) -> Dict[str, str]:
    manager_map: Dict[str, str] = {}
    for user in users.values():
        mgr_id = user.get("managerId")
        if mgr_id and mgr_id not in manager_map and mgr_id in users:
            manager_map[mgr_id] = users[mgr_id]["name"]
    return manager_map


# ----------------------------
# Tab 1: Finished evals exporter (analytics + evaluation details) -> question-level rows
# ----------------------------
def safe_get(obj: Any, path: List[str], default=None):
    for key in path:
        obj = obj.get(key) if isinstance(obj, dict) else None
        if obj is None:
            return default
    return obj


def process_evaluation_form(eval_form: Dict[str, Any]) -> Tuple[Dict[str, str], Dict[str, str], Dict[str, str], Dict[str, Dict[str, str]]]:
    """
    Builds lookup maps from the expanded evaluationForm.

    Important: Genesys multipleSelectQuestion answers are not stored on the
    parent question as a normal answerId. The parent questionScore has
    answerId == "" and the selected/unselected checkbox answers are in
    multipleSelectQuestionOptionScores. Those option scores use the child
    multipleSelectOptionQuestions IDs, so we must index those child questions
    and their Selected/Unselected answer IDs too.
    """
    group_lookup: Dict[str, str] = {}
    question_lookup: Dict[str, str] = {}
    answer_lookup: Dict[str, str] = {}
    multiselect_parent_lookup: Dict[str, Dict[str, str]] = {}

    for group in eval_form.get("questionGroups", []) or []:
        group_id = group.get("id")
        group_name = group.get("name", "")
        if group_id:
            group_lookup[group_id] = group_name

        for question in group.get("questions", []) or []:
            question_id = question.get("id")
            question_text = question.get("text", "")
            question_type = question.get("type", "")

            if question_id:
                question_lookup[question_id] = question_text

            # Normal single-answer questions.
            for answer in question.get("answerOptions", []) or []:
                answer_id = answer.get("id")
                answer_text = answer.get("text") or answer.get("builtInType") or ""
                if answer_id:
                    answer_lookup[answer_id] = answer_text

            # Checkbox / multiple-select questions.
            if question_type == "multipleSelectQuestion":
                option_id_to_text: Dict[str, str] = {}

                for option_question in question.get("multipleSelectOptionQuestions", []) or []:
                    option_qid = option_question.get("id")
                    option_text = option_question.get("text", "")
                    if not option_qid:
                        continue

                    option_id_to_text[option_qid] = option_text
                    # Make child option question IDs resolvable too.
                    question_lookup[option_qid] = f"{question_text} - {option_text}" if question_text else option_text

                    for answer in option_question.get("answerOptions", []) or []:
                        answer_id = answer.get("id")
                        # Genesys Selected/Unselected options usually have no text.
                        answer_text = answer.get("text") or answer.get("builtInType") or ""
                        if answer_id:
                            answer_lookup[answer_id] = answer_text

                if question_id:
                    multiselect_parent_lookup[question_id] = option_id_to_text

    return group_lookup, question_lookup, answer_lookup, multiselect_parent_lookup

def extract_evaluation_data(evaluation: Dict[str, Any], users: Dict[str, Any], manager_map: Dict[str, str]) -> Dict[str, Any]:
    agent_id = safe_get(evaluation, ["agent", "id"])
    evaluator_id = safe_get(evaluation, ["evaluator", "id"])

    agent_name = users.get(str(agent_id), {}).get("name", "Unknown") if agent_id else "Unknown"
    if evaluator_id:
        evaluator_name = users.get(str(evaluator_id), {}).get("name", "Unknown")
    elif evaluation.get("systemSubmitted") is True:
        evaluator_name = "Virtual Supervisor"
    else:
        evaluator_name = "Unknown"

    evaluator_email = ""
    if evaluator_id:
        evaluator_info = users.get(str(evaluator_id), {}) or {}
        evaluator_email = evaluator_info.get("email") or evaluator_info.get("username") or ""

    manager_id = users.get(str(agent_id), {}).get("managerId", "") if agent_id else ""
    manager_name = manager_map.get(manager_id, "Unknown") if manager_id else "No Manager"

    return {
        "evaluation_id": evaluation.get("id"),
        "conversation_id": safe_get(evaluation, ["conversation", "id"]),
        "evaluation_form_id": safe_get(evaluation, ["evaluationForm", "id"]),
        "evaluation_form_name": safe_get(evaluation, ["evaluationForm", "name"]),
        "evaluator_id": evaluator_id,
        "evaluator_name": evaluator_name,
        "evaluator_email": evaluator_email,
        "agent_id": agent_id,
        "agent_name": agent_name,
        "manager_id": manager_id,
        "manager_name": manager_name,
        "status": evaluation.get("status"),
        "agent_has_read": evaluation.get("agentHasRead"),
        "release_date": evaluation.get("releaseDate"),
        "assigned_date": evaluation.get("assignedDate"),
        "changed_date": evaluation.get("changedDate"),
        "media_type": ",".join(evaluation.get("mediaType", []) or []),
        "conversation_date": evaluation.get("conversationDate"),
        "conversation_end_date": evaluation.get("conversationEndDate"),
        "never_release": evaluation.get("neverRelease"),
        "has_assistance_failed": evaluation.get("hasAssistanceFailed"),
        "total_score": safe_get(evaluation, ["answers", "totalScore"]),
        "total_critical_score": safe_get(evaluation, ["answers", "totalCriticalScore"]),
        "total_non_critical_score": safe_get(evaluation, ["answers", "totalNonCriticalScore"]),
        "any_failed_kill_questions": safe_get(evaluation, ["answers", "anyFailedKillQuestions"]),
        "overall_comments": safe_get(evaluation, ["answers", "comments"]),
        "overall_private_comments": safe_get(evaluation, ["answers", "privateComments"]),
        "agent_comments": safe_get(evaluation, ["answers", "agentComments"]),
        "queue_id": safe_get(evaluation, ["queue", "id"]),
        "evaluation_source_id": safe_get(evaluation, ["evaluationSource", "id"]),
        "evaluation_source_name": safe_get(evaluation, ["evaluationSource", "name"]),
        "evaluation_source_type": safe_get(evaluation, ["evaluationSource", "type"]),
        "dispute_count": evaluation.get("disputeCount"),
        "version": evaluation.get("version"),
        "declined_review": evaluation.get("declinedReview"),
        "evaluation_context_id": evaluation.get("evaluationContextId"),
        "calibration_id": safe_get(evaluation, ["calibration", "id"]),
        "calibration_self_uri": safe_get(evaluation, ["calibration", "selfUri"]),
        "system_submitted": evaluation.get("systemSubmitted"),
        "ai_scoring_pending": safe_get(evaluation, ["aiScoring", "pending"]),
        "ai_scoring_date_last_changed": safe_get(evaluation, ["aiScoring", "dateLastChanged"]),
        "evaluation_form_type": safe_get(evaluation, ["_published_form_metadata", "form_type"]),
        "export_record_type": evaluation.get("_export_record_type", "evaluation"),
    }



def _bool_to_text(value: Optional[bool]) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    return ""


def _calculate_ai_agreement(final_answer_id: Any, ai_answer_id: Any) -> Tuple[str, str]:
    """Return (ai_answer_matches_final, ai_answer_overridden).

    Blank AI answers mean the question was not AI-scored, so both fields stay
    blank rather than false. This avoids confusing non-AI questions with AI
    disagreements.
    """
    ai_id = str(ai_answer_id or "").strip()
    if not ai_id:
        return "", ""
    final_id = str(final_answer_id or "").strip()
    matches = bool(final_id and final_id == ai_id)
    return _bool_to_text(matches), _bool_to_text(not matches)

def process_evaluation_question_rows(
    evaluation: Dict[str, Any],
    group_lookup: Dict[str, str],
    question_lookup: Dict[str, str],
    answer_lookup: Dict[str, str],
    multiselect_parent_lookup: Dict[str, Dict[str, str]],
    users: Dict[str, Any],
    manager_map: Dict[str, str],
) -> List[Dict[str, Any]]:
    base = extract_evaluation_data(evaluation, users, manager_map)
    out: List[Dict[str, Any]] = []

    group_scores = safe_get(evaluation, ["answers", "questionGroupScores"], []) or []
    for question_group in group_scores:
        group_id = question_group.get("questionGroupId")

        group_data = base.copy()
        group_data.update(
            {
                "question_group_id": group_id,
                "question_group_name": group_lookup.get(group_id, ""),
                "question_group_total_score": question_group.get("totalScore"),
                "question_group_max_total_score": question_group.get("maxTotalScore"),
                "question_group_marked_na": question_group.get("markedNA"),
                "question_group_total_critical_score": question_group.get("totalCriticalScore"),
                "question_group_max_total_critical_score": question_group.get("maxTotalCriticalScore"),
                "question_group_total_non_critical_score": question_group.get("totalNonCriticalScore"),
                "question_group_max_total_non_critical_score": question_group.get("maxTotalNonCriticalScore"),
            }
        )

        for q in question_group.get("questionScores", []) or []:
            qid = q.get("questionId")
            answer_id = q.get("answerId")

            # Multiple-select parent questions have answerId == "" and the
            # real checkbox answers are nested in multipleSelectQuestionOptionScores.
            ms_option_scores = q.get("multipleSelectQuestionOptionScores", []) or []
            if ms_option_scores:
                selected_option_texts: List[str] = []
                selected_option_ids: List[str] = []
                parent_option_lookup = multiselect_parent_lookup.get(qid, {})

                for opt in ms_option_scores:
                    opt_qid = opt.get("questionId")
                    opt_answer_id = opt.get("answerId")
                    opt_answer_text = answer_lookup.get(opt_answer_id, "")
                    if opt_answer_text == "Selected":
                        selected_option_ids.append(opt_qid or "")
                        selected_option_texts.append(parent_option_lookup.get(opt_qid, question_lookup.get(opt_qid, "")))

                # Keep one parent row, with the selected checkbox labels joined.
                row = group_data.copy()
                answer_id_joined = "; ".join([x for x in selected_option_ids if x])
                answer_text_joined = "; ".join([x for x in selected_option_texts if x])
                ai_answer_id = safe_get(q, ["aiAnswer", "answerId"])
                ai_answer_matches_final, ai_answer_overridden = _calculate_ai_agreement(answer_id_joined, ai_answer_id)
                row.update(
                    {
                        "question_id": qid,
                        "question_text": question_lookup.get(qid, ""),
                        "answer_id": answer_id_joined,
                        "answer_text": answer_text_joined,
                        "question_score": q.get("score"),
                        "question_marked_na": q.get("markedNA"),
                        "question_system_marked_na": q.get("systemMarkedNA"),
                        "failed_kill_question": q.get("failedKillQuestion"),
                        "question_comments": q.get("comments"),
                        "automated_answer_type": safe_get(q, ["automatedAnswer", "type"]),
                        "automated_answer_id": safe_get(q, ["automatedAnswer", "answerId"]),
                        "ai_answer_id": ai_answer_id,
                        "ai_answer_text": answer_lookup.get(ai_answer_id, "") if ai_answer_id else "",
                        "ai_explanation": safe_get(q, ["aiAnswer", "explanation"]),
                        "ai_marked_not_applicable": safe_get(q, ["aiAnswer", "markedNotApplicable"]),
                        "ai_answer_matches_final": ai_answer_matches_final,
                        "ai_answer_overridden": ai_answer_overridden,
                    }
                )
                out.append(row)
                continue

            answer_text = answer_lookup.get(answer_id, "")
            if answer_text == "" and q.get("systemMarkedNA"):
                answer_text = "Not Asked - hidden by logic"
                answer_id = "system_not_asked"
            elif answer_text == "" and q.get("markedNA"):
                answer_text = "N/A"
                answer_id = "manual_na"
            elif answer_text == "" and not answer_id:
                answer_text = ""
                answer_id = ""

            ai_answer_id = safe_get(q, ["aiAnswer", "answerId"])
            ai_answer_matches_final, ai_answer_overridden = _calculate_ai_agreement(answer_id, ai_answer_id)
            row = group_data.copy()
            row.update(
                {
                    "question_id": qid,
                    "question_text": question_lookup.get(qid, ""),
                    "answer_id": answer_id,
                    "answer_text": answer_text,
                    "question_score": q.get("score"),
                    "question_marked_na": q.get("markedNA"),
                    "question_system_marked_na": q.get("systemMarkedNA"),
                    "failed_kill_question": q.get("failedKillQuestion"),
                    "question_comments": q.get("comments"),
                    "automated_answer_type": safe_get(q, ["automatedAnswer", "type"]),
                    "automated_answer_id": safe_get(q, ["automatedAnswer", "answerId"]),
                    "ai_answer_id": ai_answer_id,
                    "ai_answer_text": answer_lookup.get(ai_answer_id, "") if ai_answer_id else "",
                    "ai_explanation": safe_get(q, ["aiAnswer", "explanation"]),
                    "ai_marked_not_applicable": safe_get(q, ["aiAnswer", "markedNotApplicable"]),
                    "ai_answer_matches_final": ai_answer_matches_final,
                    "ai_answer_overridden": ai_answer_overridden,
                }
            )
            out.append(row)

    return out


def _build_evaluations_aggregate_query(interval: str, calibration_filter: str, system_submitted_filter: str) -> Dict[str, Any]:
    """
    calibration_filter: "notExists" for normal evaluations, "exists" for calibrations.
    system_submitted_filter: "both", "human", or "auto".
    """
    clauses = [
        {
            "type": "or",
            "predicates": [{"dimension": "calibrationId", "operator": calibration_filter}],
        }
    ]

    if system_submitted_filter == "human":
        clauses.append({"type": "or", "predicates": [{"dimension": "systemSubmitted", "value": "false"}]})
    elif system_submitted_filter == "auto":
        clauses.append({"type": "or", "predicates": [{"dimension": "systemSubmitted", "value": "true"}]})

    return {
        "interval": interval,
        "granularity": "P1DT1H",
        "groupBy": ["conversationId", "evaluationId"],
        "filter": {"type": "and", "clauses": clauses},
        "metrics": ["nEvaluations"],
    }


def _write_export_outputs(
    all_rows: List[Dict[str, Any]],
    output_csv_path: str,
) -> Dict[str, Any]:
    """Write the question-level CSV output."""
    os.makedirs(os.path.dirname(output_csv_path) or ".", exist_ok=True)
    saved_files: Dict[str, str] = {}

    df = pd.DataFrame(all_rows)
    if not df.empty:
        for col in [c for c in df.columns if "date" in c.lower()]:
            df[col] = pd.to_datetime(df[col], errors="coerce")

    df.to_csv(output_csv_path, index=False, encoding="utf-8-sig")
    saved_files["question_level"] = output_csv_path

    return {"saved_files": saved_files, "rows": int(len(df))}

def run_finished_evals_export(
    token: str,
    api_host: str,
    start_date_yyyy_mm_dd: str,
    end_date_yyyy_mm_dd: str,
    output_csv_path: str,
    users_cache: Dict[str, Any],
    system_submitted_filter: str = "both",
    record_type: str = "evaluation",
) -> Dict[str, Any]:
    """
    Analytics aggregates -> fetch evaluation details -> question-level rows.

    record_type = "evaluation" excludes calibrations via calibrationId notExists.
    record_type = "calibration" includes only calibration evaluations via calibrationId exists.
    """
    headers = {"Authorization": f"Bearer {token}"}
    interval = f"{start_date_yyyy_mm_dd}T00:00:00.000Z/{end_date_yyyy_mm_dd}T23:59:59.999Z"

    users = users_cache or {}
    manager_map = resolve_manager_names(users)

    analytics_url = f"https://{api_host}/api/v2/analytics/evaluations/aggregates/query"
    calibration_filter = "exists" if record_type == "calibration" else "notExists"
    query = _build_evaluations_aggregate_query(interval, calibration_filter, system_submitted_filter)

    agg = _request_with_backoff("POST", analytics_url, headers, payload=query, timeout=180)
    results = agg.get("results", []) or []

    all_rows: List[Dict[str, Any]] = []
    fetched_evals = 0
    published_form_cache: Dict[str, Dict[str, Any]] = {}
    evaluation_detail_cache: Dict[str, Dict[str, Any]] = {}
    seen_eval_ids = set()

    for r in results:
        grp = r.get("group", {}) or {}
        convo_id = grp.get("conversationId")
        eval_id = grp.get("evaluationId")
        if not convo_id or not eval_id or eval_id in seen_eval_ids:
            continue
        seen_eval_ids.add(eval_id)

        if eval_id in evaluation_detail_cache:
            eval_json = evaluation_detail_cache[eval_id]
        else:
            eval_url = f"https://{api_host}/api/v2/quality/conversations/{convo_id}/evaluations/{eval_id}"
            eval_json = _request_with_backoff("GET", eval_url, headers, timeout=180)
            evaluation_detail_cache[eval_id] = eval_json

        # Extra safety if the analytics filter is unsupported/loose in any org/API version.
        has_calibration = bool(safe_get(eval_json, ["calibration", "id"]))
        if record_type == "calibration" and not has_calibration:
            continue
        if record_type != "calibration" and has_calibration:
            continue
        if system_submitted_filter == "human" and eval_json.get("systemSubmitted") is True:
            continue
        if system_submitted_filter == "auto" and eval_json.get("systemSubmitted") is not True:
            continue

        eval_json["_export_record_type"] = record_type

        form_ref = eval_json.get("evaluationForm", {}) or {}
        form_id = form_ref.get("id")
        if form_id:
            if form_id not in published_form_cache:
                published_form_url = f"https://{api_host}/api/v2/quality/publishedforms/evaluations/{form_id}"
                published_form_cache[form_id] = _request_with_backoff("GET", published_form_url, headers, timeout=180)
            eval_form = published_form_cache[form_id]
        else:
            eval_form = form_ref

        eval_json["_published_form_metadata"] = {
            "form_type": detect_published_form_type(eval_form, eval_json),
        }

        group_lookup, question_lookup, answer_lookup, multiselect_parent_lookup = process_evaluation_form(eval_form)
        rows = process_evaluation_question_rows(
            eval_json, group_lookup, question_lookup, answer_lookup, multiselect_parent_lookup, users, manager_map
        )
        all_rows.extend(rows)
        fetched_evals += 1

    write_summary = _write_export_outputs(all_rows, output_csv_path)

    return {
        "saved_to": output_csv_path,
        "saved_files": write_summary["saved_files"],
        "rows": write_summary["rows"],
        "evaluations_fetched": int(fetched_evals),
        "groups_returned": int(len(results)),
        "published_forms_fetched": int(len(published_form_cache)),
        "interval_used": interval,
        "record_type": record_type,
        "system_submitted_filter": system_submitted_filter,
    }


# ----------------------------
# Tab 2: Evaluations by Evaluator (query API ONLY) -> friendly evaluator_name column
# ----------------------------
def fetch_evaluations_for_evaluators_query_only(
    token: str,
    api_host: str,
    evaluator_user_ids: Iterable[str],
    start_time_iso: str,
    end_time_iso: str,
    statuses: Optional[List[str]],
    page_size: int,
    sleep_between_calls_s: float,
    expand_answer_total_scores: bool,
) -> List[Dict[str, Any]]:
    url = f"https://{api_host}/api/v2/quality/evaluations/query"
    headers = {"Authorization": f"Bearer {token}"}

    all_entities: List[Dict[str, Any]] = []
    seen_ids = set()

    for evaluator_id in evaluator_user_ids:
        page_number = 1
        while True:
            params = {
                "evaluatorUserId": evaluator_id,
                "startTime": start_time_iso,
                "endTime": end_time_iso,
                "pageSize": page_size,
                "pageNumber": page_number,
            }
            if expand_answer_total_scores:
                params["expandAnswerTotalScores"] = "true"

            data = _request_with_backoff("GET", url, headers, params=params, timeout=120)
            entities = data.get("entities", []) or []
            if not entities:
                break

            for e in entities:
                ev_id = e.get("id")
                if not ev_id or ev_id in seen_ids:
                    continue
                # no status filtering – keep ALL statuses
                seen_ids.add(ev_id)
                all_entities.append(e)

            if len(entities) < page_size:
                break
            page_number += 1
            time.sleep(sleep_between_calls_s)

        time.sleep(sleep_between_calls_s)

    return all_entities


def export_query_only_to_csv(
    token: str,
    api_host: str,
    evaluator_user_ids: List[str],
    start_time_iso: str,
    end_time_iso: str,
    output_csv_path: str,
    user_id_to_name: Dict[str, str],
    statuses: Optional[List[str]],
    sleep_between_calls_s: float,
    page_size: int = 100,
    expand_answer_total_scores: bool = True,
) -> Dict[str, Any]:
    entities = fetch_evaluations_for_evaluators_query_only(
        token=token,
        api_host=api_host,
        evaluator_user_ids=evaluator_user_ids,
        start_time_iso=start_time_iso,
        end_time_iso=end_time_iso,
        statuses=statuses,
        page_size=page_size,
        sleep_between_calls_s=sleep_between_calls_s,
        expand_answer_total_scores=expand_answer_total_scores,
    )

    df = pd.json_normalize(entities)

    # Normalize evaluator_id from whichever field is present
    evaluator_id_col = None
    for c in ["evaluator.id", "evaluatorUserId", "evaluator.userId"]:
        if c in df.columns:
            evaluator_id_col = c
            break

    if evaluator_id_col is None:
        df["evaluator_id"] = ""
    else:
        df["evaluator_id"] = df[evaluator_id_col].astype(str)

    df["evaluator_name"] = df["evaluator_id"].map(user_id_to_name).fillna("")

    # Optional agent mapping if present
    if "agent.id" in df.columns:
        df["agent_id"] = df["agent.id"].astype(str)
        df["agent_name"] = df["agent_id"].map(user_id_to_name).fillna("")

    # Front-load friendly columns based on the query payload structure
    preferred_front = [
        "id",                    # evaluation id
        "status",                # FINISHED / PENDING / etc.
        "evaluator_name",
        "evaluator_id",
        "agent_name",
        "agent_id",
        "evaluationForm.name",
        "evaluationForm.id",
        "conversation.id",
        "conversationDate",
        "conversationEndDate",
        "assignedDate",
        "releaseDate",
        "createdDate",
        "changedDate",
        "submittedDate",
        "queue.id",
    ]
    front_cols = [c for c in preferred_front if c in df.columns]
    remaining = [c for c in df.columns if c not in front_cols]
    df = df[front_cols + remaining]


    df.to_csv(output_csv_path, index=False)
    return {
        "saved_to": output_csv_path,
        "rows": int(len(df)),
        "evaluators_selected": int(len(evaluator_user_ids)),
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "statuses_filter": statuses or "ALL",
    }


# ----------------------------
# GUI
# ----------------------------
def to_iso_bounds(start_date, end_date) -> Tuple[str, str]:
    start_iso = start_date.strftime("%Y-%m-%dT00:00:00.000Z")
    end_iso = end_date.strftime("%Y-%m-%dT23:59:59.999Z")
    return start_iso, end_iso


def run_gui():
    root = tk.Tk()
    root.title("Quality Exports")
    root.geometry("860x680")

    # ---- Credentials panel ----
    cred_frame = tk.LabelFrame(root, text="Authentication")
    cred_frame.pack(fill="x", padx=10, pady=10)

    tk.Label(cred_frame, text="Client ID").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    client_id_entry = tk.Entry(cred_frame, width=55)
    client_id_entry.grid(row=0, column=1, sticky="w", padx=8, pady=6)

    tk.Label(cred_frame, text="Client Secret").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    client_secret_entry = tk.Entry(cred_frame, width=55, show="*")
    client_secret_entry.grid(row=1, column=1, sticky="w", padx=8, pady=6)

    tk.Label(cred_frame, text="Region").grid(row=2, column=0, sticky="w", padx=8, pady=6)
    region_var = tk.StringVar(value="eu-west-2")
    region_menu = tk.OptionMenu(cred_frame, region_var, *REGION_HOSTS.keys())
    region_menu.grid(row=2, column=1, sticky="w", padx=8, pady=6)

    remember_var = tk.IntVar(value=1)
    tk.Checkbutton(cred_frame, text="Remember credentials on this machine", variable=remember_var).grid(
        row=3, column=1, sticky="w", padx=8, pady=6
    )

    saved = load_credentials_encrypted()
    if saved:
        client_id_entry.insert(0, saved["client_id"])
        client_secret_entry.insert(0, saved["client_secret"])
        region_var.set(saved["region"])

    # ---- Tabs ----
    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=10, pady=10)

    tab_finished = ttk.Frame(notebook)
    tab_eval_query = ttk.Frame(notebook)

    notebook.add(tab_finished, text="Finished evals (question-level)")
    notebook.add(tab_eval_query, text="Evaluations by evaluator (query-only)")

    # ---- Shared: users cache control ----
    shared_users_frame = tk.LabelFrame(root, text="Users cache (for name mapping + evaluator list)")
    shared_users_frame.pack(fill="x", padx=10, pady=(0, 10))

    users_status = tk.Label(shared_users_frame, text="", fg="blue", wraplength=820, justify="left")
    users_status.grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=6)

    def ensure_users_cache(force_refresh: bool = False) -> Dict[str, Any]:
        cache = load_users_cache(USERS_CACHE_FILE)
        if cache and not force_refresh:
            return cache

        # Auth required to refresh users
        client_id = client_id_entry.get().strip()
        client_secret = client_secret_entry.get().strip()
        region = region_var.get().strip()
        if region not in REGION_HOSTS:
            raise ValueError(f"Unknown region: {region}")
        login_host = REGION_HOSTS[region]["login"]
        api_host = REGION_HOSTS[region]["api"]

        token = authenticate_client_credentials(client_id, client_secret, login_host)
        users = fetch_all_users(api_host, token)
        save_users_cache(users, USERS_CACHE_FILE)
        return users

    def on_refresh_users():
        def job():
            try:
                users_status.config(text="Refreshing users cache...")
                users = ensure_users_cache(force_refresh=True)
                users_status.config(text=f"✅ Users cache refreshed ({len(users)} users).")
                # refresh list in evaluator tab
                refresh_evaluator_lists()
            except Exception as e:
                messagebox.showerror("Error", str(e))
                users_status.config(text=f"❌ Error refreshing users: {e}")

        threading.Thread(target=job, daemon=True).start()

    tk.Button(shared_users_frame, text="Refresh users cache now", command=on_refresh_users).grid(row=1, column=0, sticky="w", padx=8, pady=6)

    # =========================
    # Tab 1: Finished evals UI
    # =========================
    finished_frame = tk.LabelFrame(tab_finished, text="Export finished evals (question-level)")
    finished_frame.pack(fill="x", padx=10, pady=10)

    tk.Label(finished_frame, text="Start Date").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    finished_start = DateEntry(finished_frame, width=18)
    finished_start.grid(row=0, column=1, sticky="w", padx=8, pady=6)

    tk.Label(finished_frame, text="End Date").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    finished_end = DateEntry(finished_frame, width=18)
    finished_end.grid(row=1, column=1, sticky="w", padx=8, pady=6)

    tk.Label(finished_frame, text="Evaluation source").grid(row=3, column=0, sticky="w", padx=8, pady=6)
    system_submitted_var = tk.StringVar(value="both")
    system_submitted_menu = ttk.Combobox(
        finished_frame,
        textvariable=system_submitted_var,
        values=["both", "human", "auto"],
        width=18,
        state="readonly",
    )
    system_submitted_menu.grid(row=3, column=1, sticky="w", padx=8, pady=6)
    tk.Label(finished_frame, text="human = systemSubmitted false; auto = systemSubmitted true").grid(
        row=3, column=2, sticky="w", padx=8, pady=6
    )

    include_calibrations_var = tk.IntVar(value=0)
    tk.Checkbutton(
        finished_frame,
        text="Include calibrations as separate CSV output",
        variable=include_calibrations_var,
    ).grid(row=4, column=0, columnspan=3, sticky="w", padx=8, pady=6)

    refresh_users_before_export_var = tk.IntVar(value=0)
    tk.Checkbutton(
        finished_frame,
        text="Refresh user cache before export",
        variable=refresh_users_before_export_var,
    ).grid(row=5, column=0, columnspan=3, sticky="w", padx=8, pady=6)

    finished_status = tk.Label(tab_finished, text="", fg="blue", wraplength=820, justify="left")
    finished_status.pack(padx=10, pady=10, anchor="w")

    def run_finished_export():
        def job():
            try:
                client_id = client_id_entry.get().strip()
                client_secret = client_secret_entry.get().strip()
                region = region_var.get().strip()
                if not client_id or not client_secret:
                    raise ValueError("Client ID and Client Secret are required.")
                if region not in REGION_HOSTS:
                    raise ValueError(f"Unknown region: {region}")

                if remember_var.get() == 1:
                    save_credentials_encrypted(client_id, client_secret, region)

                login_host = REGION_HOSTS[region]["login"]
                api_host = REGION_HOSTS[region]["api"]

                # output path
                start_yyyy_mm_dd = finished_start.get_date().strftime("%Y-%m-%d")
                end_yyyy_mm_dd = finished_end.get_date().strftime("%Y-%m-%d")
                out_default = f"finished_evals_question_level_{start_yyyy_mm_dd}_to_{end_yyyy_mm_dd}.csv"
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    initialfile=out_default,
                    filetypes=[("CSV Files", "*.csv")],
                )
                if not out_path:
                    finished_status.config(text="Save cancelled.")
                    return

                finished_status.config(text="Authenticating...")
                token = authenticate_client_credentials(client_id, client_secret, login_host)

                # ensure users cache for name mapping
                users = load_users_cache(USERS_CACHE_FILE)
                if refresh_users_before_export_var.get() == 1 or not users:
                    finished_status.config(text="Refreshing users cache..." if users else "Users cache missing. Fetching users (one-time)...")
                    users = fetch_all_users(api_host, token)
                    save_users_cache(users, USERS_CACHE_FILE)
                    refresh_evaluator_lists()

                system_filter = system_submitted_var.get() or "both"

                finished_status.config(text="Running evaluations export (this can take a while)...")
                summary = run_finished_evals_export(
                    token=token,
                    api_host=api_host,
                    start_date_yyyy_mm_dd=start_yyyy_mm_dd,
                    end_date_yyyy_mm_dd=end_yyyy_mm_dd,
                    output_csv_path=out_path,
                    users_cache=users,
                    system_submitted_filter=system_filter,
                    record_type="evaluation",
                )

                summaries = [summary]
                if include_calibrations_var.get() == 1:
                    cal_out_path = _csv_sibling_path(out_path, "_calibrations")
                    finished_status.config(text="Running calibrations export as separate CSV (this can take a while)...")
                    cal_summary = run_finished_evals_export(
                        token=token,
                        api_host=api_host,
                        start_date_yyyy_mm_dd=start_yyyy_mm_dd,
                        end_date_yyyy_mm_dd=end_yyyy_mm_dd,
                        output_csv_path=cal_out_path,
                        users_cache=users,
                            system_submitted_filter=system_filter,
                        record_type="calibration",
                    )
                    summaries.append(cal_summary)

                def format_saved_files(item):
                    saved = item.get("saved_files", {}) or {}
                    if not saved:
                        return item.get("saved_to", "")
                    return "\n".join([f"  - {label}: {path}" for label, path in saved.items()])

                status_parts = ["✅ Done!"]
                for item in summaries:
                    label = "Calibrations" if item.get("record_type") == "calibration" else "Evaluations"
                    status_parts.append(
                        f"\n{label}:\n"
                        f"- Saved files:\n{format_saved_files(item)}\n"
                        f"- Rows: {item['rows']}\n"
                        f"- Records fetched: {item['evaluations_fetched']}\n"
                        f"- Published forms fetched: {item['published_forms_fetched']}"
                    )
                status_parts.append(f"\nInterval: {summary['interval_used']}")
                finished_status.config(text="".join(status_parts))
            except Exception as e:
                messagebox.showerror("Error", str(e))
                finished_status.config(text=f"❌ Error: {e}")

        threading.Thread(target=job, daemon=True).start()

    tk.Button(finished_frame, text="Export CSV", command=run_finished_export, height=2).grid(
        row=6, column=0, columnspan=2, sticky="w", padx=8, pady=10
    )

    # =========================
    # Tab 2: Evaluations query-only UI
    # =========================
    evalq_frame = tk.LabelFrame(tab_eval_query, text="Export evaluations by evaluator (query API only)")
    evalq_frame.pack(fill="both", expand=True, padx=10, pady=10)

    # Date range
    tk.Label(evalq_frame, text="Start Date").grid(row=0, column=0, sticky="w", padx=8, pady=6)
    evalq_start = DateEntry(evalq_frame, width=18)
    evalq_start.grid(row=0, column=1, sticky="w", padx=8, pady=6)

    tk.Label(evalq_frame, text="End Date").grid(row=1, column=0, sticky="w", padx=8, pady=6)
    evalq_end = DateEntry(evalq_frame, width=18)
    evalq_end.grid(row=1, column=1, sticky="w", padx=8, pady=6)

    # Throttle
    throttle_box = tk.LabelFrame(evalq_frame, text="Throttle between API calls (seconds)")
    throttle_box.grid(row=3, column=0, columnspan=4, sticky="we", padx=8, pady=6)
    throttle_var = tk.DoubleVar(value=0.25)
    tk.Scale(throttle_box, from_=0.0, to=2.0, resolution=0.05, orient="horizontal", variable=throttle_var).pack(fill="x", padx=10, pady=6)

    # Evaluator pickers
    tk.Label(evalq_frame, text="Search users").grid(row=4, column=0, sticky="w", padx=8, pady=(10, 0))
    search_var = tk.StringVar()
    search_entry = tk.Entry(evalq_frame, textvariable=search_var, width=45)
    search_entry.grid(row=4, column=1, sticky="w", padx=8, pady=(10, 0))

    list_frame = tk.Frame(evalq_frame)
    list_frame.grid(row=5, column=0, columnspan=4, sticky="nsew", padx=8, pady=8)

    evalq_frame.grid_rowconfigure(5, weight=1)
    evalq_frame.grid_columnconfigure(3, weight=1)

    available_lb = tk.Listbox(list_frame, width=48, height=14)
    available_lb.grid(row=0, column=0, padx=5, sticky="nsew")

    btn_frame = tk.Frame(list_frame)
    btn_frame.grid(row=0, column=1, padx=5, sticky="ns")

    selected_lb = tk.Listbox(list_frame, width=48, height=14)
    selected_lb.grid(row=0, column=2, padx=5, sticky="nsew")

    list_frame.grid_columnconfigure(0, weight=1)
    list_frame.grid_columnconfigure(2, weight=1)

    selected_ids: List[str] = []

    # These are refreshed when users cache changes
    id_to_name: Dict[str, str] = {}
    display_items: List[Tuple[str, str]] = []

    def refresh_available():
        q = search_var.get().strip().lower()
        available_lb.delete(0, tk.END)
        for name, uid in display_items:
            label = f"{name}  ({uid})"
            if q == "" or q in name.lower() or q in uid.lower():
                available_lb.insert(tk.END, label)

    def add_selected():
        sel = available_lb.curselection()
        for i in sel:
            label = available_lb.get(i)
            uid = label.split("(")[-1].strip(")")
            if uid not in selected_ids:
                selected_ids.append(uid)
                selected_lb.insert(tk.END, label)

    def remove_selected():
        sel = list(selected_lb.curselection())
        sel.reverse()
        for i in sel:
            label = selected_lb.get(i)
            uid = label.split("(")[-1].strip(")")
            if uid in selected_ids:
                selected_ids.remove(uid)
            selected_lb.delete(i)

    def clear_selected():
        selected_ids.clear()
        selected_lb.delete(0, tk.END)

    tk.Button(btn_frame, text="Add →", command=add_selected).pack(pady=6)
    tk.Button(btn_frame, text="← Remove", command=remove_selected).pack(pady=6)
    tk.Button(btn_frame, text="Clear", command=clear_selected).pack(pady=6)

    def refresh_evaluator_lists():
        nonlocal_vars = {"ok": True}  # just to avoid python scoping confusion in some editors

        users = load_users_cache(USERS_CACHE_FILE)
        if not users:
            # no cache yet; keep empty list
            id_to_name.clear()
            display_items.clear()
        else:
            id_map, items = build_user_maps(users)
            id_to_name.clear()
            id_to_name.update(id_map)
            display_items.clear()
            display_items.extend(items)

        refresh_available()

    # Make it available to other functions (refresh after cache refresh)
    globals()["refresh_evaluator_lists"] = refresh_evaluator_lists  # intentional

    search_var.trace_add("write", lambda *args: refresh_available())
    refresh_evaluator_lists()

    evalq_status = tk.Label(tab_eval_query, text="", fg="blue", wraplength=820, justify="left")
    evalq_status.pack(padx=10, pady=10, anchor="w")

    def run_eval_query_export():
        def job():
            try:
                if not selected_ids:
                    raise ValueError("Select at least one evaluator from the list.")

                client_id = client_id_entry.get().strip()
                client_secret = client_secret_entry.get().strip()
                region = region_var.get().strip()
                if not client_id or not client_secret:
                    raise ValueError("Client ID and Client Secret are required.")
                if region not in REGION_HOSTS:
                    raise ValueError(f"Unknown region: {region}")

                if remember_var.get() == 1:
                    save_credentials_encrypted(client_id, client_secret, region)

                login_host = REGION_HOSTS[region]["login"]
                api_host = REGION_HOSTS[region]["api"]

                # Ensure users cache exists (so evaluator_name can be added)
                users = load_users_cache(USERS_CACHE_FILE)
                if not users:
                    evalq_status.config(text="Users cache missing. Fetching users (one-time)...")
                    token_tmp = authenticate_client_credentials(client_id, client_secret, login_host)
                    users = fetch_all_users(api_host, token_tmp)
                    save_users_cache(users, USERS_CACHE_FILE)
                    refresh_evaluator_lists()

                # we now always export ALL statuses
                statuses = None

                # output path
                start_iso, end_iso = to_iso_bounds(evalq_start.get_date(), evalq_end.get_date())
                out_default = f"evaluations_by_evaluator_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
                out_path = filedialog.asksaveasfilename(
                    defaultextension=".csv",
                    initialfile=out_default,
                    filetypes=[("CSV Files", "*.csv")],
                )
                if not out_path:
                    evalq_status.config(text="Save cancelled.")
                    return

                evalq_status.config(text="Authenticating...")
                token = authenticate_client_credentials(client_id, client_secret, login_host)

                evalq_status.config(text=f"Running query-only export for {len(selected_ids)} evaluator(s)...")
                summary = export_query_only_to_csv(
                    token=token,
                    api_host=api_host,
                    evaluator_user_ids=selected_ids,
                    start_time_iso=start_iso,
                    end_time_iso=end_iso,
                    output_csv_path=out_path,
                    user_id_to_name=id_to_name,
                    statuses=None,  # ALL statuses
                    sleep_between_calls_s=float(throttle_var.get()),
                )


                evalq_status.config(
                    text=(
                        "✅ Done!\n"
                        f"- Saved: {summary['saved_to']}\n"
                        f"- Rows: {summary['rows']}\n"
                        f"- Evaluators: {summary['evaluators_selected']}"
                    )
                )


            except Exception as e:
                messagebox.showerror("Error", str(e))
                evalq_status.config(text=f"❌ Error: {e}")

        threading.Thread(target=job, daemon=True).start()

    tk.Button(evalq_frame, text="Export query-only CSV", command=run_eval_query_export, height=2).grid(
        row=6, column=0, columnspan=2, sticky="w", padx=8, pady=10
    )

    root.mainloop()


if __name__ == "__main__":
    run_gui()
