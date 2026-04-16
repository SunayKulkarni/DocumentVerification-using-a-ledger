from __future__ import annotations

import os
from pathlib import Path
from uuid import uuid4

from flask import Flask, flash, jsonify, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

from main import (
    DEFAULT_CHAIN_PATH,
    append_document_block,
    build_document_payload,
    find_document_record,
    load_chain,
    save_chain,
    sha256_file,
    validate_chain,
)

BASE_DIR = Path(__file__).resolve().parent
UPLOADS_DIR = BASE_DIR / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)


def _get_dashboard_state(chain_path: Path) -> dict[str, object]:
    try:
        chain = load_chain(chain_path)
        is_valid, chain_message = validate_chain(chain)
    except Exception as exc:  # pragma: no cover - defensive error path
        return {
            "chain_path": str(chain_path),
            "is_valid": False,
            "chain_message": f"Unable to read chain: {exc}",
            "chain_blocks": 0,
            "document_count": 0,
            "recent_documents": [],
        }

    docs: list[dict[str, object]] = []
    for block in reversed(chain):
        payload = block.payload
        if payload.get("type") != "document":
            continue
        docs.append(
            {
                "block_index": block.index,
                "document_id": payload.get("document_id", ""),
                "owner": payload.get("owner", ""),
                "file_name": payload.get("file_name", ""),
                "issued_at": payload.get("issued_at", ""),
                "file_hash": payload.get("file_hash", ""),
            }
        )
        if len(docs) >= 8:
            break

    document_count = sum(1 for item in chain if item.payload.get("type") == "document")

    return {
        "chain_path": str(chain_path),
        "is_valid": is_valid,
        "chain_message": chain_message,
        "chain_blocks": len(chain),
        "document_count": document_count,
        "recent_documents": docs,
    }


def _save_uploaded_file() -> tuple[Path, str]:
    file_storage = request.files.get("document")
    if file_storage is None or not file_storage.filename:
        raise ValueError("Please upload a file first.")

    original_name = file_storage.filename
    safe_name = secure_filename(original_name) or "uploaded-document"
    temp_name = f"{uuid4().hex}_{safe_name}"
    target = UPLOADS_DIR / temp_name
    file_storage.save(target)
    return target, original_name


def _render_home(chain_path: Path, issue_result: dict[str, object] | None = None, verify_result: dict[str, object] | None = None):
    state = _get_dashboard_state(chain_path)
    return render_template(
        "index.html",
        state=state,
        issue_result=issue_result,
        verify_result=verify_result,
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    chain_path = Path(os.environ.get("CHAIN_PATH", str(DEFAULT_CHAIN_PATH)))

    @app.get("/")
    def home():
        return _render_home(chain_path)

    @app.post("/issue")
    def issue_document():
        owner = request.form.get("owner", "").strip()
        note = request.form.get("note", "").strip()
        document_id = request.form.get("document_id", "").strip() or None

        if not owner:
            flash("Owner name is required for issuance.", "error")
            return redirect(url_for("home"))

        temp_file: Path | None = None
        try:
            temp_file, original_name = _save_uploaded_file()

            chain = load_chain(chain_path)
            is_valid, chain_message = validate_chain(chain)
            if not is_valid:
                flash(f"Cannot issue document: {chain_message}", "error")
                return redirect(url_for("home"))

            payload = build_document_payload(
                file_path=temp_file,
                owner=owner,
                document_id=document_id,
                note=note,
            )
            payload["file_name"] = original_name

            block = append_document_block(chain, payload)
            save_chain(chain_path, chain)

            issue_result = {
                "status": "success",
                "message": "Document issued successfully.",
                "block_index": block.index,
                "document_id": payload["document_id"],
                "file_hash": payload["file_hash"],
                "owner": payload["owner"],
                "issued_at": payload["issued_at"],
            }
            return _render_home(chain_path, issue_result=issue_result)
        except Exception as exc:
            flash(f"Issue failed: {exc}", "error")
            return redirect(url_for("home"))
        finally:
            if temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)

    @app.post("/verify")
    def verify_document():
        document_id = request.form.get("document_id", "").strip() or None

        temp_file: Path | None = None
        try:
            temp_file, original_name = _save_uploaded_file()

            chain = load_chain(chain_path)
            is_valid, chain_message = validate_chain(chain)
            if not is_valid:
                verify_result = {
                    "status": "error",
                    "message": f"Blockchain integrity failed: {chain_message}",
                }
                return _render_home(chain_path, verify_result=verify_result)

            file_hash = sha256_file(temp_file)
            record = find_document_record(chain, file_hash, document_id)

            if record is None:
                verify_result = {
                    "status": "error",
                    "message": "Document is not verified. No matching blockchain record found.",
                    "file_name": original_name,
                    "file_hash": file_hash,
                    "document_id": document_id or "Not provided",
                }
            else:
                payload = record.payload
                verify_result = {
                    "status": "success",
                    "message": "Document verified successfully.",
                    "file_name": original_name,
                    "file_hash": file_hash,
                    "block_index": record.index,
                    "document_id": payload.get("document_id", ""),
                    "owner": payload.get("owner", ""),
                    "issued_at": payload.get("issued_at", ""),
                }

            return _render_home(chain_path, verify_result=verify_result)
        except Exception as exc:
            flash(f"Verification failed: {exc}", "error")
            return redirect(url_for("home"))
        finally:
            if temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)

    @app.get("/api/chain")
    def api_chain():
        chain = load_chain(chain_path)
        is_valid, chain_message = validate_chain(chain)
        return jsonify(
            {
                "is_valid": is_valid,
                "message": chain_message,
                "blocks": [
                    {
                        "index": block.index,
                        "timestamp": block.timestamp,
                        "previous_hash": block.previous_hash,
                        "hash": block.hash,
                        "payload": block.payload,
                    }
                    for block in chain
                ],
            }
        )

    return app


app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
