from __future__ import annotations

import base64
import io
import os
import socket
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

from flask import Flask, flash, has_request_context, jsonify, redirect, render_template, request, url_for
import qrcode  # pyright: ignore[reportMissingModuleSource]
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


def _guess_local_ip() -> str | None:
    # Detect a LAN-reachable IP for QR links used by mobile devices.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            ip = sock.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
    except OSError:
        pass

    try:
        ip = socket.gethostbyname(socket.gethostname())
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass

    return None


def _resolve_public_base_url() -> str:
    configured = os.environ.get("PUBLIC_BASE_URL", "").strip().rstrip("/")
    if configured:
        return configured

    current = request.host_url.rstrip("/")
    parsed = urlparse(current)
    if parsed.hostname in {"localhost", "127.0.0.1"}:
        lan_ip = _guess_local_ip()
        if lan_ip:
            port = f":{parsed.port}" if parsed.port else ""
            return f"{parsed.scheme}://{lan_ip}{port}"

    return current


def _build_verify_url(document_id: str) -> str:
    base_url = _resolve_public_base_url()
    verify_path = url_for("verify_by_document_id", document_id=document_id)
    return f"{base_url}{verify_path}"


def _build_qr_image_data(content: str) -> str:
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(content)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    encoded = base64.b64encode(buffer.getvalue()).decode("ascii")
    return f"data:image/png;base64,{encoded}"


def _find_document_block_by_id(chain, document_id: str):
    for block in reversed(chain):
        payload = block.payload
        if payload.get("type") != "document":
            continue
        if payload.get("document_id") == document_id:
            return block
    return None


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
    qr_base_url = _resolve_public_base_url() if has_request_context() else ""
    qr_uses_configured_base = bool(os.environ.get("PUBLIC_BASE_URL", "").strip())
    return render_template(
        "index.html",
        state=state,
        issue_result=issue_result,
        verify_result=verify_result,
        qr_base_url=qr_base_url,
        qr_uses_configured_base=qr_uses_configured_base,
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-secret-change-me")
    app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024

    chain_path = Path(os.environ.get("CHAIN_PATH", str(DEFAULT_CHAIN_PATH)))

    @app.get("/")
    def home():
        return _render_home(chain_path)

    @app.get("/verify/<document_id>")
    def verify_by_document_id(document_id: str):
        chain = load_chain(chain_path)
        is_valid, chain_message = validate_chain(chain)

        if not is_valid:
            return render_template(
                "qr_verify.html",
                status="error",
                message=f"Blockchain integrity check failed: {chain_message}",
                record=None,
                chain_valid=is_valid,
                chain_message=chain_message,
                verify_url=None,
                qr_image_data=None,
            )

        record_block = _find_document_block_by_id(chain, document_id)
        if record_block is None:
            return render_template(
                "qr_verify.html",
                status="error",
                message="No blockchain record found for this document ID.",
                record=None,
                chain_valid=is_valid,
                chain_message=chain_message,
                verify_url=None,
                qr_image_data=None,
            )

        payload = record_block.payload
        verify_url = _build_verify_url(document_id)
        qr_image_data = _build_qr_image_data(verify_url)
        record = {
            "block_index": record_block.index,
            "document_id": payload.get("document_id", ""),
            "owner": payload.get("owner", ""),
            "file_name": payload.get("file_name", ""),
            "issued_at": payload.get("issued_at", ""),
            "file_hash": payload.get("file_hash", ""),
        }
        return render_template(
            "qr_verify.html",
            status="success",
            message="Document ID exists on the blockchain ledger.",
            record=record,
            chain_valid=is_valid,
            chain_message=chain_message,
            verify_url=verify_url,
            qr_image_data=qr_image_data,
        )

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
            issue_result["verify_url"] = _build_verify_url(payload["document_id"])
            issue_result["qr_image_data"] = _build_qr_image_data(issue_result["verify_url"])
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
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", "5000"))
    app.run(host=host, port=port, debug=True)
