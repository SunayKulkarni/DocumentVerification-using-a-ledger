"""Digital document verification using a local blockchain ledger.

Usage examples:
  python main.py init
  python main.py issue test.pdf --owner "Alice"
  python main.py verify test.pdf
  python main.py validate
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

DEFAULT_CHAIN_PATH = Path("chain.json")


@dataclass
class Block:
    index: int
    timestamp: str
    previous_hash: str
    payload: dict[str, Any]
    hash: str


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_json(data: Any) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def calculate_block_hash(block_data: dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(block_data).encode("utf-8"))


def create_genesis_block() -> Block:
    block_data = {
        "index": 0,
        "timestamp": now_utc(),
        "previous_hash": "0" * 64,
        "payload": {
            "type": "genesis",
            "message": "Digital document verification chain initialized",
        },
    }
    block_hash = calculate_block_hash(block_data)
    return Block(hash=block_hash, **block_data)


def block_to_hashable_dict(block: Block) -> dict[str, Any]:
    return {
        "index": block.index,
        "timestamp": block.timestamp,
        "previous_hash": block.previous_hash,
        "payload": block.payload,
    }


def save_chain(chain_path: Path, chain: list[Block]) -> None:
    raw = [asdict(block) for block in chain]
    chain_path.write_text(json.dumps(raw, indent=2), encoding="utf-8")


def parse_block(raw_block: dict[str, Any]) -> Block:
    required_keys = {"index", "timestamp", "previous_hash", "payload", "hash"}
    if required_keys != set(raw_block.keys()):
        missing_or_extra = {
            "missing": sorted(required_keys - set(raw_block.keys())),
            "extra": sorted(set(raw_block.keys()) - required_keys),
        }
        raise ValueError(f"Invalid block schema: {missing_or_extra}")

    return Block(
        index=int(raw_block["index"]),
        timestamp=str(raw_block["timestamp"]),
        previous_hash=str(raw_block["previous_hash"]),
        payload=dict(raw_block["payload"]),
        hash=str(raw_block["hash"]),
    )


def load_chain(chain_path: Path) -> list[Block]:
    if not chain_path.exists():
        chain = [create_genesis_block()]
        save_chain(chain_path, chain)
        return chain

    raw_chain = json.loads(chain_path.read_text(encoding="utf-8"))
    if not isinstance(raw_chain, list) or not raw_chain:
        raise ValueError("Chain file is empty or malformed.")

    return [parse_block(item) for item in raw_chain]


def validate_chain(chain: list[Block]) -> tuple[bool, str]:
    if not chain:
        return False, "Chain is empty."

    first = chain[0]
    expected_genesis_hash = calculate_block_hash(block_to_hashable_dict(first))
    if first.index != 0 or first.previous_hash != "0" * 64 or first.hash != expected_genesis_hash:
        return False, "Genesis block is invalid or has been tampered with."

    for idx in range(1, len(chain)):
        current = chain[idx]
        previous = chain[idx - 1]

        if current.index != previous.index + 1:
            return False, f"Invalid index continuity at block {idx}."

        if current.previous_hash != previous.hash:
            return False, f"Broken previous_hash link at block {idx}."

        recalculated_hash = calculate_block_hash(block_to_hashable_dict(current))
        if recalculated_hash != current.hash:
            return False, f"Hash mismatch at block {idx}."

    return True, f"Chain is valid ({len(chain)} blocks)."


def build_document_payload(
    file_path: Path,
    owner: str,
    document_id: str | None,
    note: str,
) -> dict[str, Any]:
    doc_id = document_id or str(uuid4())
    return {
        "type": "document",
        "document_id": doc_id,
        "owner": owner,
        "file_name": file_path.name,
        "file_size": file_path.stat().st_size,
        "file_hash": sha256_file(file_path),
        "issued_at": now_utc(),
        "note": note,
    }


def append_document_block(chain: list[Block], payload: dict[str, Any]) -> Block:
    previous = chain[-1]
    block_data = {
        "index": previous.index + 1,
        "timestamp": now_utc(),
        "previous_hash": previous.hash,
        "payload": payload,
    }
    block_hash = calculate_block_hash(block_data)
    block = Block(hash=block_hash, **block_data)
    chain.append(block)
    return block


def find_document_record(
    chain: list[Block], file_hash: str, document_id: str | None
) -> Block | None:
    for block in reversed(chain):
        payload = block.payload
        if payload.get("type") != "document":
            continue
        if document_id is not None and payload.get("document_id") != document_id:
            continue
        if payload.get("file_hash") == file_hash:
            return block
    return None


def init_command(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    if chain_path.exists() and not args.force:
        print(f"Chain already exists at: {chain_path}")
        print("Use --force to recreate it.")
        return 1

    chain = [create_genesis_block()]
    save_chain(chain_path, chain)
    print(f"Initialized blockchain at: {chain_path}")
    return 0


def issue_command(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    file_path = Path(args.file)

    if not file_path.exists() or not file_path.is_file():
        print(f"Document not found: {file_path}")
        return 1

    chain = load_chain(chain_path)
    valid, message = validate_chain(chain)
    if not valid:
        print(f"Cannot issue document. {message}")
        return 1

    payload = build_document_payload(
        file_path=file_path,
        owner=args.owner,
        document_id=args.document_id,
        note=args.note,
    )
    block = append_document_block(chain, payload)
    save_chain(chain_path, chain)

    print("Document issued successfully.")
    print(f"Block index : {block.index}")
    print(f"Document ID : {payload['document_id']}")
    print(f"File SHA256 : {payload['file_hash']}")
    print(f"Block hash  : {block.hash}")
    return 0


def verify_command(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    file_path = Path(args.file)

    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        return 1

    if not file_path.exists() or not file_path.is_file():
        print(f"Document not found: {file_path}")
        return 1

    chain = load_chain(chain_path)
    valid, message = validate_chain(chain)
    if not valid:
        print(f"Verification failed: {message}")
        return 1

    file_hash = sha256_file(file_path)
    record = find_document_record(chain, file_hash, args.document_id)
    if record is None:
        print("Document is NOT verified.")
        print("No matching blockchain record found for this file hash.")
        if args.document_id:
            print(f"Searched with Document ID: {args.document_id}")
        return 1

    payload = record.payload
    print("Document verified successfully.")
    print(f"Block index : {record.index}")
    print(f"Document ID : {payload.get('document_id')}")
    print(f"Owner       : {payload.get('owner')}")
    print(f"Issued at   : {payload.get('issued_at')}")
    print(f"File SHA256 : {payload.get('file_hash')}")
    return 0


def validate_command(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        return 1

    chain = load_chain(chain_path)
    valid, message = validate_chain(chain)
    print(message)
    return 0 if valid else 1


def show_command(args: argparse.Namespace) -> int:
    chain_path = Path(args.chain)
    if not chain_path.exists():
        print(f"Chain file not found: {chain_path}")
        return 1

    chain = load_chain(chain_path)
    blocks = chain[-args.last :] if args.last else chain
    for block in blocks:
        print("-" * 72)
        print(f"Index      : {block.index}")
        print(f"Timestamp  : {block.timestamp}")
        print(f"Prev hash  : {block.previous_hash}")
        print(f"Block hash : {block.hash}")
        print(f"Payload    : {json.dumps(block.payload, indent=2)}")
    print("-" * 72)
    print(f"Displayed {len(blocks)} of {len(chain)} blocks.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Digital document verification with a local blockchain ledger."
    )
    parser.add_argument(
        "--chain",
        default=str(DEFAULT_CHAIN_PATH),
        help="Path to the blockchain JSON file (default: chain.json)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize blockchain ledger")
    init_parser.add_argument(
        "--force",
        action="store_true",
        help="Recreate the chain file if it already exists",
    )
    init_parser.set_defaults(func=init_command)

    issue_parser = subparsers.add_parser("issue", help="Issue a document to blockchain")
    issue_parser.add_argument("file", help="Path to the document file")
    issue_parser.add_argument(
        "--owner",
        required=True,
        help="Owner name for the document",
    )
    issue_parser.add_argument(
        "--document-id",
        help="Optional existing document id (UUID recommended)",
    )
    issue_parser.add_argument(
        "--note",
        default="",
        help="Optional extra note",
    )
    issue_parser.set_defaults(func=issue_command)

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a document against blockchain"
    )
    verify_parser.add_argument("file", help="Path to the document file")
    verify_parser.add_argument(
        "--document-id",
        help="Optional document id to narrow verification",
    )
    verify_parser.set_defaults(func=verify_command)

    validate_parser = subparsers.add_parser(
        "validate", help="Validate blockchain integrity"
    )
    validate_parser.set_defaults(func=validate_command)

    show_parser = subparsers.add_parser("show", help="Show blockchain blocks")
    show_parser.add_argument(
        "--last",
        type=int,
        default=0,
        help="Show only the last N blocks",
    )
    show_parser.set_defaults(func=show_command)

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        return args.func(args)
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"Error: {exc}")
        return 1


if __name__ == "__main__":
    os.environ.setdefault("PYTHONHASHSEED", "0")
    sys.exit(main())

