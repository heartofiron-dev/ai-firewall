from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .model import LinearModel
from . import __version__


MAX_MODEL_BYTES = 10 * 1024 * 1024
MAX_BUNDLE_BYTES = 12 * 1024 * 1024
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
EXPECTED_MEMBERS = {"manifest.json", "model.json", "signature.bin"}


def _crypto() -> tuple[Any, Any, Any]:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey, Ed25519PublicKey,
        )
    except ImportError as exc:
        raise ValueError("模型签名功能需要先安装: pip install -e '.[updates]'") from exc
    return serialization, Ed25519PrivateKey, Ed25519PublicKey


def _canonical_json(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _check_plain_file(path: Path, limit: int, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} 必须是普通文件")
    if path.stat().st_size > limit:
        raise ValueError(f"{label} 超过安全大小上限")


def _version_tuple(value: str) -> tuple[int, int, int]:
    if not VERSION_PATTERN.fullmatch(value):
        raise ValueError("manifest 版本不是有效 SemVer")
    core = value.split("-", 1)[0].split("+", 1)[0]
    return tuple(int(part) for part in core.split("."))


def generate_signing_keys(
    private_path: str | Path, public_path: str | Path, *, overwrite: bool = False,
) -> None:
    serialization, Ed25519PrivateKey, _ = _crypto()
    private_file, public_file = Path(private_path), Path(public_path)
    if private_file.resolve() == public_file.resolve():
        raise ValueError("私钥与公钥必须是不同文件")
    if not overwrite and (private_file.exists() or public_file.exists()):
        raise ValueError("密钥文件已存在；默认拒绝覆盖")
    if private_file.is_symlink() or public_file.is_symlink():
        raise ValueError("密钥路径不能是符号链接")
    private_file.parent.mkdir(parents=True, exist_ok=True)
    public_file.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_file.write_bytes(private_bytes)
    public_file.write_bytes(public_bytes)
    if os.name != "nt":
        private_file.chmod(0o600)


def create_signed_bundle(
    model_path: str | Path,
    private_key_path: str | Path,
    output_path: str | Path,
    *,
    version: str,
    min_app_version: str = "1.0.0",
    overwrite: bool = False,
) -> dict[str, object]:
    if not VERSION_PATTERN.fullmatch(version) or not VERSION_PATTERN.fullmatch(min_app_version):
        raise ValueError("版本必须使用 SemVer，例如 1.0.0")
    serialization, Ed25519PrivateKey, _ = _crypto()
    model_file, key_file, output = Path(model_path), Path(private_key_path), Path(output_path)
    _check_plain_file(model_file, MAX_MODEL_BYTES, "模型")
    _check_plain_file(key_file, 64 * 1024, "私钥")
    if output.suffix.casefold() != ".aifw":
        raise ValueError("签名更新包必须使用 .aifw 扩展名")
    if output.exists() and not overwrite:
        raise ValueError("更新包已存在；默认拒绝覆盖")
    if output.is_symlink():
        raise ValueError("更新包路径不能是符号链接")
    model_bytes = model_file.read_bytes()
    # Refuse to sign an incompatible or malformed model.
    LinearModel.load(model_file)
    manifest: dict[str, object] = {
        "schema_version": "1.0",
        "package_version": version,
        "min_app_version": min_app_version,
        "algorithm": "ed25519",
        "model_sha256": hashlib.sha256(model_bytes).hexdigest(),
        "model_bytes": len(model_bytes),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    private_key = serialization.load_pem_private_key(key_file.read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("私钥不是 Ed25519 私钥")
    signature = private_key.sign(_canonical_json(manifest))
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    if temporary.exists() or temporary.is_symlink():
        raise ValueError("临时更新包已存在，请先人工检查")
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", _canonical_json(manifest))
            archive.writestr("model.json", model_bytes)
            archive.writestr("signature.bin", signature)
        temporary.replace(output)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest


def verify_signed_bundle(
    bundle_path: str | Path,
    public_key_path: str | Path,
    *,
    expected_version: str,
) -> tuple[dict[str, object], bytes]:
    serialization, _, Ed25519PublicKey = _crypto()
    bundle, public_key = Path(bundle_path), Path(public_key_path)
    _check_plain_file(bundle, MAX_BUNDLE_BYTES, "更新包")
    _check_plain_file(public_key, 64 * 1024, "公钥")
    if not VERSION_PATTERN.fullmatch(expected_version):
        raise ValueError("expected_version 必须使用 SemVer")
    try:
        with zipfile.ZipFile(bundle, "r") as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or set(names) != EXPECTED_MEMBERS:
                raise ValueError("更新包只能包含 manifest.json、model.json 和 signature.bin")
            if any(info.file_size > MAX_MODEL_BYTES for info in archive.infolist()):
                raise ValueError("更新包成员超过安全大小上限")
            manifest_bytes = archive.read("manifest.json")
            model_bytes = archive.read("model.json")
            signature = archive.read("signature.bin")
    except zipfile.BadZipFile as exc:
        raise ValueError("更新包格式无效") from exc
    try:
        manifest = json.loads(manifest_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError("更新包 manifest 无效") from exc
    if not isinstance(manifest, dict) or manifest.get("schema_version") != "1.0":
        raise ValueError("不支持的更新包 manifest")
    if _canonical_json(manifest) != manifest_bytes:
        raise ValueError("manifest 必须使用规范 JSON 编码")
    if manifest.get("package_version") != expected_version:
        raise ValueError("更新包版本与固定的 expected_version 不一致")
    minimum = str(manifest.get("min_app_version") or "")
    if _version_tuple(__version__) < _version_tuple(minimum):
        raise ValueError(f"当前程序版本 {__version__} 低于更新包要求 {minimum}")
    if manifest.get("algorithm") != "ed25519":
        raise ValueError("更新包签名算法不受支持")
    if manifest.get("model_bytes") != len(model_bytes):
        raise ValueError("模型大小校验失败")
    if manifest.get("model_sha256") != hashlib.sha256(model_bytes).hexdigest():
        raise ValueError("模型 SHA-256 校验失败")
    verifier = serialization.load_pem_public_key(public_key.read_bytes())
    if not isinstance(verifier, Ed25519PublicKey):
        raise ValueError("公钥不是 Ed25519 公钥")
    try:
        verifier.verify(signature, manifest_bytes)
    except Exception as exc:
        raise ValueError("Ed25519 签名验证失败") from exc
    return manifest, model_bytes


def install_signed_bundle(
    bundle_path: str | Path,
    public_key_path: str | Path,
    target_path: str | Path,
    *,
    expected_version: str,
) -> dict[str, object]:
    manifest, model_bytes = verify_signed_bundle(
        bundle_path, public_key_path, expected_version=expected_version,
    )
    target = Path(target_path)
    if target.is_symlink():
        raise ValueError("模型目标不能是符号链接")
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(target.name + ".staged")
    backup = target.with_name(target.name + ".rollback")
    if staged.exists() or staged.is_symlink():
        raise ValueError("暂存模型已存在，请先人工检查")
    staged.write_bytes(model_bytes)
    try:
        LinearModel.load(staged)
        if backup.exists():
            if backup.is_symlink():
                raise ValueError("回滚模型不能是符号链接")
            backup.unlink()
        if target.exists():
            shutil.copy2(target, backup)
        staged.replace(target)
        try:
            LinearModel.load(target)
        except Exception:
            if backup.exists():
                backup.replace(target)
            raise
    finally:
        staged.unlink(missing_ok=True)
    return {"installed": True, "package_version": manifest["package_version"], "backup": str(backup)}


def rollback_model(target_path: str | Path) -> dict[str, object]:
    target = Path(target_path)
    backup = target.with_name(target.name + ".rollback")
    _check_plain_file(backup, MAX_MODEL_BYTES, "回滚模型")
    LinearModel.load(backup)
    failed = target.with_name(target.name + ".failed")
    if failed.exists() or failed.is_symlink():
        raise ValueError("失败模型保留路径已存在，请先人工检查")
    if target.exists():
        target.replace(failed)
    try:
        backup.replace(target)
        LinearModel.load(target)
    except Exception:
        if failed.exists():
            failed.replace(target)
        raise
    return {"rolled_back": True, "failed_model": str(failed) if failed.exists() else None}
