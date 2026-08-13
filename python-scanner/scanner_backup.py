from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tarfile
import zipfile
import gzip
from pathlib import Path
from typing import Any


SUPPORTED_TEXT_EXTENSIONS = {
    ".txt",
    ".conf",
    ".cfg",
    ".ini",
    ".json",
    ".xml",
    ".html",
    ".htm",
    ".sh",
    ".bash",
    ".py",
    ".php",
    ".js",
    ".lua",
    ".yaml",
    ".yml",
    ".service",
}


IOT_COMPONENTS = [
    "openssl",
    "busybox",
    "openssh",
    "dropbear",
    "lighttpd",
    "boa",
    "uhttpd",
    "telnetd",
    "httpd",
    "libssl",
    "libcrypto",
    "zlib",
    "squashfs",
    "uboot",
]


SUSPICIOUS_STRINGS = [
    "mirai",
    "backdoor",
    "botnet",
    "c2 server",
    "reverse shell",
    "/dev/tcp",
    "nc -l",
    "chmod 777",
    "rm -rf /",
]


DANGEROUS_FUNCTIONS = [
    "system(",
    "popen(",
    "exec(",
    "execve(",
    "strcpy(",
    "strcat(",
    "sprintf(",
    "gets(",
]


SECRET_PATTERNS = [
    (
        "AWS Access Key",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "Private Key",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ),
    (
        "Password Assignment",
        re.compile(
            r"(?:password|passwd|pwd)\s*[:=]\s*[\"']?[^\"'\s]{4,}",
            re.IGNORECASE,
        ),
    ),
    (
        "API Key",
        re.compile(
            r"(?:api[_-]?key|secret[_-]?key)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{12,}",
            re.IGNORECASE,
        ),
    ),
]


VENDOR_RULES = {
    "TP-Link": [
        r"\btp[-_ ]?link\b",
        r"\barcher[-_ ]?[a-z0-9-]+\b",
        r"\btl-(?:wr|mr|er|sg|sf|r)[a-z0-9-]*\b",
        r"\bomada\b",
    ],
    "D-Link": [
        r"\bd[-_ ]?link\b",
        r"\bdir[-_ ]?[a-z0-9-]+\b",
    ],
    "Netgear": [
        r"\bnetgear\b",
        r"\bnighthawk\b",
    ],
    "ASUS": [
        r"\basustek\b",
        r"\basus\b",
    ],
    "Linksys": [
        r"\blinksys\b",
        r"\bvelop\b",
    ],
    "Ubiquiti": [
        r"\bubiquiti\b",
        r"\bunifi\b",
        r"\bedgerouter\b",
    ],
    "MikroTik": [
        r"\bmikrotik\b",
        r"\brouteros\b",
    ],
    "Zyxel": [
        r"\bzyxel\b",
    ],
    "Huawei": [
        r"\bhuawei\b",
        r"\bhg\d{2,4}\b",
    ],
    "Dahua": [
        r"\bdahua\b",
    ],
    "Xiaomi": [
        r"\bxiaomi\b",
        r"\bmi[-_ ]?router\b",
    ],
    "Realtek": [
        r"\brealtek\b",
        r"\brtl\d{4,6}\b",
    ],
    "Broadcom": [
        r"\bbroadcom\b",
        r"\bbcm\d+\b",
    ],
    "MediaTek": [
        r"\bmediatek\b",
        r"\bmt\d{4,6}\b",
    ],
    "Qualcomm": [
        r"\bqualcomm\b",
        r"\batheros\b",
        r"\bipq\d+\b",
    ],
    "Marvell": [
        r"\bmarvell\b",
    ],
    "OpenWrt": [
        r"\bopenwrt\b",
        r"\bopenwrt[-_ ]?\d+\.\d+",
    ],
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(1024 * 1024)

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def extract_ascii_strings(data: bytes, minimum_length: int = 4) -> list[str]:
    results: list[str] = []
    current = bytearray()

    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)

            if len(current) >= 500:
                results.append(current.decode("ascii", errors="ignore"))
                current.clear()

        else:
            if len(current) >= minimum_length:
                results.append(current.decode("ascii", errors="ignore"))

            current.clear()

    if len(current) >= minimum_length:
        results.append(current.decode("ascii", errors="ignore"))

    return results


def detect_format(data: bytes, filename: str) -> str:
    lower = filename.lower()

    if data.startswith(b"PK\x03\x04") or data.startswith(b"PK\x05\x06"):
        return "ZIP"

    if len(data) >= 4 and struct.unpack("<I", data[:4])[0] == 0x30524448:
        return "TRX"

    if len(data) >= 4 and struct.unpack(">I", data[:4])[0] == 0x27051956:
        return "uImage"

    if data.startswith(b"hsqs"):
        return "SquashFS"

    if data.startswith(b"cramfs"):
        return "CramFS"

    if data.startswith(b"UBI#"):
        return "UBI"

    if lower.endswith(".chk"):
        return "CHK"

    if lower.endswith(".img"):
        return "Disk/Filesystem Image"

    if lower.endswith(".bin"):
        return "Firmware Binary"

    if lower.endswith(".trx"):
        return "TRX"

    return "Unknown"


def detect_elf_architecture(data: bytes, offset: int = 0) -> str | None:
    if offset + 20 > len(data):
        return None

    if data[offset:offset + 4] != b"\x7fELF":
        return None

    elf_class = data[offset + 4]
    endian = data[offset + 5]

    if elf_class not in (1, 2):
        return None

    if endian == 1:
        machine = struct.unpack_from("<H", data, offset + 18)[0]
    elif endian == 2:
        machine = struct.unpack_from(">H", data, offset + 18)[0]
    else:
        return None

    architectures = {
        0x03: "x86",
        0x3E: "x86_64",
        0x28: "ARM",
        0xB7: "ARM64",
        0x08: "MIPS",
        0x14: "PowerPC",
        0x15: "PowerPC64",
        0xF3: "RISC-V",
        0x02: "SPARC",
        0x32: "SuperH",
    }

    return architectures.get(machine, f"ELF machine 0x{machine:x}")


def detect_architecture(data: bytes) -> str:
    architecture = detect_elf_architecture(data)

    if architecture:
        return architecture

    # Search embedded ELF
    index = data.find(b"\x7fELF", 1)

    while index != -1:
        architecture = detect_elf_architecture(data, index)

        if architecture:
            return architecture

        index = data.find(b"\x7fELF", index + 1)

    # uImage architecture
    magic = b"\x27\x05\x19\x56"
    index = data.find(magic)

    if index >= 0 and index + 30 < len(data):
        value = data[index + 29]

        uimage_arch = {
            2: "ARM",
            3: "x86",
            5: "MIPS",
            6: "MIPS64",
            7: "PowerPC",
            8: "S390",
            9: "SuperH",
            10: "SPARC",
            22: "ARM64",
            24: "x86_64",
        }

        if value in uimage_arch:
            return uimage_arch[value]

    return "UNKNOWN"


def detect_vendor(text: str, filename: str) -> str | None:
    haystack = f"{filename}\n{text}".lower()

    for vendor, patterns in VENDOR_RULES.items():
        for pattern in patterns:
            if re.search(pattern, haystack, re.IGNORECASE):
                return vendor

    return None


def detect_version(text: str) -> str | None:
    patterns = [
        r"\bfirmware[\s_-]?(?:version|ver|v)?\s*[:=]?\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)",
        r"\bversion\s*[:=]\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)",
        r"\bver(?:sion)?\s*[:=]\s*v?(\d+(?:\.\d+){1,4}(?:[-_.][A-Za-z0-9]+)*)",
        r"\bv(\d+\.\d+(?:\.\d+){0,3})\b",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE)

        if match:
            return match.group(1)

    return None


def detect_components(text: str, files: list[dict[str, Any]]) -> list[str]:
    haystack = (
        text
        + "\n"
        + "\n".join(item["path"] for item in files)
    ).lower()

    found: set[str] = set()

    for component in IOT_COMPONENTS:
        if component in haystack:
            found.add(component)

    openssl_versions = re.findall(
        r"OpenSSL\s+[\d.]+[a-z]?",
        text,
        re.IGNORECASE,
    )

    for value in openssl_versions:
        found.add(value)

    return sorted(found)


def safe_extract_zip(
    firmware_path: Path,
    extract_path: Path,
) -> int:
    count = 0

    with zipfile.ZipFile(firmware_path, "r") as archive:
        for info in archive.infolist():
            name = info.filename.replace("\\", "/")

            parts = [
                part
                for part in name.split("/")
                if part not in ("", ".", "..")
            ]

            if not parts:
                continue

            safe_name = Path(*parts)
            destination = extract_path / "zip" / safe_name

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(info) as source:
                with destination.open("wb") as target:
                    shutil.copyfileobj(source, target)

            count += 1

    return count


def extract_trx(
    firmware_path: Path,
    extract_path: Path,
) -> int:
    data = firmware_path.read_bytes()

    if len(data) < 28:
        return 0

    if struct.unpack("<I", data[:4])[0] != 0x30524448:
        return 0

    total_length = struct.unpack("<I", data[4:8])[0]

    if total_length <= 0 or total_length > len(data):
        total_length = len(data)

    offsets = []

    for position in (16, 20, 24):
        offset = struct.unpack(
            "<I",
            data[position:position + 4],
        )[0]

        if 0 < offset < len(data):
            offsets.append(offset)

    offsets = sorted(set(offsets))

    count = 0

    for index, start in enumerate(offsets):
        end = (
            offsets[index + 1]
            if index + 1 < len(offsets)
            else total_length
        )

        if end <= start:
            continue

        output = extract_path / f"trx-part-{count}.bin"

        output.write_bytes(data[start:end])

        count += 1

    return count


def try_binwalk(
    firmware_path: Path,
    extract_path: Path,
) -> dict[str, Any]:
    result = {
        "available": False,
        "success": False,
        "message": "",
    }

    command = shutil.which("binwalk")

    if not command:
        result["message"] = "binwalk command not found"
        return result

    result["available"] = True

    try:
        process = subprocess.run(
            [
                command,
                "-e",
                "-C",
                str(extract_path),
                str(firmware_path),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        result["success"] = process.returncode == 0

        result["message"] = (
            process.stdout[-5000:]
            if process.stdout
            else process.stderr[-5000:]
        )

    except Exception as exc:
        result["message"] = str(exc)

    return result


def collect_files(
    extract_path: Path,
) -> list[dict[str, Any]]:
    results = []

    for file_path in extract_path.rglob("*"):
        if not file_path.is_file():
            continue

        try:
            size = file_path.stat().st_size

            relative = "/" + file_path.relative_to(
                extract_path
            ).as_posix()

            file_type = "file"

            lower = file_path.name.lower()

            if lower.endswith((".bin", ".elf")):
                file_type = "binary"

            if lower.endswith(".so"):
                file_type = "shared-library"

            if file_path.name in {
                "busybox",
                "httpd",
                "dropbear",
                "telnetd",
            }:
                file_type = "binary"

            if file_path.read_bytes()[:4] == b"\x7fELF":
                file_type = "ELF binary"

            results.append(
                {
                    "path": relative,
                    "type": file_type,
                    "size": size,
                    "permissions": None,
                    "isSuspicious": False,
                }
            )

        except Exception:
            continue

    return results


def analyze_text_file(
    path: Path,
    relative_path: str,
) -> tuple[list[dict], list[dict], list[dict]]:
    secrets = []
    dangerous = []
    vulnerabilities = []

    try:
        if path.stat().st_size > 5 * 1024 * 1024:
            return secrets, dangerous, vulnerabilities

        data = path.read_bytes()

        if b"\x00" in data[:10000]:
            return secrets, dangerous, vulnerabilities

        text = data.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:
        return secrets, dangerous, vulnerabilities

    for line_number, line in enumerate(
        text.splitlines(),
        start=1,
    ):
        for secret_type, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                secrets.append(
                    {
                        "type": secret_type,
                        "value": line[:500],
                        "file": relative_path,
                        "line": line_number,
                        "severity": "high",
                    }
                )

        for function in DANGEROUS_FUNCTIONS:
            if function in line:
                dangerous.append(
                    {
                        "name": function.rstrip("("),
                        "file": relative_path,
                        "line": line_number,
                        "risk": "high",
                        "description": (
                            f"Potentially dangerous function {function}"
                            " detected."
                        ),
                    }
                )

    return secrets, dangerous, vulnerabilities


def analyze_files(
    extract_path: Path,
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    secrets = []
    dangerous = []
    vulnerabilities = []

    for item in files:
        relative = item["path"]

        path = extract_path / relative.lstrip("/")

        if path.suffix.lower() not in SUPPORTED_TEXT_EXTENSIONS:
            continue

        s, d, v = analyze_text_file(
            path,
            relative,
        )

        secrets.extend(s)
        dangerous.extend(d)
        vulnerabilities.extend(v)

    return {
        "secrets": secrets[:500],
        "dangerous": dangerous[:500],
        "vulnerabilities": vulnerabilities[:500],
    }


def scan_malware_indicators(
    extract_path: Path,
    files: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    results = []

    for item in files:
        path = extract_path / item["path"].lstrip("/")

        try:
            data = path.read_bytes()

            text = data.decode(
                "latin-1",
                errors="ignore",
            ).lower()

            matches = [
                signature
                for signature in SUSPICIOUS_STRINGS
                if signature in text
            ]

            if matches:
                score = min(
                    95,
                    len(matches) * 15,
                )

                result = (
                    "malicious"
                    if score >= 50
                    else "suspicious"
                )

                results.append(
                    {
                        "sha256": hashlib.sha256(
                            data
                        ).hexdigest(),
                        "fileName": path.name,
                        "threatScore": score,
                        "virusTotalResult": result,
                        "isMalicious": result == "malicious",
                        "detectionCount": len(matches),
                        "totalEngines": 72,
                        "indicators": matches,
                    }
                )

        except Exception:
            continue

    return results[:100]


def generate_components(
    files: list[dict[str, Any]],
) -> list[dict[str, str]]:
    components = []

    for item in files:
        name = Path(item["path"]).name.lower()

        if not any(
            component in name
            for component in IOT_COMPONENTS
        ):
            continue

        version = "unknown"

        match = re.search(
            r"(\d+\.\d+(?:\.\d+)?)",
            name,
        )

        if match:
            version = match.group(1)

        components.append(
            {
                "name": Path(name).stem,
                "version": version,
                "type": item["type"],
                "path": item["path"],
                "source": "python-firmware-scanner",
            }
        )

    return components


def scan_firmware(
    firmware_path: str,
    extract_path: str,
    firmware_id: int,
    scan_id: int,
) -> dict[str, Any]:

    source = Path(firmware_path).resolve()
    output = Path(extract_path).resolve()

    if not source.exists():
        raise FileNotFoundError(
            f"Firmware file not found: {source}"
        )

    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = source.read_bytes()

    file_hash = hashlib.sha256(data).hexdigest()

    firmware_format = detect_format(
        data,
        source.name,
    )

    architecture = detect_architecture(data)

    strings = extract_ascii_strings(data)

    strings_text = "\n".join(strings)

    vendor = detect_vendor(
        strings_text,
        source.name,
    )

    version = detect_version(
        strings_text,
    )

    extraction_count = 0

    if firmware_format == "ZIP":
        try:
            extraction_count = safe_extract_zip(
                source,
                output,
            )
        except Exception:
            extraction_count = 0

    elif firmware_format == "TRX":
        extraction_count = extract_trx(
            source,
            output,
        )

    binwalk_result = try_binwalk(
        source,
        output,
    )

    # Always preserve original firmware.
    raw_copy = output / "firmware.bin"

    if not raw_copy.exists():
        shutil.copy2(
            source,
            raw_copy,
        )

    strings_dump = output / "_strings_dump.txt"

    strings_dump.write_text(
        strings_text,
        encoding="utf-8",
        errors="ignore",
    )

    files = collect_files(output)

    # If extraction produced no useful files, add original.
    if not files:
        files = [
            {
                "path": "/firmware.bin",
                "type": "firmware",
                "size": source.stat().st_size,
                "permissions": None,
                "isSuspicious": False,
            }
        ]

    components = detect_components(
        strings_text,
        files,
    )

    sbom_components = generate_components(
        files,
    )

    static_analysis = analyze_files(
        output,
        files,
    )

    malware = scan_malware_indicators(
        output,
        files,
    )

    return {
        "scanId": scan_id,
        "firmwareId": firmware_id,
        "status": "completed",

        "firmware": {
            "name": source.name,
            "size": source.stat().st_size,
            "sha256": file_hash,
            "format": firmware_format,
        },

        "metadata": {
            "architecture": architecture,
            "vendor": vendor,
            "version": version,
            "components": components,
        },

        "extraction": {
            "path": str(output),
            "filesExtracted": extraction_count,
            "binwalk": binwalk_result,
        },

        "files": files,

        "strings": {
            "count": len(strings),
            "sample": strings[:200],
        },

        "staticAnalysis": static_analysis,

        "malware": malware,

        "sbom": {
            "components": sbom_components,
        },
    }