from __future__ import annotations

import gzip
import hashlib
import re
import shutil
import struct
import subprocess
import tarfile
import zipfile

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
    ".env",
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
        re.compile(
            r"\bAKIA[0-9A-Z]{16}\b"
        ),
    ),

    (
        "Private Key",
        re.compile(
            r"-----BEGIN "
            r"(?:RSA |EC |OPENSSH )?"
            r"PRIVATE KEY-----"
        ),
    ),

    (
        "Password Assignment",
        re.compile(
            r"(?:password|passwd|pwd)"
            r"\s*[:=]\s*"
            r"[\"']?"
            r"[^\"'\s]{4,}",
            re.IGNORECASE,
        ),
    ),

    (
        "API Key",
        re.compile(
            r"(?:api[_-]?key|secret[_-]?key)"
            r"\s*[:=]\s*"
            r"[\"']?"
            r"[A-Za-z0-9_\-]{12,}",
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


def sha256_file(
    path: Path,
) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as file:
        while True:
            chunk = file.read(
                1024 * 1024
            )

            if not chunk:
                break

            digest.update(chunk)

    return digest.hexdigest()


def extract_ascii_strings(
    data: bytes,
    minimum_length: int = 4,
) -> list[str]:
    sample_data = data[: 64 * 1024 * 1024]
    pattern = re.compile(rb"[ -~]{" + str(minimum_length).encode() + rb",500}")
    return [match.group(0).decode("ascii", errors="ignore") for match in pattern.finditer(sample_data)][:20000]


def detect_format(
    data: bytes,
    filename: str,
) -> str:
    lower = filename.lower()

    if (
        data.startswith(
            b"PK\x03\x04"
        )
        or data.startswith(
            b"PK\x05\x06"
        )
    ):
        return "ZIP"

    if (
        len(data) >= 4
        and struct.unpack(
            "<I",
            data[:4],
        )[0]
        == 0x30524448
    ):
        return "TRX"

    if (
        len(data) >= 4
        and struct.unpack(
            ">I",
            data[:4],
        )[0]
        == 0x27051956
    ):
        return "uImage"

    if data.startswith(
        b"hsqs"
    ):
        return "SquashFS"

    if data.startswith(
        b"cramfs"
    ):
        return "CramFS"

    if data.startswith(
        b"UBI#"
    ):
        return "UBI"

    if lower.endswith(".chk"):
        return "CHK"

    if lower.endswith(".img"):
        return "Disk/Filesystem Image"

    if lower.endswith(".bin"):
        return "Firmware Binary"

    if lower.endswith(".trx"):
        return "TRX"

    if lower.endswith(".gz"):
        return "GZIP"

    if lower.endswith(".tar"):
        return "TAR"

    if lower.endswith(".iso"):
        return "ISO"

    return "Unknown"


def detect_elf_architecture(
    data: bytes,
    offset: int = 0,
) -> str | None:

    if (
        offset + 20
        > len(data)
    ):
        return None

    if (
        data[
            offset:
            offset + 4
        ]
        != b"\x7fELF"
    ):
        return None

    elf_class = data[
        offset + 4
    ]

    endian = data[
        offset + 5
    ]

    if elf_class not in (
        1,
        2,
    ):
        return None

    if endian == 1:
        machine = struct.unpack_from(
            "<H",
            data,
            offset + 18,
        )[0]

    elif endian == 2:
        machine = struct.unpack_from(
            ">H",
            data,
            offset + 18,
        )[0]

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

    return architectures.get(
        machine,
        f"ELF machine 0x{machine:x}",
    )


def detect_architecture(
    data: bytes,
) -> str:

    architecture =detect_elf_architecture(
            data
        )

    if architecture:
        return architecture

    index = data.find(
        b"\x7fELF",
        1,
    )

    while index != -1:
        architecture = detect_elf_architecture(
                data,
                index,
            )

        if architecture:
            return architecture

        index = data.find(
            b"\x7fELF",
            index + 1,
        )

    magic = b"\x27\x05\x19\x56"

    index = data.find(magic)

    if (
        index >= 0
        and index + 30 < len(data)
    ):
        value = data[
            index + 29
        ]

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
            return uimage_arch[
                value
            ]

    return "UNKNOWN"


def detect_vendor(
    text: str,
    filename: str,
) -> str | None:

    haystack = (
        f"{filename}\n{text}"
    ).lower()

    for (
        vendor,
        patterns,
    ) in VENDOR_RULES.items():

        for pattern in patterns:
            if re.search(
                pattern,
                haystack,
                re.IGNORECASE,
            ):
                return vendor

    return None


def detect_version(
    text: str,
) -> str | None:

    patterns = [
        r"\bfirmware[\s_-]?"
        r"(?:version|ver|v)?"
        r"\s*[:=]?\s*v?"
        r"(\d+(?:\.\d+){1,4}"
        r"(?:[-_.][A-Za-z0-9]+)*)",

        r"\bversion\s*[:=]\s*v?"
        r"(\d+(?:\.\d+){1,4}"
        r"(?:[-_.][A-Za-z0-9]+)*)",

        r"\bver(?:sion)?\s*[:=]\s*v?"
        r"(\d+(?:\.\d+){1,4}"
        r"(?:[-_.][A-Za-z0-9]+)*)",

        r"\bv(\d+\.\d+"
        r"(?:\.\d+){0,3})\b",
    ]

    for pattern in patterns:
        match = re.search(
            pattern,
            text,
            re.IGNORECASE,
        )

        if match:
            return match.group(1)

    return None


def detect_components(
    text: str,
    files: list[dict[str, Any]],
) -> list[str]:

    haystack = (
        text
        + "\n"
        + "\n".join(
            item["path"]
            for item in files
        )
    ).lower()

    found: set[str] = set()

    for component in IOT_COMPONENTS:
        if component in haystack:
            found.add(component)

    version_patterns = [
        r"OpenSSL\s+[\d.]+[a-z]?",
        r"BusyBox\s+v?[\d.]+",
        r"OpenSSH[_\s]+[\d.]+[a-z0-9]*",
        r"Dropbear\s+v?[\d.]+",
        r"lighttpd\/[\d.]+",
        r"Apache\/[\d.]+",
        r"dnsmasq-[\d.]+",
    ]

    for pattern in version_patterns:
        matches = re.findall(
            pattern,
            text,
            re.IGNORECASE,
        )
        for val in matches:
            found.add(val.strip())

    return sorted(found)


def safe_extract_zip(
    firmware_path: Path,
    extract_path: Path,
) -> int:

    count = 0

    destination_root = (
        extract_path / "zip"
    ).resolve()

    destination_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    with zipfile.ZipFile(
        firmware_path,
        "r",
    ) as archive:

        for info in archive.infolist():

            name = (
                info.filename
                .replace("\\", "/")
            )

            parts = [
                part
                for part in name.split("/")
                if part
                not in (
                    "",
                    ".",
                    "..",
                )
            ]

            if not parts:
                continue

            safe_name = Path(
                *parts
            )

            destination = (
                destination_root
                / safe_name
            ).resolve()

            if not str(
                destination
            ).startswith(
                str(destination_root)
            ):
                continue

            if info.is_dir():
                destination.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                continue

            destination.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(
                info
            ) as source:

                with destination.open(
                    "wb"
                ) as target:

                    shutil.copyfileobj(
                        source,
                        target,
                    )

            count += 1

    return count


def extract_trx(
    firmware_path: Path,
    extract_path: Path,
) -> int:

    data = firmware_path.read_bytes()

    if len(data) < 28:
        return 0

    if (
        struct.unpack(
            "<I",
            data[:4],
        )[0]
        != 0x30524448
    ):
        return 0

    total_length = struct.unpack(
        "<I",
        data[4:8],
    )[0]

    if (
        total_length <= 0
        or total_length > len(data)
    ):
        total_length = len(data)

    offsets = []

    for position in (
        16,
        20,
        24,
    ):
        offset = struct.unpack(
            "<I",
            data[
                position:
                position + 4
            ],
        )[0]

        if (
            0 < offset < total_length
        ):
            offsets.append(offset)

    offsets = sorted(
        set(offsets)
    )

    count = 0

    for index, start in enumerate(
        offsets
    ):

        end = (
            offsets[index + 1]
            if index + 1 < len(offsets)
            else total_length
        )

        if end <= start:
            continue

        output = (
            extract_path
            / f"trx-part-{count}.bin"
        )

        output.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        output.write_bytes(
            data[start:end]
        )

        count += 1

    return count


def extract_tar(
    firmware_path: Path,
    extract_path: Path,
) -> int:

    count = 0

    destination_root = (
        extract_path / "tar"
    ).resolve()

    destination_root.mkdir(
        parents=True,
        exist_ok=True,
    )

    with tarfile.open(
        firmware_path,
        "r:*",
    ) as archive:

        for member in archive.getmembers():

            if not (
                member.isfile()
                or member.isdir()
            ):
                continue

            parts = [
                part
                for part in member.name.replace(
                    "\\",
                    "/",
                ).split("/")
                if part
                not in (
                    "",
                    ".",
                    "..",
                )
            ]

            if not parts:
                continue

            target = (
                destination_root
                / Path(*parts)
            ).resolve()

            if not str(
                target
            ).startswith(
                str(destination_root)
            ):
                continue

            if member.isdir():
                target.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                continue

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            source = archive.extractfile(
                member
            )

            if source is None:
                continue

            with source, target.open(
                "wb"
            ) as output:

                shutil.copyfileobj(
                    source,
                    output,
                )

            count += 1

    return count


def extract_gzip(
    firmware_path: Path,
    extract_path: Path,
) -> int:

    output = (
        extract_path
        / firmware_path.stem
    )

    with gzip.open(
        firmware_path,
        "rb",
    ) as source:

        with output.open(
            "wb"
        ) as target:

            shutil.copyfileobj(
                source,
                target,
            )

    return 1


def extract_squashfs_partitions(
    firmware_path: Path,
    extract_path: Path,
    modules: list[Any],
) -> int:
    """Extract any SquashFS filesystems found by binwalk's signature
    scan using PySquashfsImage (a pure-Python SquashFS reader).

    binwalk3's built-in extraction shells out to the external
    `sasquatch` tool, which has no Windows build — so on Windows the
    SquashFS root filesystem (where secrets/dangerous functions
    actually live) never gets unpacked even though it's correctly
    *detected*. This works around that by extracting it ourselves,
    with no external binary required.

    Returns the number of files extracted.
    """

    try:
        from PySquashfsImage import SquashFsImage
        from PySquashfsImage.extract import extract_dir
    except ImportError:
        return 0

    extracted_count = 0

    try:
        data = firmware_path.read_bytes()
    except Exception:
        return 0

    for module in modules:
        for res in getattr(module, "results", []) or []:

            module_name = (
                getattr(res, "module", "") or ""
            ).lower()

            description = (
                getattr(res, "description", "") or ""
            ).lower()

            if (
                "squashfs" not in module_name
                and "squashfs" not in description
            ):
                continue

            offset = getattr(res, "offset", None)

            if offset is None:
                continue

            dest = (
                extract_path
                / f"squashfs_{offset:x}"
            )

            try:
                dest.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                chunk = data[offset:]

                with SquashFsImage.from_bytes(
                    chunk
                ) as image:

                    extract_dir(
                        image.root,
                        dest=str(dest),
                        force=True,
                        quiet=True,
                    )

                    for _ in dest.rglob("*"):
                        extracted_count += 1

            except Exception as exc:
                print(
                    "[SquashFS extraction warning]",
                    f"offset={offset:#x}:",
                    exc,
                )

    return extracted_count


def try_binwalk(
    firmware_path: Path,
    extract_path: Path,
) -> dict[str, Any]:

    result = {
        "available": False,
        "success": False,
        "message": "",
    }

    # Preferred path: the `binwalk3` pip package. It bundles the
    # binwalk v3 Rust binary (including a Windows x64 build), so it
    # works via `import binwalk` without needing a separate CLI
    # install or PATH entry — this is what makes it usable from a
    # plain Windows venv.
    try:
        import binwalk as binwalk3  # type: ignore

        result["available"] = True

        modules = binwalk3.scan(
            str(firmware_path),
            signature=True,
            extract=True,
            directory=str(extract_path),
            matryoshka=False,
            quiet=True,
        )

        total_results = sum(
            len(getattr(module, "results", []) or [])
            for module in modules
        )

        all_errors = []
        for module in modules:
            all_errors.extend(
                getattr(module, "errors", []) or []
            )

        result["success"] = True

        squashfs_files = extract_squashfs_partitions(
            firmware_path,
            extract_path,
            modules,
        )

        if squashfs_files:
            result["message"] = (
                f"binwalk3 (python) found "
                f"{total_results} signature(s); "
                f"extracted {squashfs_files} file(s) "
                f"from SquashFS via PySquashfsImage"
            )
            return result

        if all_errors:
            result["message"] = (
                f"binwalk3 (python) found "
                f"{total_results} signature(s); "
                f"errors: {' | '.join(all_errors)[:2000]}"
            )
        else:
            result["message"] = (
                f"binwalk3 (python) found "
                f"{total_results} signature(s)"
            )

        return result

    except ImportError:
        # binwalk3 not installed — fall through and try the
        # system `binwalk` CLI instead.
        pass

    except Exception as exc:
        # binwalk3 was importable but the scan/extract itself
        # failed (e.g. Windows symlink privilege error on
        # extraction). Record it, then still try the CLI as a
        # fallback rather than giving up.
        result["message"] = (
            f"binwalk3 (python) failed: {exc}"
        )

    command = shutil.which(
        "binwalk"
    )

    if not command:
        if not result["message"]:
            result["message"] = (
                "binwalk not found: run "
                "'pip install binwalk3' in this venv, "
                "or install the binwalk CLI and ensure "
                "it is on PATH"
            )

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

        result["success"] = (
            process.returncode == 0
        )

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
            size = (
                file_path.stat()
                .st_size
            )

            relative = (
                "/"
                + file_path.relative_to(
                    extract_path
                ).as_posix()
            )

            file_type = "file"

            lower = (
                file_path.name.lower()
            )

            if lower.endswith(
                (
                    ".bin",
                    ".elf",
                )
            ):
                file_type = "binary"

            if lower.endswith(
                ".so"
            ):
                file_type = (
                    "shared-library"
                )

            if file_path.name in {
                "busybox",
                "httpd",
                "dropbear",
                "telnetd",
            }:
                file_type = "binary"

            try:
                header = file_path.read_bytes()[
                    :4
                ]

                if header == b"\x7fELF":
                    file_type = (
                        "ELF binary"
                    )

            except Exception:
                pass

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
) -> tuple[
    list[dict],
    list[dict],
    list[dict],
]:

    secrets = []
    dangerous = []
    vulnerabilities = []

    try:
        if (
            path.stat().st_size
            > 5 * 1024 * 1024
        ):
            return (
                secrets,
                dangerous,
                vulnerabilities,
            )

        data = path.read_bytes()

        if b"\x00" in data[:10000]:
            return (
                secrets,
                dangerous,
                vulnerabilities,
            )

        text = data.decode(
            "utf-8",
            errors="ignore",
        )

    except Exception:
        return (
            secrets,
            dangerous,
            vulnerabilities,
        )

    for (
        line_number,
        line,
    ) in enumerate(
        text.splitlines(),
        start=1,
    ):

        for (
            secret_type,
            pattern,
        ) in SECRET_PATTERNS:

            if pattern.search(
                line
            ):

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
                        "description":
                            (
                                f"Potentially dangerous "
                                f"function {function} "
                                f"detected."
                            ),
                    }
                )

    return (
        secrets,
        dangerous,
        vulnerabilities,
    )


BINARY_FILE_TYPES = {
    "binary",
    "ELF binary",
    "shared-library",
    "firmware",
}


def analyze_binary_file(
    path: Path,
    relative_path: str,
) -> tuple[
    list[dict],
    list[dict],
]:
    """Scan a compiled/binary file (ELF, .bin, .so, extension-less
    executables like busybox/httpd) by extracting its printable ASCII
    strings and running the same secret/dangerous-function patterns
    against each string, similar to `strings file | grep`."""

    secrets = []
    dangerous = []

    try:
        if (
            path.stat().st_size
            > 25 * 1024 * 1024
        ):
            # cap how much we read for very large binaries
            data = path.read_bytes()[: 25 * 1024 * 1024]
        else:
            data = path.read_bytes()

    except Exception:
        return secrets, dangerous

    strings = extract_ascii_strings(data)

    for (
        line_number,
        line,
    ) in enumerate(strings, start=1):

        for (
            secret_type,
            pattern,
        ) in SECRET_PATTERNS:

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
                        "description":
                            (
                                f"Potentially dangerous "
                                f"function {function} "
                                f"detected."
                            ),
                    }
                )

    return secrets, dangerous


def analyze_files(
    extract_path: Path,
    files: list[dict[str, Any]],
) -> dict[str, Any]:

    secrets = []
    dangerous = []
    vulnerabilities = []

    for item in files:

        relative = item["path"]

        path = (
            extract_path
            / relative.lstrip("/")
        )

        file_type = item.get("type", "file")

        if (
            path.suffix.lower()
            in SUPPORTED_TEXT_EXTENSIONS
        ):
            (
                s,
                d,
                v,
            ) = analyze_text_file(
                path,
                relative,
            )

            vulnerabilities.extend(v)

        elif (
            file_type in BINARY_FILE_TYPES
            or path.suffix == ""
        ):
            # No recognised text extension, but it's an executable /
            # binary blob (ELF, .bin, .so, busybox, etc.) — scan its
            # extracted strings instead of skipping it outright.
            s, d = analyze_binary_file(
                path,
                relative,
            )

        else:
            continue

        secrets.extend(s)
        dangerous.extend(d)

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

        path = (
            extract_path
            / item["path"].lstrip("/")
        )

        try:
            data = path.read_bytes()

            text = data.decode(
                "latin-1",
                errors="ignore",
            ).lower()

            matches = [
                signature
                for signature
                in SUSPICIOUS_STRINGS
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
                        "sha256":
                            hashlib.sha256(
                                data
                            ).hexdigest(),

                        "fileName":
                            path.name,

                        "threatScore":
                            score,

                        "virusTotalResult":
                            result,

                        "isMalicious":
                            result == "malicious",

                        "detectionCount":
                            len(matches),

                        "totalEngines":
                            72,

                        "indicators":
                            matches,
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

        name = Path(
            item["path"]
        ).name.lower()

        matched_component = None

        for component in IOT_COMPONENTS:
            if component in name:
                matched_component = (
                    component
                )
                break

        if not matched_component:
            continue

        version = "unknown"

        match = re.search(
            r"(\d+\.\d+(?:\.\d+)?)",
            name,
        )

        if match:
            version = (
                match.group(1)
            )

        components.append(
            {
                "name":
                    matched_component,

                "version":
                    version,

                "type":
                    item["type"],

                "path":
                    item["path"],

                "source":
                    "python-firmware-scanner",
            }
        )

    unique = {}

    for component in components:
        key = (
            component["name"],
            component["version"],
            component["path"],
        )

        unique[key] = component

    return list(
        unique.values()
    )


def scan_firmware(
    firmware_path: str,
    extract_path: str,
    firmware_id: int,
    scan_id: int,
) -> dict[str, Any]:

    source = Path(
        firmware_path
    ).resolve()

    output = Path(
        extract_path
    ).resolve()

    if not source.exists():
        raise FileNotFoundError(
            f"Firmware file not found: {source}"
        )

    if not source.is_file():
        raise ValueError(
            f"Firmware path is not a file: {source}"
        )

    output.mkdir(
        parents=True,
        exist_ok=True,
    )

    

    data = source.read_bytes()

    file_hash = hashlib.sha256(
        data
    ).hexdigest()

    firmware_format = detect_format(
        data,
        source.name,
    )

    architecture = detect_architecture(
        data
    )

    strings = extract_ascii_strings(
        data
    )

    strings_text = "\n".join(
        strings
    )

    vendor = detect_vendor(
        strings_text,
        source.name,
    )

    version = detect_version(
        strings_text
    )

    extraction_count = 0

    try:

        if firmware_format == "ZIP":

            extraction_count = (
                safe_extract_zip(
                    source,
                    output,
                )
            )

        elif firmware_format == "TRX":

            extraction_count = (
                extract_trx(
                    source,
                    output,
                )
            )

        elif firmware_format == "TAR":

            extraction_count = (
                extract_tar(
                    source,
                    output,
                )
            )

        elif firmware_format == "GZIP":

            extraction_count = (
                extract_gzip(
                    source,
                    output,
                )
            )

    except Exception as exc:

        print(
            "[Extraction warning]",
            exc,
        )

    binwalk_result = try_binwalk(
        source,
        output,
    )


    raw_copy = (
        output / "firmware.bin"
    )

    if not raw_copy.exists():

        shutil.copy2(
            source,
            raw_copy,
        )

    strings_dump = (
        output
        / "_strings_dump.txt"
    )

    strings_dump.write_text(
        strings_text,
        encoding="utf-8",
        errors="ignore",
    )


    files = collect_files(
        output
    )

    if not files:

        files = [
            {
                "path":
                    "/firmware.bin",

                "type":
                    "firmware",

                "size":
                    source.stat().st_size,

                "permissions":
                    None,

                "isSuspicious":
                    False,
            }
        ]


    detected_components = (
        detect_components(
            strings_text,
            files,
        )
    )

    sbom_components = (
        generate_components(
            files
        )
    )


    static_analysis = (
        analyze_files(
            output,
            files,
        )
    )

    malware = (
        scan_malware_indicators(
            output,
            files,
        )
    )

    return {
        "scanId":
            scan_id,

        "firmwareId":
            firmware_id,

        "status":
            "completed",

        "firmware": {
            "name":
                source.name,

            "size":
                source.stat().st_size,

            "sha256":
                file_hash,

            "format":
                firmware_format,
        },

        "metadata": {
            "architecture":
                architecture,

            "vendor":
                vendor,

            "version":
                version,

            "components":
                detected_components,
        },

        "extraction": {
            "path":
                str(output),

            "filesExtracted":
                extraction_count,

            "binwalk":
                binwalk_result,
        },

        "files":
            files,

        "strings": {
            "count":
                len(strings),

            "sample":
                strings[:200],
        },

        "staticAnalysis":
            static_analysis,

        "malware":
            malware,

        "sbom": {
            "components":
                sbom_components,
        },
    }