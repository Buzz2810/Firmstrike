from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from scanner import scan_firmware


app = FastAPI(
    title="FirmStrike Python Scanner",
    version="1.0.0",
)


class ScanRequest(BaseModel):
    firmwareId: int
    scanId: int
    filePath: str
    extractPath: str


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "firmstrike-python-scanner",
    }


@app.post("/scan")
def scan(request: ScanRequest) -> dict[str, Any]:
    """
    Run the Python firmware scanner.

    The Node backend sends absolute Windows paths.
    """

    firmware_path = Path(
        request.filePath
    ).resolve()

    extract_path = Path(
        request.extractPath
    ).resolve()

    print("")
    print("=" * 60)
    print("           PYTHON FIRMWARE SCANNER")
    print("=" * 60)
    print("Firmware ID :", request.firmwareId)
    print("Scan ID     :", request.scanId)
    print("Firmware    :", firmware_path)
    print("Extract     :", extract_path)
    print("=" * 60)
    print("")

    if not firmware_path.exists():
        raise HTTPException(
            status_code=404,
            detail=(
                f"Firmware file not found: "
                f"{firmware_path}"
            ),
        )

    if not firmware_path.is_file():
        raise HTTPException(
            status_code=400,
            detail=(
                f"Firmware path is not a file: "
                f"{firmware_path}"
            ),
        )

    try:
        extract_path.mkdir(
            parents=True,
            exist_ok=True,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=(
                f"Could not create extraction "
                f"directory: {exc}"
            ),
        ) from exc

    try:
        result = scan_firmware(
            firmware_path=str(
                firmware_path
            ),
            extract_path=str(
                extract_path
            ),
            firmware_id=request.firmwareId,
            scan_id=request.scanId,
        )

        print("")
        print("=" * 60)
        print("           PYTHON SCAN COMPLETE")
        print("=" * 60)
        print(
            "Architecture :",
            result["metadata"][
                "architecture"
            ],
        )
        print(
            "Vendor       :",
            result["metadata"][
                "vendor"
            ],
        )
        print(
            "Version      :",
            result["metadata"][
                "version"
            ],
        )
        print(
            "Files        :",
            len(result["files"]),
        )
        print(
            "Secrets      :",
            len(
                result["staticAnalysis"][
                    "secrets"
                ]
            ),
        )
        print(
            "Dangerous    :",
            len(
                result["staticAnalysis"][
                    "dangerous"
                ]
            ),
        )
        print(
            "Malware      :",
            len(result["malware"]),
        )
        print("=" * 60)
        print("")

        return result

    except FileNotFoundError as exc:
        raise HTTPException(
            status_code=404,
            detail=str(exc),
        ) from exc

    except Exception as exc:
        print(
            "[Python Scanner Error]",
            repr(exc),
        )

        raise HTTPException(
            status_code=500,
            detail=(
                f"Python scanner failed: "
                f"{exc}"
            ),
        ) from exc