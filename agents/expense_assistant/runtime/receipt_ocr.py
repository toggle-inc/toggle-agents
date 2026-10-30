"""Local receipt OCR only. Extracted text is untrusted DATA, never instructions.

This adapter neither fetches attachments nor calls a provider, model or finance
API. Its output is not a verified expense, company policy or write approval.
Pillow and the dedicated system Tesseract/language packages are deployment
prerequisites. Importing this module does not start processes or load images.
"""

import io
import math
import os
from pathlib import Path
import selectors
import subprocess
import tempfile
import time

from .state import ExpenseError

MAX_INPUT = 10 * 1024 * 1024
MAX_PIXELS = 16_000_000
MAX_DIMENSION = 10_000
MAX_OUTPUT = 64 * 1024
EXECUTABLES = frozenset({"/usr/bin/tesseract", "/usr/local/bin/tesseract", "/opt/homebrew/bin/tesseract"})
LANGUAGES = frozenset({"jpn+eng", "jpn", "eng"})
FORMATS = {"image/png": "PNG", "image/jpeg": "JPEG"}


class ReceiptOCR:
    """Trusted composition API: read(bytes, MIME) -> text/engine/language.

    executable/language are fixed allowlisted deployment inputs, not environment
    command strings or tool arguments. No shell, inherited secrets, Tesseract
    config files, URL inputs or per-request CLI flags are supported.
    """

    def __init__(self, *, language="jpn+eng", timeout=15, executable="/usr/bin/tesseract"):
        if (not isinstance(language, str) or language not in LANGUAGES
                or not isinstance(executable, str) or executable not in EXECUTABLES
                or type(timeout) not in (int, float) or not math.isfinite(timeout)
                or not 0 < timeout <= 30):
            raise ValueError("Explicit bounded local receipt OCR configuration required")
        self.language, self.timeout, self.executable = language, timeout, executable

    @staticmethod
    def _normalize(content, content_type, path):
        from PIL import Image, ImageOps

        def check(image):
            width, height = image.size
            if (image.format != FORMATS[content_type] or getattr(image, "n_frames", 1) != 1
                    or not 0 < width <= MAX_DIMENSION or not 0 < height <= MAX_DIMENSION
                    or width * height > MAX_PIXELS):
                raise ValueError("unsupported raster")

        # Header/CRC verification is not a decode. Reopen and load all pixels
        # before passing a metadata-free normalized raster to Leptonica.
        with Image.open(io.BytesIO(content), formats=[FORMATS[content_type]]) as image:
            check(image)
            image.verify()
        with Image.open(io.BytesIO(content), formats=[FORMATS[content_type]]) as image:
            check(image)
            image.load()
            with ImageOps.exif_transpose(image) as oriented:
                with oriented.convert("L") as gray:
                    if "A" in oriented.getbands() or "transparency" in oriented.info:
                        with oriented.convert("RGBA") as rgba, rgba.getchannel("A") as alpha:
                            with Image.new("L", gray.size, 255) as white:
                                with Image.composite(gray, white, alpha) as flattened:
                                    ReceiptOCR._save_raster(flattened, path)
                    else:
                        ReceiptOCR._save_raster(gray, path)

    @staticmethod
    def _save_raster(image, path):
        # Private directory plus O_EXCL and 0600; never use the receipt's name.
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as output:
            # Grayscale PGM is at most MAX_PIXELS + a tiny fixed header. It
            # strips EXIF, PNG text/config metadata and compressed payloads.
            image.save(output, format="PPM")

    def _recognize(self, image_path, directory):
        deadline = time.monotonic() + self.timeout
        process = None
        try:
            process = subprocess.Popen(
                [self.executable, str(image_path), "stdout", "-l", self.language, "--psm", "6"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                shell=False, close_fds=True, cwd=directory,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                     "TMPDIR": directory, "OMP_THREAD_LIMIT": "1"},
            )
            result = bytearray()
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0 or not selector.select(remaining):
                        raise TimeoutError
                    chunk = os.read(process.stdout.fileno(), min(4096, MAX_OUTPUT - len(result) + 1))
                    if not chunk:
                        break
                    if len(chunk) > MAX_OUTPUT - len(result):
                        raise ValueError("OCR output limit exceeded")
                    result.extend(chunk)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or process.wait(timeout=remaining) != 0:
                raise ValueError("OCR failed")
            text = result.decode("utf-8", errors="strict").strip()
            if not text or any(ord(c) < 32 and c not in "\n\r\t" or ord(c) == 127 for c in text):
                raise ValueError("OCR text unavailable")
            return text
        finally:
            if process is not None:
                try:
                    if process.poll() is None:
                        process.kill()
                    process.wait(timeout=1)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                finally:
                    if process.stdout is not None:
                        process.stdout.close()

    def read(self, content: bytes, content_type: str) -> dict:
        if (not isinstance(content, bytes) or not 0 < len(content) <= MAX_INPUT
                or not isinstance(content_type, str) or content_type not in FORMATS):
            raise ExpenseError("OCRは10MiB以下のPNG/JPEG画像だけに対応しています。PDF/HEICは未対応です。")
        try:
            with tempfile.TemporaryDirectory(prefix="expense-receipt-ocr-") as directory:
                image_path = Path(directory) / "input.pgm"
                self._normalize(content, content_type, image_path)
                text = self._recognize(image_path, directory)
            return {"text": text, "engine": "tesseract", "language": self.language}
        except Exception:
            # No stdout/stderr, receipt contents, temporary paths or inherited
            # process errors may become public diagnostics.
            raise ExpenseError("画像の文字を安全に読み取れませんでした。画像・OCRの対応形式と設定を確認してください。") from None
