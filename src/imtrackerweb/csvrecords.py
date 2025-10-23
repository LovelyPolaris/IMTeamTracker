"""CSV Records - Read and write CSV files."""

# Programmed by CoolCat467

__title__ = "CSV Records"
__author__ = "CoolCat467"
__version__ = "0.0.0"


import csv
from os import makedirs, path
from pathlib import Path

import trio

from imtrackerweb.database import Table

_LOADED: dict[str, "CSVRecords"] = {}


def _escape(raw_value: object) -> str:
    """Escape CSV value.

    Escape CSV value as per RFC-4180
    """
    value = raw_value if isinstance(raw_value, str) else repr(raw_value)

    need_quotes = False
    if '"' in value:
        need_quotes = True
        value = value.replace('"', '""')
    else:
        for char in value:
            if char in {",", "\n", "\r"}:
                need_quotes = True
                break
    if need_quotes:
        value = f'"{value}"'
    return value


class CSVRecords(dict[str, dict[str, str | int]]):
    """Records dict with CSV file read write functions."""

    __slots__ = ("__weakref__", "_lock", "file", "key_name")

    def __init__(
        self,
        file_path: str | Path | trio.Path,
        key_name: str,
        lock: trio.StrictFIFOLock,
    ) -> None:
        """Initialize file path, key name, file lock, and load file."""
        super().__init__()
        self.file = file_path
        self.key_name = key_name
        self._lock = lock

        if path.exists(self.file):
            self.reload_file()

    def reload_file(self) -> None:
        """Reload database file."""
        with open(self.file, encoding="utf-8") as csv_file:
            reader = csv.reader(csv_file, dialect="unix")
            self.key_name, *keys = next(reader)
            for row in reader:
                entry: dict[str, str | int] = {}
                entry_name, *values = row
                for key, value in zip(keys, values, strict=True):
                    if value.isdecimal():
                        try:
                            entry[key] = int(value)
                            continue
                        except ValueError:
                            pass
                    entry[key] = value
                self[entry_name] = entry

    def sync_write_file(self) -> None:
        """Write database file synchronously (avoid if possible)."""
        folder = Path(path.dirname(self.file))
        if not folder.exists():
            makedirs(folder, exist_ok=True)
        with open(self.file, encoding="utf-8") as csv_file:
            writer = csv.writer(csv_file, dialect="unix")
            table = Table(self, self.key_name)
            writer.writerows(table.column_and_rows())

    async def async_write_file(self) -> None:
        """Write database file asynchronously."""
        folder = trio.Path(path.dirname(self.file))
        if not await folder.exists():
            makedirs(folder, exist_ok=True)
        async with self._lock:
            table = Table(self, self.key_name)
            async with await trio.open_file(
                self.file,
                "w",
                encoding="utf-8",
            ) as file:
                for row in table.column_and_rows():
                    for idx, value in enumerate(row):
                        if idx:  # If not first value, add comma
                            await file.write(",")
                        await file.write(_escape(value))
                    await file.write("\n")


def load(
    file_path: str | Path | trio.Path,
    key_name: str | None = None,
) -> CSVRecords:
    """Load database from file path or return already loaded instance.

    If key name is none, read key name from the file
    """
    file = path.abspath(file_path)
    if file not in _LOADED:
        if key_name is None:
            key_name = ""
        lock = trio.StrictFIFOLock()
        _LOADED[file] = CSVRecords(file, key_name, lock)
    return _LOADED[file]


def get_loaded() -> set[str]:
    """Return set of loaded database files."""
    return set(_LOADED)


async def unload(file_path: str | Path | trio.Path) -> None:
    """If database loaded, write file and unload."""
    file = path.abspath(file_path)
    if file not in get_loaded():
        return
    # must be loaded then so None is fine
    database = load(file, None)
    await database.async_write_file()
    del _LOADED[file]


async def unload_all() -> None:
    """Unload all loaded databases."""
    async with trio.open_nursery() as nursery:
        for file_path in get_loaded():
            nursery.start_soon(
                unload,
                file_path,
                name=f"csv_unload_{file_path}",
            )


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
