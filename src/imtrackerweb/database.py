"""Database - Read and write json files."""

# Programmed by CoolCat467

__title__ = "Database"
__author__ = "CoolCat467"

import json
from collections.abc import Generator, Iterable, Iterator
from os import makedirs, path
from pathlib import Path
from typing import Any

_LOADED: dict[str, "Records"] = {}


class Database(dict[str, Any]):
    """Database dict with file read write functions."""

    __slots__ = ("__weakref__", "file")

    def __init__(self, file_path: str | Path) -> None:
        """Initialize and set file path."""
        super().__init__()
        self.file = file_path

        if path.exists(self.file):
            self.reload_file()

    def reload_file(self) -> None:
        """Reload database file."""
        with open(self.file, "rb") as file:
            self.update(json.load(file))

    def write_file(self) -> None:
        """Write database file."""
        folder = path.dirname(self.file)
        if not path.exists(folder):
            makedirs(folder, exist_ok=True)
        with open(self.file, "w", encoding="utf-8") as file:
            json.dump(self, file, separators=(",", ":"))


class Table:
    """Table from dictionary.

    Allows getting and setting entire columns of a database
    """

    __slots__ = ("_key_name", "_records")

    def __init__(self, records: dict[str, Any], key_name: str) -> None:
        """Initialize and set records and key name."""
        self._records = records
        self._key_name = key_name

    def __repr__(self) -> str:
        """Get text representation of table."""
        size: dict[str, int] = {}
        columns = self.keys()
        for column in columns:
            size[column] = len(column)
            for value in self[column]:
                if value is None:
                    continue
                length = (
                    len(value)
                    if hasattr(value, "__len__")
                    else len(repr(value))
                )
                size[column] = max(size[column], length)
        num_pad = len(str(len(self)))
        lines = []
        column_names = " ".join(c.ljust(length) for c, length in size.items())
        lines.append("".rjust(num_pad) + " " + column_names)
        for index in range(len(self)):
            line = [str(index).ljust(num_pad)]
            for column in columns:
                line.append(str(self[column][index]).ljust(size[column]))
            lines.append(" ".join(line))
        return "\n".join(lines)

    def __getitem__(self, column: str) -> tuple[Any, ...]:
        """Get column data."""
        if column not in self.keys():
            return tuple(None for _ in range(len(self)))
        if column == self._key_name:
            return tuple(self._records.keys())
        return tuple([row.get(column) for row in self._records.values()])

    def __setitem__(self, column: str, value: Iterable[Any]) -> None:
        """Set column data to value."""
        if column == self._key_name:
            raise ValueError("column is key type")
        for key, set_value in zip(self._records, value, strict=True):
            if set_value is None:
                continue
            self._records[key][column] = set_value

    def keys(self) -> set[str]:
        """Return the name of every column."""
        keys = {self._key_name}
        for row in self._records.values():
            keys |= set(row.keys())
        return keys

    def __iter__(self) -> Iterator[str]:
        """Return iterator for column names."""
        return iter(self.keys())

    def values(self) -> tuple[Any, ...]:
        """Return every column."""
        values = []
        for key in self.keys():
            values.append(self[key])
        return tuple(values)

    def items(self) -> tuple[tuple[str, Any], ...]:
        """Return tuples of column names and columns."""
        items = []
        for key in self.keys():
            items.append((key, self[key]))
        return tuple(items)

    def column_and_rows(self) -> Generator[tuple[str | Any, ...], None, None]:
        """Yield tuple of column row and then rows in column order."""
        columns = tuple(self.keys() - {self._key_name})
        yield (self._key_name, *columns)
        for key, value in self._records.items():
            yield (key, *tuple(value.get(col) for col in columns))

    def rows(self) -> Generator[tuple[Any, ...], None, None]:
        """Yield each row."""
        gen = self.column_and_rows()
        _ = next(gen)
        yield from gen

    def __len__(self) -> int:
        """Return number of records."""
        return len(self._records)


class Records(Database):
    """Records dict with columns."""

    __slots__ = ()

    def table(self, element_name: str) -> Table:
        """Get table object given that keys are named element name."""
        return Table(self, element_name)


def load(file_path: str | Path) -> Records:
    """Load database from file path or return already loaded instance."""
    file = path.abspath(file_path)
    if file not in _LOADED:
        _LOADED[file] = Records(file)
    return _LOADED[file]


def get_loaded() -> set[str]:
    """Return set of loaded database files."""
    return set(_LOADED)


def unload(file_path: str | Path) -> None:
    """If database loaded, write file and unload."""
    file = path.abspath(file_path)
    if file not in get_loaded():
        return
    database = load(file)
    database.write_file()
    del _LOADED[file]


def unload_all() -> None:
    """Unload all loaded databases."""
    for file_path in get_loaded():
        unload(file_path)
