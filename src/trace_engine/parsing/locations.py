"""Source code location representation."""

from pydantic import BaseModel


class SourceLocation(BaseModel):
    """Precise coordinates within a source file."""
    file: str
    line_start: int
    line_end: int
    column_start: int = 0
    column_end: int = 0

    def __str__(self) -> str:
        if self.line_start == self.line_end:
            return f"{self.file}:{self.line_start}"
        return f"{self.file}:{self.line_start}-{self.line_end}"
