"""Tree-sitter parser loading and language helpers."""

from typing import Optional, Any
import logging

logger = logging.getLogger(__name__)

_PARSERS: dict = {}


def get_tree_sitter_parser(language: str) -> Optional[Any]:
    """Retrieve or initialize a tree-sitter parser for a language."""
    if language in _PARSERS:
        return _PARSERS[language]

    try:
        import tree_sitter_language_pack as tslp
        ts_lang = "python" if language == "python" else "javascript" if language in ("javascript", "typescript") else language
        parser = tslp.get_parser(ts_lang)
        _PARSERS[language] = parser
        return parser
    except Exception as e:
        logger.debug(f"Tree-sitter parser initialization failed for {language}: {e}")
        return None
