"""The checks. Each one looks at one aspect of a message and returns what it found."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Options:
    # The name your own mail server uses in Authentication-Results, such as "mx.google.com".
    # When set, results from any other server are ignored.
    trusted_server: Optional[str] = None
    # Domains to watch for imitations of, besides the built-in brands: usually your own organisation's.
    protected: Tuple[str, ...] = ()
