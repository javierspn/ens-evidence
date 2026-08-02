"""ens-evidence — ENS (RD 311/2022) evidence from open-source security scanners.

Evidence for an auditor, never a verdict. See DESIGN.md for the why and
.specify/memory/constitution.md for the non-negotiables.

The mapping tables and the report template ship INSIDE this package rather than at
the repository root: the tool cannot produce evidence without them, so an installed
copy must carry them. They stay plain YAML and Jinja under version control —
reviewable and diffable — which is what "mapping and severity are data files, not
code" actually asks for. Where they live is declared once, here.
"""

from pathlib import Path

__version__ = "1.0.0"

PACKAGE_DIR = Path(__file__).resolve().parent
MAPPING_DIR = PACKAGE_DIR / "mapping"
TEMPLATE_DIR = PACKAGE_DIR / "templates"

# Our census language name -> the upstream rules directory that covers it. Lives here and
# not in run.py because the renderer needs it too — run.py imports render, so the arrow
# cannot point back — and two copies would let the coverage table disagree with itself.
RULE_DIR_ALIASES = {"shell": "bash"}
