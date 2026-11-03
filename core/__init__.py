"""gravyard core — shared CLI, logging, config, input and output helpers.

Every category (crypto, webtest, ...) and every tool inside it reuses these
modules so the whole toolkit behaves like one program:

- core.cli      top-level `gravyard` dispatcher + plugin-style registry
- core.output   tables / JSON output, coloured status lines
- core.logging  stderr logging setup (--verbose)
- core.config   optional TOML config loading
- core.input    shared --text / --file / stdin resolution
"""

__version__ = "0.1.0"
