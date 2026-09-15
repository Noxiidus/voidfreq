# Contributing to VoidFreq

Thanks for your interest in contributing to VoidFreq! This guide will help you get started.

## Setup

```bash
git clone https://github.com/Noxiidus/voidfreq.git
cd voidfreq
pip install -e ".[dev]"
```

## Development Workflow

1. Create a feature branch from `main`
2. Write code following the existing patterns
3. Add tests for new functionality
4. Run lint and tests before committing:

```bash
ruff check voidfreq/ tests/
pytest tests/ -v
```

## Code Style

- Python 3.11+ type hints everywhere
- `ruff` with rules: E, F, W, I, UP, B, SIM
- No comments unless the "why" is non-obvious
- Every module takes `Config` + `OpsecEngine` in its constructor
- All external tools called via `subprocess.run()` — never `shell=True`
- Rich for all terminal output (tables, panels, progress)

## Module Structure

Each module in `voidfreq/modules/` follows this pattern:

```python
from ..core.config import Config
from ..core.logger import get_logger
from ..core.opsec import OpsecEngine

log = get_logger("module_name")

class MyModule:
    def __init__(self, config: Config, opsec: OpsecEngine) -> None:
        self.config = config
        self.opsec = opsec

    def do_something(self, interface: str) -> None:
        self.opsec.pre_operation()
        # ... your code
```

## Testing

- Tests use `unittest.mock.patch` to mock subprocess calls
- No real WiFi hardware needed for tests
- Test file: `tests/test_<module>.py`
- When patching the entire `subprocess` module, patch `subprocess.run` directly if you need to catch `subprocess.TimeoutExpired`

## Pull Requests

- Keep PRs focused on a single feature or fix
- Include tests
- Update the docstring if you add new CLI commands
- Run the full test suite before submitting

## Reporting Issues

- Include your OS and Python version
- Include the output of `voidfreq doctor`
- For bugs, include steps to reproduce and the full error traceback
