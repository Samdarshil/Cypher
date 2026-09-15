"""Minimal pytest-compatible shim so tests written against pytest's API
can run with only the stdlib, in environments without network access to
install real pytest. Not a full pytest reimplementation -- just enough
for fixtures via tmp_path and pytest.raises used in this test suite.
"""
import contextlib
import functools
import inspect
import shutil
import sys
import tempfile
import traceback
from pathlib import Path


class _RaisesContext:
    def __init__(self, exc_type):
        self.exc_type = exc_type

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            raise AssertionError(f"Expected {self.exc_type} to be raised, nothing was raised")
        if not issubclass(exc_type, self.exc_type):
            return False
        return True


class _Pytest:
    @staticmethod
    def raises(exc_type):
        return _RaisesContext(exc_type)

    @staticmethod
    def fixture(func):
        func._is_fixture = True
        return func


sys.modules["pytest"] = _Pytest()
pytest = _Pytest()


def _make_tmp_path():
    d = tempfile.mkdtemp(prefix="cypher_test_")
    return Path(d)


def run_module(modpath):
    import importlib.util

    spec = importlib.util.spec_from_file_location(modpath.stem, modpath)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    fixtures = {}
    for name, obj in vars(mod).items():
        if callable(obj) and getattr(obj, "_is_fixture", False):
            fixtures[name] = obj

    test_funcs = [
        (name, obj)
        for name, obj in vars(mod).items()
        if name.startswith("test_") and callable(obj)
    ]

    passed, failed = 0, 0
    for name, func in test_funcs:
        sig = inspect.signature(func)
        kwargs = {}
        cleanup_dirs = []
        try:
            for pname in sig.parameters:
                if pname == "tmp_path":
                    tp = _make_tmp_path()
                    cleanup_dirs.append(tp)
                    kwargs[pname] = tp
                elif pname in fixtures:
                    # our only fixture (workspace) itself needs tmp_path
                    fsig = inspect.signature(fixtures[pname])
                    fkwargs = {}
                    if "tmp_path" in fsig.parameters:
                        tp = _make_tmp_path()
                        cleanup_dirs.append(tp)
                        fkwargs["tmp_path"] = tp
                    kwargs[pname] = fixtures[pname](**fkwargs)
            func(**kwargs)
            print(f"  PASS  {modpath.name}::{name}")
            passed += 1
        except Exception:
            print(f"  FAIL  {modpath.name}::{name}")
            traceback.print_exc()
            failed += 1
        finally:
            for d in cleanup_dirs:
                shutil.rmtree(d, ignore_errors=True)
    return passed, failed


if __name__ == "__main__":
    test_dir = Path(__file__).parent
    total_pass, total_fail = 0, 0
    for f in sorted(test_dir.glob("test_*.py")):
        p, fl = run_module(f)
        total_pass += p
        total_fail += fl
    print(f"\n{total_pass} passed, {total_fail} failed")
    sys.exit(1 if total_fail else 0)
