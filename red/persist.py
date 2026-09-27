"""Model and result persistence using pickle + zip compression."""

import io
import os
import sys
import json
import types
import pickle
import zipfile
import logging

logger = logging.getLogger(__name__)

_ONEDAL_CLEANED = False

def _install_stubs():
    """Stub out optional accelerator packages so pickled models load anywhere."""
    global _ONEDAL_CLEANED
    if _ONEDAL_CLEANED:
        return

    class _AutoStub(types.ModuleType):
        def __getattr__(self, name):
            full = self.__name__ + "." + name
            if full not in sys.modules:
                child = _AutoStub(full)
                sys.modules[full] = child
                setattr(self, name, child)
            return sys.modules[full]
        def __call__(self, *a, **kw):
            return None

    for pkg in ["onedal", "sklearnex", "cuml", "cuml.svm"]:
        if pkg not in sys.modules:
            sys.modules[pkg] = _AutoStub(pkg)

    _ONEDAL_CLEANED = True


class _PortableUnpickler(pickle.Unpickler):
    """Remap sklearnex/onedal/cuml classes to plain sklearn equivalents."""

    def find_class(self, module, name):
        if "sklearnex" in module and name == "SVC":
            import sklearn.svm._classes
            return sklearn.svm._classes.SVC
        if "onedal" in module or "cuml" in module:
            # return a harmless stub class
            class _Stub:
                def __init__(self, *a, **kw): pass
                def __setstate__(self, s):
                    if isinstance(s, dict):
                        self.__dict__.update(s)
                def __call__(self, *a, **kw): return None
                def __getattr__(self, n): return None
            return _Stub
        return super().find_class(module, name)


def _clean_onedal(obj, visited=None):
    """Remove onedal internal attributes from sklearn SVC objects."""
    if visited is None:
        visited = set()
    oid = id(obj)
    if oid in visited:
        return
    visited.add(oid)

    _ONEDAL_ATTRS = ("_onedal_estimator", "_onedal_params", "_daal_model",
                     "_onedal_model", "_onedal_estimator_")

    target = None
    if isinstance(obj, dict):
        target = obj.values()
    elif hasattr(obj, "__dict__") and not isinstance(obj.__dict__, types.MappingProxyType):
        # strip onedal attrs from SVC-like objects
        for attr in _ONEDAL_ATTRS:
            obj.__dict__.pop(attr, None)
        if "dual_coef_" in obj.__dict__ and "_dual_coef_" not in obj.__dict__:
            obj._dual_coef_ = obj.__dict__.pop("dual_coef_")
        target = obj.__dict__.values()

    if target:
        for v in list(target):
            if v is None or isinstance(v, (str, int, float, bool, bytes)):
                continue
            if isinstance(v, (list, tuple)):
                for item in v:
                    _clean_onedal(item, visited)
            else:
                _clean_onedal(v, visited)


def save_result(obj, name: str, output_dir: str, info: dict = None):
    os.makedirs(output_dir, exist_ok=True)
    zip_path = os.path.join(output_dir, f"{name}.zip")
    pkl_name = f"{name}.pkl"
    data = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(pkl_name, data)
    logger.info("Saved result to %s", zip_path)
    if info is not None:
        info_path = os.path.join(output_dir, f"{name}_info.json")
        with open(info_path, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2, default=_json_default)
        logger.info("Saved info to %s", info_path)


def load_result(path: str):
    _install_stubs()
    with zipfile.ZipFile(path, "r") as zf:
        names = zf.namelist()
        pkl_name = [n for n in names if n.endswith(".pkl")]
        if not pkl_name:
            raise ValueError(f"No .pkl file found in {path}")
        data = zf.read(pkl_name[0])
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        obj = _PortableUnpickler(io.BytesIO(data)).load()
    _clean_onedal(obj)
    logger.info("Loaded result from %s", path)
    return obj


def _json_default(obj):
    import numpy as np
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return float(obj)
    if isinstance(obj, np.ndarray):
        return obj.tolist()
    return str(obj)
