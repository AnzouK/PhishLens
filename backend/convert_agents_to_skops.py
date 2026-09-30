"""
One-time conversion of the Random Forest agents from joblib (pickle) to
skops, with an optional upload to the Hugging Face model repo.

Run it where the joblib files already load, i.e. inside the running
backend container (same scikit-learn version as production):

    docker exec -it phishlens python convert_agents_to_skops.py            # convert + verify
    docker exec -it phishlens python convert_agents_to_skops.py --upload   # ...and publish

The joblib files are read from ./agents (where the backend downloads
them). Unpickling them here is fine: they are the files the backend
already trusts today. The script then checks that the skops copy gives
exactly the same probabilities as the original on 200 random inputs
before writing or uploading anything.

--upload needs a Hugging Face token with write access to
HF_AGENTS_REPO. It is read from HF_TOKEN or asked interactively; it is
never printed or stored.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

import agent_io

AGENTS = ("url_agent", "metadata_agent")
REPO = os.environ.get("HF_AGENTS_REPO", "AnzouKiona/phishlens-agents")


def probabilities(state: dict, rows: pd.DataFrame) -> np.ndarray:
    X = state["scaler"].transform(rows[state["feature_names"]].values)
    return state["model"].predict_proba(X)


def convert(folder: Path) -> list[Path]:
    rng = np.random.default_rng(0)
    written = []
    for stem in AGENTS:
        src = folder / f"{stem}.joblib"
        dst = folder / f"{stem}.skops"
        if not src.exists():
            print(f"skip {stem}: {src} not found")
            continue
        state = joblib.load(src)
        agent_io.dump_skops_state(state, dst)
        reloaded = agent_io.load_skops_state(dst)

        cols = state["feature_names"]
        rows = pd.DataFrame(rng.integers(0, 4, size=(200, len(cols))), columns=cols).astype(float)
        if not np.allclose(probabilities(state, rows), probabilities(reloaded, rows)):
            dst.unlink()
            sys.exit(f"{stem}: skops copy does not reproduce the original predictions, aborting.")
        print(f"ok   {stem}: {dst} ({dst.stat().st_size // 1024} KB), predictions identical")
        written.append(dst)
    return written


def upload(files: list[Path]) -> None:
    from huggingface_hub import HfApi

    token = os.environ.get("HF_TOKEN") or getpass.getpass("Hugging Face write token: ")
    api = HfApi(token=token)
    for f in files:
        api.upload_file(
            path_or_fileobj=str(f),
            path_in_repo=f.name,
            repo_id=REPO,
            repo_type="model",
            commit_message=f"Add {f.name} (skops format, no pickle)",
        )
        print(f"uploaded {f.name} to https://huggingface.co/{REPO}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--folder", default="agents", type=Path)
    ap.add_argument("--upload", action="store_true", help=f"publish the .skops files to {REPO}")
    args = ap.parse_args()

    files = convert(args.folder)
    if not files:
        sys.exit("Nothing converted.")
    if args.upload:
        upload(files)
    else:
        print("Dry run: add --upload to publish.")


if __name__ == "__main__":
    main()
