#!/usr/bin/env python3
"""
embed_class_names.py — Bake class names into a LightGBM model file.

Run this once after training. The firewall will then read class names directly
from the model — no FW_CLASS_NAMES env var needed.

Usage:
    # If your training script used a LabelEncoder, pass the encoder pickle:
    python firewall/embed_class_names.py --encoder path/to/label_encoder.pkl

    # Or pass class names explicitly (must be in the same order as training labels):
    python firewall/embed_class_names.py --names "Benign,DoS,Reconnaissance,MQTT_Flood,Mirai"

    # Optionally specify a different model file:
    python firewall/embed_class_names.py --encoder le.pkl --model firewall/lightgbm_model.txt

How to find the right order:
    During training you likely did one of:
        le = LabelEncoder(); le.fit(df["Label"])
        # → le.classes_ is the ordered list, save it:
        joblib.dump(le, "label_encoder.pkl")

    Or with pandas:
        df["Label"] = df["Label"].astype("category")
        # → df["Label"].cat.categories gives the order

    The order must match exactly what was passed to lgb.Dataset as labels.
"""

import argparse
import sys
from pathlib import Path

import lightgbm as lgb


REPO_ROOT   = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = Path(__file__).resolve().parent / "lightgbm_model.txt"


def main() -> None:
    parser = argparse.ArgumentParser(description="Embed class names into LightGBM model metadata")
    src = parser.add_mutually_exclusive_group(required=True)
    src.add_argument("--encoder", help="Path to a joblib-saved sklearn LabelEncoder pickle")
    src.add_argument("--names",   help='Comma-separated class names in training label order, e.g. "Benign,DoS,Flood"')
    parser.add_argument("--model", default=str(DEFAULT_MODEL), help=f"Model file to update (default: {DEFAULT_MODEL})")
    args = parser.parse_args()

    model_path = Path(args.model)
    if not model_path.exists():
        print(f"Error: model file not found: {model_path}", file=sys.stderr)
        sys.exit(1)

    # Resolve class names
    if args.encoder:
        try:
            import joblib
        except ImportError:
            print("Error: joblib is required to load an encoder pickle (pip install joblib)", file=sys.stderr)
            sys.exit(1)
        enc = joblib.load(args.encoder)
        if not hasattr(enc, "classes_"):
            print("Error: the loaded object does not have a .classes_ attribute — is it a LabelEncoder?", file=sys.stderr)
            sys.exit(1)
        class_names: list[str] = [str(c) for c in enc.classes_]
    else:
        class_names = [c.strip() for c in args.names.split(",") if c.strip()]

    if not class_names:
        print("Error: class name list is empty.", file=sys.stderr)
        sys.exit(1)

    # Load model, embed names, save back
    model = lgb.Booster(model_file=str(model_path))
    n_model_classes = model.num_class()

    if len(class_names) != n_model_classes:
        print(
            f"Error: {len(class_names)} class names provided but model has "
            f"{n_model_classes} classes. They must match exactly.",
            file=sys.stderr,
        )
        print(f"  Provided : {class_names}", file=sys.stderr)
        sys.exit(1)

    model.set_attr(class_names=",".join(class_names))
    model.save_model(str(model_path))

    print(f"Saved {len(class_names)} class names into {model_path}:")
    for i, name in enumerate(class_names):
        print(f"  [{i}] {name}")
    print("\nThe firewall will now read class names directly from the model.")
    print('Verify with: python -c "import lightgbm as lgb; m=lgb.Booster(model_file=\'firewall/lightgbm_model.txt\'); print(m.attr(\'class_names\'))"')


if __name__ == "__main__":
    main()
