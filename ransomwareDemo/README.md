# Safe Ransomware Workload Demo

This is a separate demonstration application for the ransomware detection project.

It creates 300 dummy `.bin` files in `demo_files/`, with logarithmically distributed sizes from about 1 KiB to 150 MiB. The simulation performs a reversible XOR transformation in bounded 256 KiB chunks and never targets files outside this directory.

## Run

```fish
python3 -m venv .venv
source .venv/bin/activate.fish
python -m pip install -r requirements.txt
python demo_ui.py
```

Keep this application separate from the main detector GUI.


### UI threading fix
The demo uses Qt signals to update the progress bar from its worker thread safely; the progress signal is separate from the QProgressBar widget.
