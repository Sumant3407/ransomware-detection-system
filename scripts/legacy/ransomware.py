"""Compatibility entry point for the safe lab activity simulator.

This project must never encrypt arbitrary files. Use this module only with a
disposable directory containing a ``.lab-simulation`` marker file.
"""

from labActivitySimulator import main


if __name__ == "__main__":
    main()