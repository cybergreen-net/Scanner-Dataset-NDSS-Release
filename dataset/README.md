# Dataset Release

This directory contains the various datasets that are a part of the release.

1. `dataset.csv` contains 401224 hostname entries mapped to country and respective ISO-A2 (ISO 3611 A2) codes.
2. The datasets in `intermediate/` are the individual datasets merged and extended to obtain the released dataset. They are included here only for reproducibility, and each is licensed as described in their projects. Please refer to the [README](intermediate/README.md) in the intermediate directory for more details.

Dataset size: 16031898 bytes (16.0 MB)
SHA256 Fingerprint: `7e057601cf7214dcf2e976286885a1640ae78d94a8cb5b55a8437f62e7431656`

Verify using:
```shell
$ echo "7e057601cf7214dcf2e976286885a1640ae78d94a8cb5b55a8437f62e7431656 dataset.csv" | sha256sum --check
dataset.csv: OK
```
