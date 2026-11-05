# Project instructions

This is an independent native Windows x86-64 port project. The current code provides a host scaffold, offline input inspection, verified segment preparation, offline linking, and ARM64 analysis; do not describe it as a working game port.

- Keep code, documentation, and commit messages in English.
- Keep changes focused and verify behavior before reporting success.
- Keep game files, keys, extracted content, generated game code, and compiled output out of Git.
- Put build output under `build/` and generated game output under `generated/`.
- Implement project code independently. Any future imported third-party code must retain its applicable license and notices.
- Run the native host self-test when changing host code.
- Run `python -B -m unittest discover -s tests -v` when changing input inspection. Test fixtures must be synthetic.
- Build the local ZBIC helper before running segment integration tests. Keep its external dependency under ignored `toolchain/`, with its license intact.
- Linking works on private images and must not execute guest code or invent addresses for unresolved strong symbols. Keep linked images and reports under ignored `build/`.
- Install `tools/requirements-analysis.txt` in the project environment for ARM64 integration tests. Decoder success is not semantic lifter support, and unvisited text must not be called proven data.
