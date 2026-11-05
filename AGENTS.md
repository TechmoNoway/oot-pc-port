# Project instructions

This is an independent native Windows x86-64 port project. The current code provides a host scaffold and an offline input inspector; do not describe it as a working game port.

- Keep code, documentation, and commit messages in English.
- Keep changes focused and verify behavior before reporting success.
- Keep game files, keys, extracted content, generated game code, and compiled output out of Git.
- Put build output under `build/` and generated game output under `generated/`.
- Implement project code independently. Any future imported third-party code must retain its applicable license and notices.
- Run the native host self-test when changing host code.
- Run `python -B -m unittest discover -s tests -v` when changing input inspection. Test fixtures must be synthetic.
