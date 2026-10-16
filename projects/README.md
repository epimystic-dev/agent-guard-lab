# projects/

One folder per artifact, named `YYYY-MM-DD_<slug>/`. Each is self-contained: its own
`README.md`, `LICENSE`, `project.json` (with a declared `kind`), tests under `tests/`, and
examples under `examples/`. CI discovers every folder that carries a `tests/` directory; no
workflow edit is needed to add one.
