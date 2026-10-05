# Contributing

## Development

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip -r requirements.txt
python -m unittest discover -s tests -v
```

## Pull requests

Keep changes focused, add or update tests for behavior changes, and do not add functionality that stores submitted credentials or request bodies from honeypot interactions.

## Release model

Releases are tag-driven. The repository does not create version tags automatically. Push a semantic version tag such as `v0.5.0` to trigger the Docker Hub publish workflow.
