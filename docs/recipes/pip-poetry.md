# Recipe: `pip` / `poetry`

Goal: allow Python dependency fetching while keeping egress minimal.

## Start restrictive (PyPI)

```json
{
  "network": {
    "allowedDomains": ["pypi.org", "files.pythonhosted.org"]
  },
  "filesystem": {
    "allowWrite": [".", "/tmp"]
  }
}
```

Run:

```bash
fence --settings ./fence.json pip install -r requirements.txt
```

For Poetry:

```bash
fence --settings ./fence.json poetry install
```

## Iterate with monitor mode

```bash
fence -m --settings ./fence.json poetry install
```

If you use private indexes, add those domains explicitly.
