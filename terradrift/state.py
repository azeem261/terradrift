from __future__ import annotations

import json
import subprocess


def load_state_resources(state_json_path: str | None, terraform_dir: str | None) -> list[dict]:
    """Returns every resource in Terraform state as a flat list of
    {address, type, values} dicts, recursing into child modules.

    Either pass a path to a file already containing `terraform show -json`
    output, or a directory to run that command in directly.
    """
    if state_json_path:
        with open(state_json_path) as f:
            data = json.load(f)
    else:
        result = subprocess.run(
            ["terraform", "show", "-json"],
            cwd=terraform_dir or ".",
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(result.stdout)

    root_module = data.get("values", {}).get("root_module", {})
    return list(_walk_module(root_module))


def _walk_module(module: dict):
    for resource in module.get("resources", []):
        yield {
            "address": resource["address"],
            "type": resource["type"],
            "values": resource.get("values", {}),
        }
    for child in module.get("child_modules", []):
        yield from _walk_module(child)


def resources_of_type(resources: list[dict], resource_type: str) -> list[dict]:
    return [r for r in resources if r["type"] == resource_type]
