from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from podsquire.__main__ import _load_config, _load_vault_config
from podsquire.vault_secrets import VaultOutputMode


def write_config(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "podsquire.yml"
    path.write_text(yaml.safe_dump(data), encoding="utf-8")
    return path


def test_load_config_merges_enabled_proxy_presets(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "proxy_presets": {
                "vault": {
                    "mode": "http",
                    "local_port": 8200,
                    "remote_host": "vault.example.svc.cluster.local",
                    "remote_port": 8200,
                }
            },
            "enabled_proxy_presets": ["vault"],
        },
    )

    config = _load_config(str(path))

    assert "proxy_presets" not in config
    assert config["proxies"] == [
        {
            "name": "vault",
            "mode": "http",
            "local_port": 8200,
            "remote_host": "vault.example.svc.cluster.local",
            "remote_port": 8200,
        }
    ]


def test_explicit_proxy_overrides_enabled_preset(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "proxy_presets": {
                "vault": {
                    "mode": "http",
                    "local_port": 8200,
                    "remote_host": "vault.example.svc.cluster.local",
                    "remote_port": 8200,
                }
            },
            "enabled_proxy_presets": ["vault"],
            "proxies": [
                {
                    "name": "vault",
                    "mode": "http",
                    "local_port": 18200,
                    "remote_host": "override.example.svc.cluster.local",
                    "remote_port": 8200,
                }
            ],
        },
    )

    config = _load_config(str(path))

    assert len(config["proxies"]) == 1
    assert config["proxies"][0]["local_port"] == 18200
    assert config["proxies"][0]["remote_host"] == "override.example.svc.cluster.local"


def test_unknown_enabled_proxy_preset_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, {"proxy_presets": {}, "enabled_proxy_presets": ["missing"]})

    with pytest.raises(ValueError, match="Unknown enabled_proxy_presets"):
        _load_config(str(path))


def test_vault_config_uses_public_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_ROLE", raising=False)

    cfg = _load_vault_config({"kv_path": "apps/example", "output_mode": "env"})

    assert cfg is not None
    assert cfg.url == "http://127.0.0.1:8200"
    assert cfg.role == "podsquire"
    assert cfg.output_mode == VaultOutputMode.ENV
