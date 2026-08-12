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


def write_yaml(path: Path, data: dict) -> Path:
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


def test_loads_enabled_platform_services_from_local_catalogue(tmp_path: Path) -> None:
    catalogue = write_yaml(
        tmp_path / "platform-services.yml",
        {
            "proxy_presets": {
                "vault": {
                    "mode": "http",
                    "local_port": 8200,
                    "remote_host": "vault.example.svc.cluster.local",
                    "remote_port": 8200,
                },
                "mongo": {
                    "mode": "tcp",
                    "local_port": 27017,
                    "remote_host": "mongodb.example.svc.cluster.local",
                    "remote_port": 27017,
                },
            }
        },
    )
    path = write_config(
        tmp_path,
        {
            "platform_services": {"path": str(catalogue)},
            "enabled_platform_services": ["vault", "mongo"],
        },
    )

    config = _load_config(str(path))

    assert [p["name"] for p in config["proxies"]] == ["vault", "mongo"]
    assert config["proxies"][1]["mode"] == "tcp"


def test_loads_enabled_platform_services_from_local_directory(tmp_path: Path) -> None:
    services = tmp_path / "services"
    services.mkdir()
    write_yaml(
        services / "vault.yml",
        {
            "mode": "http",
            "local_port": 8200,
            "remote_host": "vault.example.svc.cluster.local",
            "remote_port": 8200,
        },
    )
    path = write_config(
        tmp_path,
        {
            "platform_services": {"path": str(services)},
            "enabled_platform_services": ["vault"],
        },
    )

    config = _load_config(str(path))

    assert config["proxies"] == [
        {
            "name": "vault",
            "mode": "http",
            "local_port": 8200,
            "remote_host": "vault.example.svc.cluster.local",
            "remote_port": 8200,
        }
    ]


def test_platform_services_path_can_come_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    services = tmp_path / "services"
    services.mkdir()
    write_yaml(
        services / "mongo.yaml",
        {
            "mode": "tcp",
            "local_port": 27017,
            "remote_host": "mongodb.example.svc.cluster.local",
            "remote_port": 27017,
        },
    )
    monkeypatch.setenv("PODSQUIRE_PLATFORM_SERVICES_PATH", str(services))
    path = write_config(tmp_path, {"enabled_platform_services": ["mongo"]})

    config = _load_config(str(path))

    assert config["proxies"][0]["name"] == "mongo"
    assert config["proxies"][0]["remote_port"] == 27017


def test_missing_platform_services_warn_and_continue_by_default(tmp_path: Path, caplog: pytest.LogCaptureFixture) -> None:
    path = write_config(
        tmp_path,
        {
            "platform_services": {"path": str(tmp_path / "missing-services"), "retries": 0},
            "enabled_platform_services": ["vault", "mongo"],
        },
    )

    config = _load_config(str(path))

    assert config.get("proxies", []) == []
    assert "services not loaded: ['vault', 'mongo']" in caplog.text


def test_missing_platform_services_can_fail_fast(tmp_path: Path) -> None:
    path = write_config(
        tmp_path,
        {
            "platform_services": {
                "path": str(tmp_path / "platform-services.yml"),
                "retries": 0,
                "fail_on_load_error": True,
            },
            "enabled_platform_services": ["vault"],
        },
    )

    with pytest.raises(RuntimeError, match="Platform service directory failed to load"):
        _load_config(str(path))


def test_vault_config_uses_public_safe_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_URL", raising=False)
    monkeypatch.delenv("VAULT_ROLE", raising=False)

    cfg = _load_vault_config({"kv_path": "apps/example", "output_mode": "env"})

    assert cfg is not None
    assert cfg.url == "http://127.0.0.1:8200"
    assert cfg.role == "podsquire"
    assert cfg.output_mode == VaultOutputMode.ENV
