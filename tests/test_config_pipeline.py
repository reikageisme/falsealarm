import pytest
import inspect
import pkgutil
import importlib

from falsealarm.core.config import ScanConfig
from falsealarm.core.pipeline import PipelineManager
from falsealarm.modules.base import BaseModule


@pytest.mark.parametrize(
    ("changes", "message"),
    [
        ({"timeout": 0}, "Timeout"),
        ({"delay": -1}, "Delay"),
        ({"depth": "extreme"}, "Depth"),
        ({"format": "xml"}, "Output format"),
        ({"notify_type": "email"}, "Notification type"),
        ({"notify_type": "discord"}, "webhook URL"),
        ({"notify_type": "telegram"}, "token and chat ID"),
    ],
)
def test_config_rejects_invalid_operational_settings(changes, message):
    config = ScanConfig(target="example.com", **changes)

    with pytest.raises(ValueError, match=message):
        config.validate()


def test_pipeline_preserves_explicit_module_order_and_deduplicates():
    config = ScanConfig(
        target="example.com",
        modules=["vulnscan", "httpprobe", "vulnscan"],
    )

    assert PipelineManager(config).get_allowed_modules() == [
        "vulnscan",
        "httpprobe",
    ]


def test_quick_module_alias_uses_quick_depth_profile():
    config = ScanConfig(target="example.com", modules=["quick"], depth="normal")

    assert PipelineManager(config).get_allowed_modules() == [
        "httpprobe",
        "ssl",
    ]


def test_legacy_module_names_are_canonicalized():
    config = ScanConfig(
        target="example.com",
        modules=["headers_ssl", "techdetect"],
    )

    assert PipelineManager(config).get_allowed_modules() == ["ssl", "tech"]


def test_all_selects_every_discovered_module_name():
    config = ScanConfig(target="example.com", modules=["all"], depth="normal")

    assert PipelineManager(config).get_allowed_modules() == [
        "dns",
        "subdomain",
        "portscan",
        "httpprobe",
        "ssl",
        "tech",
        "vulnscan",
        "cors",
        "dirfuzz",
        "websocket",
        "js_analysis",
        "wayback",
    ]


def test_all_pipeline_entry_points_are_independent_collectors():
    config = ScanConfig(target="example.com", modules=["all"])

    assert PipelineManager(config).get_entry_points() == [
        "dns",
        "subdomain",
        "portscan",
        "httpprobe",
        "wayback",
    ]


def test_all_profile_matches_auto_discovered_modules():
    import falsealarm.modules as modules_pkg

    discovered = set()
    prefix = modules_pkg.__name__ + "."
    for _, module_name, _ in pkgutil.iter_modules(modules_pkg.__path__, prefix):
        module = importlib.import_module(module_name)
        for _, cls in inspect.getmembers(module, inspect.isclass):
            if issubclass(cls, BaseModule) and cls is not BaseModule:
                discovered.add(cls.name)

    config = ScanConfig(target="example.com", modules=["all"])
    assert set(PipelineManager(config).get_allowed_modules()) == discovered
