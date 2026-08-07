import pytest

from falsealarm.core.config import ScanConfig
from falsealarm.core.pipeline import PipelineManager


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
        "headers_ssl",
    ]
