"""
FalseAlarm — Notification Manager

Sends scan summaries / diff alerts to Discord, Slack, or Telegram via
webhook, so continuous-monitoring scans can alert automatically
instead of requiring someone to check the terminal output.
"""

from __future__ import annotations

import aiohttp


class NotifyError(RuntimeError):
    """Raised when a notification fails to send."""


class NotifyManager:
    """Send a text/markdown message to a chat platform.

    Args:
        notify_type: One of "discord", "slack", "telegram".
        webhook_url: Discord/Slack incoming webhook URL. Ignored for telegram.
        telegram_token: Telegram bot token (only used when notify_type="telegram").
        telegram_chat_id: Telegram chat/channel ID (only used when notify_type="telegram").
    """

    def __init__(
        self,
        notify_type: str,
        webhook_url: str | None = None,
        telegram_token: str | None = None,
        telegram_chat_id: str | None = None,
    ):
        self.notify_type = notify_type.lower()
        self.webhook_url = webhook_url
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id

    async def send(self, content: str, title: str | None = None) -> None:
        """Send a message using the configured platform.

        Args:
            content: Markdown-formatted message body.
            title: Optional title (used by Discord/Slack embeds).

        Raises:
            NotifyError: If the request fails or config is incomplete.
        """
        if self.notify_type == "discord":
            await self._send_discord(content, title)
        elif self.notify_type == "slack":
            await self._send_slack(content, title)
        elif self.notify_type == "telegram":
            await self._send_telegram(content, title)
        else:
            raise NotifyError(f"Unknown notify_type: {self.notify_type}")

    async def _send_discord(self, content: str, title: str | None) -> None:
        if not self.webhook_url:
            raise NotifyError("Discord notify requires --notify-webhook")

        # Discord content field caps at 2000 chars; embeds cap at 4096.
        payload = {
            "embeds": [
                {
                    "title": title or "FalseAlarm Scan Update",
                    "description": content[:4000],
                    "color": 0xE74C3C,
                }
            ]
        }
        await self._post_json(self.webhook_url, payload)

    async def _send_slack(self, content: str, title: str | None) -> None:
        if not self.webhook_url:
            raise NotifyError("Slack notify requires --notify-webhook")

        text = f"*{title}*\n{content}" if title else content
        payload = {"text": text[:39000]}  # Slack's practical message size limit
        await self._post_json(self.webhook_url, payload)

    async def _send_telegram(self, content: str, title: str | None) -> None:
        if not self.telegram_token or not self.telegram_chat_id:
            raise NotifyError(
                "Telegram notify requires --telegram-token and --telegram-chat-id"
            )

        text = f"*{title}*\n{content}" if title else content
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
        payload = {
            "chat_id": self.telegram_chat_id,
            "text": text[:4096],  # Telegram message length limit
            "parse_mode": "Markdown",
        }
        await self._post_json(url, payload)

    async def _post_json(self, url: str, payload: dict) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status >= 300:
                        body = await resp.text()
                        raise NotifyError(f"Notify request failed ({resp.status}): {body[:300]}")
        except aiohttp.ClientError as e:
            raise NotifyError(f"Network error while sending notification: {e}") from e
