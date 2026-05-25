"""Optional Windows desktop notifications for Sentinel."""

from __future__ import annotations


def send_desktop_notification(title: str, message: str) -> None:
    try:
        from plyer import notification
        notification.notify(title=title, message=message, app_name="Sentinel", timeout=5)
    except Exception:
        # Notifications should never break scanning.
        return
