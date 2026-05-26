"""Optional Windows desktop notifications for Sentinel.

This module isolates desktop notification logic from the rest of the app.

Notifications are useful for alerting the user when a suspicious file is found,
but they are not essential to the scan itself. Because of that, notification
errors should never crash Sentinel or interrupt scanning.
"""

from __future__ import annotations


def send_desktop_notification(title: str, message: str) -> None:
    """Send a desktop notification if notification support is available.

    Sentinel uses plyer for cross-platform notification support.

    This function intentionally imports plyer inside the function instead of at
    the top of the file. That way, if plyer is missing or broken, the whole app
    can still start and scan files normally.

    Notification failure is treated as non-critical because scanning and saving
    results are more important than showing a pop-up.
    """

    try:
        # Import plyer only when a notification is actually needed.
        # This keeps notification support optional.
        from plyer import notification

        # Show a short Sentinel notification.
        # The scan result itself still appears inside the main UI.
        notification.notify(
            title=title,
            message=message,
            app_name="Sentinel",
            timeout=5,
        )

    except Exception:
        # Notifications should never break scanning.
        # If Windows notifications, plyer, or Focus Assist cause issues,
        # Sentinel simply continues without showing a desktop pop-up.
        return