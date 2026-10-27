"""The Flow class and small helpers that turn text from the CSV into values.

One Flow object = one row of a netflow file = one network "conversation"
between a source machine and a destination machine.
"""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class Flow:
    """One cleaned row of the netflow file.

    Only src_ip and dst_ip are always present. The other fields are None
    when the input file does not have that column (or, for ports and time,
    when the value could not be read).
    """

    src_ip: str
    dst_ip: str
    dst_port: int | None = None
    protocol: str = ""
    start_time: datetime | None = None
    src_bytes: int | None = None
    total_bytes: int | None = None
    label: str = ""

    def is_from_botnet(self):
        """True if the CTU-13 label says the SOURCE of this flow is a bot.

        CTU-13 labels look like "flow=From-Botnet-V48-1-TCP-..." when the
        bot is the source, and "flow=To-Botnet-..." when the bot is the
        DESTINATION. Only the first kind marks the source as a bot, so the
        check looks for "from-botnet" and not just "botnet".
        """
        return "from-botnet" in self.label.lower()

    def is_from_normal(self):
        """True if the label says the source is a known clean machine."""
        return "from-normal" in self.label.lower()


def parse_count(text, column_name):
    """Turn text like "214" into the whole number 214.

    Used for byte counts. Raises ValueError with a readable message if the
    text is empty, not a whole number, or negative.
    """
    text = text.strip()
    if text == "":
        raise ValueError(f"{column_name} is empty")
    try:
        value = int(text)
    except ValueError:
        # Some tools write counts as "214.0"; accept that, reject "abc".
        try:
            number = float(text)
        except ValueError:
            raise ValueError(f"{column_name} is not a number: {text!r}")
        if not number.is_integer():
            raise ValueError(f"{column_name} is not a whole number: {text!r}")
        value = int(number)
    if value < 0:
        raise ValueError(f"{column_name} is negative: {text!r}")
    return value


def parse_port(text):
    """Turn a port like "53" or "0x0008" into a number, or None.

    CTU-13 writes ICMP "ports" in hexadecimal (for example 0x0008).
    int(text, 0) understands both "53" and "0x0008". A port is optional
    information here, so a bad or empty port gives None instead of an
    error.
    """
    text = text.strip()
    if text == "":
        return None
    try:
        port = int(text, 0)
    except ValueError:
        # int("08", 0) fails because of the leading zero; try base 10.
        try:
            port = int(text, 10)
        except ValueError:
            return None
    if port < 0 or port > 65535:
        return None
    return port


def parse_time(text, time_format):
    """Turn "2011/08/16 10:01:46.972101" into a datetime, or None.

    The format string comes from config.json. Time is only used for extra
    statistics, so a bad time gives None instead of rejecting the row.
    """
    text = text.strip()
    if text == "":
        return None
    try:
        return datetime.strptime(text, time_format)
    except ValueError:
        return None
