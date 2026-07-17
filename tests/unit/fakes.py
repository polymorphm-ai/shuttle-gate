from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from hashlib import sha256
from pathlib import Path

from shuttle_gate.runner import CommandResult


class FakeRunner:
    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], str | None, bool]] = []
        self.key_index = 0
        self.results: dict[tuple[str, ...], CommandResult] = {}

    def run(
        self,
        args: Sequence[str],
        *,
        input_text: str | None = None,
        timeout: float = 30.0,
        check: bool = True,
        env: Mapping[str, str] | None = None,
    ) -> CommandResult:
        del timeout, env
        command = tuple(str(arg) for arg in args)
        self.calls.append((command, input_text, check))
        if command in self.results:
            return self.results[command]
        stdout = ""
        if command == ("wg", "genkey"):
            self.key_index += 1
            stdout = base64.b64encode(bytes([self.key_index]) * 32).decode("ascii") + "\n"
        elif command == ("wg", "pubkey"):
            digest = sha256((input_text or "").strip().encode("ascii")).digest()
            stdout = base64.b64encode(digest).decode("ascii") + "\n"
        elif command == ("wg", "genpsk"):
            self.key_index += 1
            stdout = base64.b64encode(bytes([self.key_index + 32]) * 32).decode("ascii") + "\n"
        elif command and command[0] == "ssh-keygen":
            target = Path(command[command.index("-f") + 1])
            target.write_text("ssh-private\n", encoding="ascii")
            Path(str(target) + ".pub").write_text("ssh-ed25519 public\n", encoding="ascii")
        return CommandResult(command, 0, stdout, "")
