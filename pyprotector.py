from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Union

ProgramState = dict[str, Any]


@dataclass
class CypherPathes:
    encrypted_code: str
    rsa_key: str


class _Program:
    def __init__(
        self,
        program_state: ProgramState,
        starter: Callable[[ProgramState], Any],
        *,
        until_date: Optional[datetime] = None
    ) -> None:
        ...

    def start() -> Optional[NoReturn]:
        ...


def protect(
    initializer: Callable[[], ProgramState],
    starter: Callable[[ProgramState], Any],
    passphrase: str,
    dst: str,
    *,
    until_date: Optional[Union[datetime, timedelta]] = None
) -> CypherPathes:
    ...


def start(passphrase: str, cypher_pathes: CypherPathes) -> Any:
    ...