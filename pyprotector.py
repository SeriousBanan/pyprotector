from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Optional, Union

ProgramState = dict[str, Any]


class TimeUpError(Exception):
    """Exception raised when time is up and program can't be run."""


@dataclass
class CypherPathes:
    """Dataclass with pathes to cypher objects.

    Contains next attributes:
        - encrypted_code: Path to binary file with encrypted code.
        - rsa_key: Path to file with private RSA key.
    """

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
        self._program_state = program_state
        self._starter = starter
        self._until_date = until_date

    def start(self) -> Any:
        """Starts saved starter function with program state.

        Raises:
            TimeUpError: If the program can't be run
                because specified in initialization date has come.

        Returns:
            The returned value of starter function.
        """

        if self._until_date is not None and self._until_date < datetime.now():
            raise TimeUpError()

        return self._starter(self._program_state)


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
