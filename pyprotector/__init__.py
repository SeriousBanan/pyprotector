"""Module for protecting python code."""

import pickle
import platform
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO
from os import path
from types import FunctionType, ModuleType
from typing import Any, Callable, Optional, Union

import cloudpickle
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


__all__ = ["ProgramState", "TimeUpError", "CipherPathes", "protect", "start"]


ProgramState = dict[str, Any]


class TimeUpError(Exception):
    """Exception raised when time is up and program can't be run."""


class RSAImportError(Exception):
    """Exception raised when problems appears while importing RSA key."""


class DecryptionError(Exception):
    """Exception raised when problems with decryption of the code."""


@dataclass
class CipherPathes:
    """Dataclass with pathes to cipher objects.

    Contains next attributes:
        - encrypted_code: Path to binary file with encrypted code.
        - rsa_key: Path to file with private RSA key.
    """

    encrypted_code: str
    rsa_key: str


@dataclass
class _EncryptedData:
    encrypted_data: bytes
    protected_private_rsa_key: bytes


del dataclass


class _Program:
    def __init__(
        self,
        program_state: ProgramState,
        starter: Callable[[ProgramState], Any],
        *,
        until_date: Optional[datetime] = None,
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
            raise TimeUpError("the time at which the code can run expired")

        return self._starter(self._program_state)


def protect(
    program_state: ProgramState,
    starter: Callable[[ProgramState], Any],
    passphrase: str,
    dst: str,
    *,
    until_date: Optional[Union[datetime, timedelta]] = None,
) -> CipherPathes:
    """Protect program by saving encrypted serealized code into binary file.

    Serialize code by value using cloudpickle module for having the ability to deserialize code
    without having the source code.

    Serialized code is encrypted using AES symmetric cipher with the session key,
    encrypted with RSA private key.

    Args:
        program_state: Dict with state of the program to protect.
        starter: Main function of the program to protect. Takes only one argument: program_state.
        passphrase: Passphase for protect saved into file private RSA key.
            Private RSA key would be used for decryption of the program.
        dst: Path to folder in which encrypted_program and private RSA key would be saved.
        until_date (optional): Date of time period after which program would never starts.
            Defaults to None.

    Raises:
        NotADirectoryError: If path in `dst` argument not valid.

    Returns:
        CipherPathes instance.
    """

    if not path.isdir(dst):
        raise NotADirectoryError("Expected path to directory in `dst` argument.")

    if until_date is not None and isinstance(until_date, timedelta):
        until_date += datetime.now()

    program = _Program(program_state=program_state, starter=starter, until_date=until_date)
    pickled = _dumps_object(program)

    encrypted_data = _encrypt_code(code=pickled, passphrase=passphrase)

    cipher_pathes = CipherPathes(
        encrypted_code=path.join(dst, "encrypted_code.bin"), rsa_key=path.join(dst, "rsa_key.bin")
    )

    with open(cipher_pathes.encrypted_code, "wb") as encrypted_code_file:
        encrypted_code_file.write(encrypted_data.encrypted_data)

    with open(cipher_pathes.rsa_key, "wb") as rsa_key_file:
        rsa_key_file.write(encrypted_data.protected_private_rsa_key)

    return cipher_pathes


def start(passphrase: str, cipher_pathes: CipherPathes) -> Any:
    """Starts protected program.

    Decrypt serialized code using AES and deserialize it by `pickle` module.

    Args:
        passphrase: Passphrase to read protected private RSA key from file.
        cipher_pathes: CipherPathes instance.

    Returns:
        Returns program output.
    """

    encrypted_data = _EncryptedData(encrypted_data=b"", protected_private_rsa_key=b"")

    with open(cipher_pathes.rsa_key, "rb") as rsa_key_file:
        encrypted_data.protected_private_rsa_key = rsa_key_file.read()

    with open(cipher_pathes.encrypted_code, "rb") as encrypted_code_file:
        encrypted_data.encrypted_data = encrypted_code_file.read()

    pickled = _decrypt_code(encrypted_data=encrypted_data, passphrase=passphrase)
    program: _Program = pickle.loads(pickled)

    program.start()


def _dumps_object(obj: Any) -> bytes:
    """Dumps given object using cloudpickle.

    Object would be pickled by value, not by reference.
    So you don't need to have source code with definition of the class of that object
    to deserialize it.

    Args:
        obj: Object to dumps.

    Raises:
        RuntimeError: If __main__ module is python interpreter.

    Returns:
        Bytes string with serealized object.
    """

    # todo: #9 think how to dump objects from interpreter.
    main_module = sys.modules["__main__"]
    try:
        main_module_dir_path = path.dirname(main_module.__file__)
    except AttributeError as exp:
        raise RuntimeError("protecting from interpreter not supported now") from exp

    if platform.system() == "Windows":
        environment_path, *_ = sys.executable.split("Scripts") if "Scripts" in sys.executable else path.dirname(sys.executable)
    else:
        environment_path, *_ = sys.executable.split("bin/")

    modules_to_look = [main_module]
    modules_for_registration = {main_module}

    for module in modules_to_look:
        for module_obj in map(
            lambda name: getattr(module, name), dir(module)  # pylint: disable=cell-var-from-loop
        ):
            if isinstance(module_obj, ModuleType):
                sub_module = module_obj

            elif isinstance(module_obj, (type, FunctionType)):
                sub_module = sys.modules[module_obj.__module__]

            else:
                sub_module = sys.modules[module_obj.__class__.__module__]

            if (
                # check that module not builtin
                sub_module.__name__ not in sys.builtin_module_names
                # check that module is file in project, not installed by package manager
                and hasattr(sub_module, "__file__")
                and sub_module.__file__.startswith(main_module_dir_path)
                and not sub_module.__file__.startswith(environment_path)
                # check that module wasn't already selected
                and sub_module not in modules_for_registration
                # check that module wasn't already registered
                and sub_module not in cloudpickle.list_registry_pickle_by_value()
            ):
                modules_for_registration.add(sub_module)
                modules_to_look.append(sub_module)

    for module in modules_for_registration:
        cloudpickle.register_pickle_by_value(module)

    pickled = cloudpickle.dumps(obj)

    for module in modules_for_registration:
        cloudpickle.unregister_pickle_by_value(module)

    return pickled


def _encrypt_code(code: bytes, passphrase: str) -> _EncryptedData:
    """Encrypt code with AES and session_key with RSA.

    Generates session key, and encrypts `code` using AES in EAX mode.
    Session key additionally encrypts by RSA with key 2048 bits length.

    Args:
        code: Bytes of code for encryption.
        passphrase: Passphrase that would be used in exporting of private RSA key.

    Returns:
        _EncryptedData instance, where:
            - encrypted_data constructed by concatenating of:
                1. Encrypted by PKCS1_OAEP session key.
                2. Nonce that was used in AES encryption of the code.
                3. MAC tag.
                4. Encrypted code by AES.
            - protected_private_rsa_key: Private RSA key exported in PEM
                with protection by passphrase.
    """

    rsa_key = RSA.generate(bits=2048)
    cipher_rsa = PKCS1_OAEP.new(rsa_key.public_key())

    encrypted_data = _EncryptedData(
        encrypted_data=b"",
        protected_private_rsa_key=rsa_key.export_key(
            passphrase=passphrase, pkcs=8, protection="scryptAndAES128-CBC"
        ),
    )

    session_key_length = 16
    session_key = get_random_bytes(session_key_length)

    encrypted_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)  # type: ignore
    encrypted_code, tag = cipher_aes.encrypt_and_digest(code)  # type: ignore

    encrypted_data.encrypted_data = (
        encrypted_session_key
        + cipher_aes.nonce  # type:ignore
        + tag
        + encrypted_code
    )

    return encrypted_data


def _decrypt_code(encrypted_data: _EncryptedData, passphrase: str) -> bytes:
    """Decrypt code using AES and session key, that would be decrypted by RSA.

    Imports rsa private key using passphrase. Splits the encrypted data into encrypted session key,
    nonce, MAC tag, and encrypted code. Decrypt session key with imported RSA key and using it
    decrypt and verify encrypted code.

    Args:
        encrypted_data: _Encrypted_data instance.
        passphrase: Passphrase that would be using in importing of private RSA key.

    Raises:
        RSAImportError: If private RSA key cannot be imported.
        DecryptionError: If decryption of the code failed.

    Returns:
        bytes: Decrypted bytes of code.
    """

    try:
        rsa_key = RSA.import_key(encrypted_data.protected_private_rsa_key, passphrase=passphrase)
    except ValueError as exp:
        raise RSAImportError("incorrect passphrase or file with RSA key") from exp

    nonce_size_in_bytes = 16
    tag_size_in_bytes = 16

    with BytesIO(encrypted_data.encrypted_data) as encrypted_data_io:
        encrypted_session_key, nonce, tag, encrypted_code = [
            encrypted_data_io.read(size)
            for size in (rsa_key.size_in_bytes(), nonce_size_in_bytes, tag_size_in_bytes, -1)
        ]

    try:
        cipher_rsa = PKCS1_OAEP.new(rsa_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        code = cipher_aes.decrypt_and_verify(encrypted_code, tag)  # type: ignore
    except ValueError as exp:
        raise DecryptionError("code cannot be decrypted") from exp

    return code
