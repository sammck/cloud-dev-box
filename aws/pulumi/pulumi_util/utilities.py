from typing import List, Optional, Tuple, Type, Any

import os
import pkg_resources

from semver import VersionInfo as SemverVersion
from parver import Version as PEP440Version

def get_env_val_and_name(*args: List[str], coercer: Type=str) -> Tuple[Any, Optional[str]]:
  """
  Given an ordered list of environment variable names, returns the coerced value and name of the first
  one that is set, or (None, None) if none of them are set.

  Args:
    *args (List[str], optional):  A list of environment variable names to try in oder
    coercer:  A type or function that will convert a string into the desired return type

  Raises:
    ValueError if the string could not be coerced into the desired type.

  Returns:
    Tuple[Any, Optional[str]): the coerced value and name of the first variable that is set, or (None, None) if none of them are set.
  """
  for name in args:
    value = os.getenv(name)
    if value is not None:
      try:
        value = coercer(value)
      except Exception as e:
        raise(f"Value of environment variable \"{name}\"=\"{value}\"cannot be coerced to {coercer.__name__}") from e
      return value, name
  return None, None

def get_env(*args: List[str], coercer: Type=str) -> Any:
  """
  Given an ordered list of environment variable names, returns the coerced value of the first
  one that is set, or None if none of them are set.

  Args:
    *args (List[str], optional):  A list of environment variable names to try in oder
    coercer:  A type or function that will convert a string into the desired return type

  Raises:
    ValueError if the string could not be coerced into the desired type.

  Returns:
    Any: the coerced value of the first variable that is set, or None if none of them are set.
  """
  return get_env_val_and_name(*args, coercer=coercer)[0]

def get_env_bool(*args: List[str]) -> Optional[bool]:
  """
  Given an ordered list of environment variable names, returns the boolean value of the first
  one that is set, or None if none of them are set.

  Raises:
    ValueError: the first variable that is set does not contain a valid boolean value.

  Returns:
    Optional[bool]: the boolean value of the first variable that is set, or None if none of them are set.
  """
  def coerced_bool(s: str) -> bool:
    # NOTE: these values are taken from https://golang.org/src/strconv/atob.go?s=351:391#L1, which is what
    # Terraform uses internally when parsing boolean values.
    if s in ["1", "t", "T", "true", "TRUE", "True"]:
      return True
    if s in ["0", "f", "F", "false", "FALSE", "False"]:
      return False
    raise ValueError(f"\"{s}\" is not a valid boolean string representation")

  return get_env(*args, coercer=coerced_bool)

def get_env_int(*args: List[str]) -> Optional[int]:
  """
  Given an ordered list of environment variable names, returns the int value of the first
  one that is set, or None if none of them are set.

  Raises:
    ValueError: the first variable that is set does not contain a valid int value.

  Returns:
    Optional[int]: the int value of the first variable that is set, or None if none of them are set.
  """
  return get_env(*args, coercer=int)

def get_env_float(*args) -> Optional[float]:
  """
  Given an ordered list of environment variable names, returns the float value of the first
  one that is set, or None if none of them are set.

  Raises:
    ValueError: the first variable that is set does not contain a valid int value.

  Returns:
    Optional[float]: the int value of the first variable that is set, or None if none of them are set.
  """
  return get_env(*args, coercer=float)

def get_version():
  '''

  # __name__ is set to the fully-qualified name of the current module, In our case, it will be
  # <some module>.utilities. <some module> is the module we want to query the version for.
  root_package, *rest = __name__.split('.')

  # pkg_resources uses setuptools to inspect the set of installed packages. We use it here to ask
  # for the currently installed version of the root package (i.e. us) and get its version.

  # Unfortunately, PEP440 and semver differ slightly in incompatible ways. The Pulumi engine expects
  # to receive a valid semver string when receiving requests from the language host, so it's our
  # responsibility as the library to convert our own PEP440 version into a valid semver string.

  pep440_version_string = pkg_resources.require(root_package)[0].version
  pep440_version = PEP440Version.parse(pep440_version_string)
  (major, minor, patch) = pep440_version.release
  prerelease = None
  if pep440_version.pre_tag == 'a':
      prerelease = f"alpha.{pep440_version.pre}"
  elif pep440_version.pre_tag == 'b':
      prerelease = f"beta.{pep440_version.pre}"
  elif pep440_version.pre_tag == 'rc':
      prerelease = f"rc.{pep440_version.pre}"
  elif pep440_version.dev is not None:
      prerelease = f"dev.{pep440_version.dev}"

  # The only significant difference between PEP440 and semver as it pertains to us is that PEP440 has explicit support
  # for dev builds, while semver encodes them as "prerelease" versions. In order to bridge between the two, we convert
  # our dev build version into a prerelease tag. This matches what all of our other packages do when constructing
  # their own semver string.
  '''
  major = 1
  minor = 0
  patch = 0
  prerelease = "dev.1"
  semver_version = SemverVersion(major=major, minor=minor, patch=patch, prerelease=prerelease)
  return str(semver_version)
