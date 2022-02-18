#!/usr/bin/env python3

"""Compute canonical hash of directory contents

Usage:

    from dirhash import dirhash
    hash = dirhash("./mydir")
    print(f"The hash of ./mydir is {hash}")

Commandline usage:
    python3 -m dirhash ./mydir
"""

from posixpath import dirname
from typing import Optional, List, Sequence

from sys import argv, stderr, exit
from subprocess import PIPE, Popen
import os
import errno

def dirhash(dirname: str, exclude: Optional[Sequence[str]]=None) -> str:
  """Compute a canonical hash for the contents of a directory

  Computes a hash such that using rsync -a on a directory will
  produce a new directory with the same hash.

  File names and attributes atre included in the hash.

  File modification/access times are not significant, so touching
  a file will not change the hash.

  Args:
      dirname (str): The name of the directory to hash. Relative to current
                     working directory.
      exclude (Sequence[str], optional):  An optional sequence of glob patterns to exclude from the hash.

  Raises:
      FileNotFoundError: The provided directory does not exist
      RuntimeError: An error occurred invoking 'tar'
      RuntimeError: An error occurred invoking 'sha256sum'
      RuntimeError: sha256sum did not return a 64-character hex hash value

  Returns:
      str: A stable, canonical 64-character hex SHA 256 hash of the directory contents
  """
  if not os.path.exists(dirname):
    raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), dirname)
  cmd = ['tar', '-C', dirname, '-cf', '-', '--sort=name', '--mtime=UTC 2019-01-01']
  if not exclude is None:
    for exclude_pattern in exclude:
      cmd.append(f"--exclude={exclude_pattern}")
  cmd.append('.')
  with Popen(cmd, stdout=PIPE) as tar_process:
    with Popen(['sha256sum'], stdin=tar_process.stdout, stdout=PIPE) as sha256sum_process:
      tar_process.stdout.close()
      stdout_bytes = sha256sum_process.communicate()[0]
      rc = sha256sum_process.returncode
      if rc != 0:
        raise RuntimeError(f"sha256sum failed; rc={rc}")
    tar_process.wait()
    rc = tar_process.returncode
    if rc != 0:
      raise RuntimeError(f"tar failed; rc={rc}")

  hash = stdout_bytes.decode('utf-8').rstrip().split(' ')[0]
  if len(hash) != 64:
    raise RuntimeError(f"sha256sum returned incorrect hash length {len(hash)}")
  return hash

def main(argv: Optional[Sequence[str]]=None):
  import argparse

  parser = argparse.ArgumentParser(description="Compute a canonical hash of a directory's contents.")
  parser.add_argument('--exclude', '-x', action='append', default=[],
                      help='Exclude files from the hash that match a GLOB pattern. May be repeated.')
  parser.add_argument('dirname',
                      help=f"The directory name for which a hash should be computed. Relative to the current directory.")

  args = parser.parse_args(argv)

  dirname: str = args.dirname
  exclude: List[str] = args.exclude

  if not os.path.exists(dirname):
    print(f"dirhash: Directory does not exist: {dirname}", file=stderr)
    exit(1)

  hash = dirhash(dirname, exclude=exclude)
  print(hash)

if __name__ == "__main__":
  main()
