#!/usr/bin/env python3

from typing import Tuple, Optional
from pathlib import Path

import subprocess
import sys
import os
import argparse
import re

home_dir = os.path.expanduser("~")

pulumi_dir = os.path.join(home_dir, '.pulumi')
pulumi_bin_dir = os.path.join(pulumi_dir, 'bin')
pulumi_std_cmd = os.path.join(pulumi_bin_dir, 'pulumi')

def get_pulumi_in_path() -> Optional[str]:
  try:
    cmd_path = subprocess.check_output("command -v pulumi", shell=True).decode('utf-8').rstrip()
  except subprocess.CalledProcessError as e:
    rc: int = e.returncode
    if rc != 1 and rc != 127:
      raise
    cmd_path = None
  return cmd_path

pulumi_cmd: Optional[str] = get_pulumi_in_path()
if pulumi_cmd is None:
  pulumi_cmd = pulumi_std_cmd

def pulumi_is_installed() -> bool:
  return os.path.exists(pulumi_cmd)

def get_pulumi_cmd_version() -> Tuple[str, bool]:
  if not pulumi_is_installed():
    raise RuntimeError("Pulumi is not installed")
  upgrade_available: bool = False
  with subprocess.Popen([pulumi_cmd, 'version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
    (pulumi_out_bytes, pulumi_err_bytes) = proc.communicate()
    exit_code = proc.returncode
  pulumi_out = pulumi_out_bytes.decode('utf-8').rstrip()
  pulumi_err = pulumi_err_bytes.decode('utf-8').rstrip()
  if exit_code != 0:
    print(pulumi_err, file=sys.stderr)
    raise RuntimeError(f"Unexpected nonzero exit code from \"pulumi version\": {exit_code}")
  m = re.match(r'^v([^ ]+)$', pulumi_out, re.MULTILINE);
  if not m:
    print(pulumi_err, file=sys.stderr)
    raise RuntimeError(f"Unexpected output from \"pulumi version\": \"\"\"\"{pulumi_out}\"\"")
  pulumi_version = m[1]
  if pulumi_err != '':
    """
     warning: A new version of Pulumi is available. To upgrade from version '3.17.1' to '3.24.1', run 
     $ curl -sSL https://get.pulumi.com | sh
     or visit https://pulumi.com/docs/reference/install/ for manual instructions and release notes.
    """
    pulumi_err_0 = pulumi_err.splitlines()[0]
    m = re.match(r'^warning: A new version of Pulumi is available\..*$', pulumi_err_0)
    if not m:
      print(pulumi_err, file=sys.stderr)
      raise RuntimeError(f"Unexpected stderr output from \"pulumi version\" with version={pulumi_version}")
    upgrade_available = True
  return pulumi_version, upgrade_available

def get_short_pulumi_cmd() -> str:
  if not pulumi_is_installed():
    raise RuntimeError("Pulumi is not installed")
  result = pulumi_cmd
  if pulumi_cmd == get_pulumi_in_path():
    result = 'pulumi'
  return result

def get_pulumi_username() -> Optional[str]:
  with subprocess.Popen([pulumi_cmd, 'whoami'], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
    (pulumi_out_bytes, pulumi_err_bytes) = proc.communicate()
    exit_code = proc.returncode
  pulumi_out = pulumi_out_bytes.decode('utf-8').rstrip()
  pulumi_err = pulumi_err_bytes.decode('utf-8').rstrip()
  username: Optional[str] = None
  if pulumi_err != '':
    """
    error: PULUMI_ACCESS_TOKEN must be set for login during non-interactive CLI sessions
    """
    if not pulumi_err.startswith("error: PULUMI_ACCESS_TOKEN must be set "):
      print(pulumi_err, file=sys.stderr)
      raise RuntimeError(f"Unexpected stderr output from \"pulumi whoami\", exit_code={exit_code}")
  else:
    if exit_code != 0:
      raise RuntimeError("Unexpected nonzero exit code from \"pulumi whoami\": {exit_code}")
    if pulumi_out == "":
      raise RuntimeError(f"Unexpected empty username output from \"pulumi whoami\"")

    username = pulumi_out
  return username



need_install: bool = False
old_pulumi_version: Optional[str] = None
if not pulumi_is_installed():
  print(f"Pulumi is not installed; installing latest version into {pulumi_cmd}", file=sys.stderr)
  need_install = True
else:
  old_pulumi_version, upgrade_available = get_pulumi_cmd_version()
  if upgrade_available:
    resolved_pulumi_cmd = str(Path(pulumi_cmd).resolve())
    if resolved_pulumi_cmd != pulumi_std_cmd:
      raise RuntimeError(f"Pulumi version {old_pulumi_version} is in $PATH but is in nonstandard location \"{pulumi_cmd}\", unable to perform available upgrade")
    print(f"An upgrade for Pulumi current version {old_pulumi_version} is available; upgrading to latest version", file=sys.stderr)
    need_install = True
  else:
    pulumi_version = old_pulumi_version
    print(f"The current Pulumi version {pulumi_version} is the latest available version; no upgrade necessary", file=sys.stderr)

if need_install:
  subprocess.check_call("curl -sSL https://get.pulumi.com | sh", shell=True)
  pulumi_version, upgrade_available = get_pulumi_cmd_version()
  if upgrade_available:
    if old_pulumi_version is None:
      raise RuntimeError(f"Pulumi upgrade still available after installing version {pulumi_version}")
    else:
      raise RuntimeError(f"Pulumi upgrade still available after upgrading from version {old_pulumi_version} to version {pulumi_version}")
  else:
    if old_pulumi_version is None:
      print(f"Successfully installed Pulumi version {pulumi_version}", file=sys.stderr)
    else:
      print(f"Successfully upgraded Pulumi from version {old_pulumi_version} to version {pulumi_version}", file=sys.stderr)

short_pulumi_cmd = get_short_pulumi_cmd()

username = get_pulumi_username()
if username is None:
  print(f"NOTE: you are not logged into Pulumi. Please run \"{short_pulumi_cmd} login\" to permanently authenticate this environment.", file=sys.stderr)
else:
  print(f"You are logged into Pulumi as {username}.", file=sys.stderr)

if get_pulumi_in_path() is None:
  pulumi_bin_dir = os.path.dirname(pulumi_cmd)
  print(f"NOTE: The pulumi bin dir {pulumi_bin_dir} is not currently in your $PATH. For convenience, you may want to add it to ~/.profile", file=sys.stderr)

