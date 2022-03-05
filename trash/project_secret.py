#!/usr/bin/env python3

"""Simple tools for getting/setting project-scoped secrets. Supports arbitrary JSON-compatible secrets.

Makes use of the "keyring" package to actually store/retrieve secrets.


.project-secret.json:
  
{
  "version": "1.0",
  "keyring_backend_package": "keyring.backends.SecretService.Keyring",
  "namespace_template": "project-secret-${project_dir_hash}",
  "project_secret_root_dir": ".",
}

A key namespace for this project ensures that secrets in this project do not collide with secrets from other projects:

The key namespace is determoined from (in order of preference):

  1.  If namespace is provided as a parameter to api calls or command line, it is used
  2.  If environment variable PROJECT_SECRET_NAMESPACE is defined and not empty, it is used
  3.  If the project root directory can be determined (see below), that directory is used to determine a configuration (see below).

The project root directory name is determined from (in order of preference):

  1.  If project_dir is provided as a parameter to API calls, it is used.
  2.  If environment variable PROJECT_SECRET_ROOT_DIR is set, it is used.
  3.  If a parent directory of the current dorectory or a provided starting directory contains a file '.project-secret.json', that directory is used
  3.  If the git command is available and "git rev-parse --show-toplevel" succeeds, this is used (based on current working dir)

  a SHA1 hash of the project directory name
      is used to define a unique namespace.

"""

from argparse import Namespace
from typing import Optional, List, Dict, Tuple, Type

from importlib_metadata import version
from typehints import JSONType
import os
import sys
import keyring
from keyring.backend import KeyringBackend
import keyring.errors
import subprocess
import hashlib
import json
from string import Template

def hash(s: str) -> str:
  h = hashlib.sha1(s.encode("utf-8")).hexdigest()
  return h

KeyringBackendClass = Type[KeyringBackend]

default_keyring: Optional[KeyringBackend] = None

def set_default_key_ring(key_ring: Optional[KeyringBackend]=None):
  global default_key_ring
  default_key_ring = key_ring

def hash(s: str) -> str:
  h = hashlib.sha1(s.encode("utf-8")).hexdigest()
  return h

def set_default_keyring(key_ring: Optional[KeyringBackend]=None):
  global default_keyring
  default_keyring = key_ring

def get_default_key_ring(key_ring: Optional[KeyringBackend]=None):
  if key_ring is None:
    key_ring = default_key_ring
    if key_ring is None:
      key_ring = keyring.get_keyring()
  return key_ring

def get_default_keyring_backend_package(key_ring: Optional[KeyringBackend]):
  key_ring = get_default_key_ring(key_ring)
  klass = key_ring.__class__
  module = klass.__module__
  return module + '.' + klass.__qualname__

class ProjectSecretError(RuntimeError):
  pass

class NoRootDirError(ProjectSecretError):
  def __init__(self, starting_dir: Optional[str]=None):
    if starting_dir is None:
      msg = "A project secret root dir could not be determined. Please set PROJECT_SECRET_ROOT_DIR, or use a directory within the project secret root dir")
    else:
      msg = f"A project secret root dir could not be found at or above {starting_dir}. Please set PROJECT_SECRET_ROOT_DIR, or use a directory within the project secret root dir")
    super().__init__(msg)
      

class NoNamespaceError(ProjectSecretError):
  def __init__(self):
    super().__init__("A project secret namespace could not be determined. Please set PROJECT_SECRET_NAMESPACE or PROJECT_SECRET_ROOT_DIR, or use directory within the project secret root dir")

class NoSecretError(ProjectSecretError):
  def __init__(self, name: str, namespace: Optional[str]=None):
    if namespace is None or namespace == '':
      msg = f"The project secret \"{name}\" has not been set"
    else:
      msg = f"The project secret \"{name}\" has not been set in namespace \"{namespace}\""
    super().__init__(msg)

class ProjectSecretConfig:
  version: Optional[str] = None
  keyring_backend_package: Optional[str] = None
  namespace_template: Optional[str] = None
  project_dir: Optional[str] = None
  is_rel_project_dir: bool = True
  config_file_path: Optional[str] = None
  key_ring: Optional[KeyringBackend] = None

  DEFAULT_VERSION = "1.0"
  DEFAULT_FILENAME = ".project-secret.json"
  DEFAULT_NAMESPACE_TEMPLATE = "project-secret-%%DIRHASH%%"

  def __init__(
        self,
        keyring_backend_package: Optional[str] = None,
        namespace_template: Optional[str] = None,
        project_dir: Optional[str] = None,
        is_rel_project_dir: bool = True,
        config_file_path: Optional[str] = None,
      ):

    self.keyring_backend_package = keyring_backend_package
    self.namespace_template = namespace_template
    self.is_rel_project_dir = is_rel_project_dir
    if not project_dir is None:
      project_dir = os.path.abspath(project_dir)
    self.project_dir = project_dir
    if not config_file_path is None:
      config_file_path = os.path.abspath(config_file_path)
    self.config_file_path = config_file_path

  def clone(self) -> 'ProjectSecretConfig':
    result = ProjectSecretConfig()
    result.version = self.version
    result.keyring_backend_package = self.keyring_backend_package
    result.namespace_template = self.namespace_template
    result.project_dir = self.project_dir
    result.is_rel_project_dir = self.is_rel_project_dir
    result.config_file_path = self.config_file_path
    result.key_ring = self.key_ring
    return result

  def save(self, config_file_path: Optional[str] = None):
    """Writes the configuration file out

    {
      "version": "1.0",
      "keyring_backend_package": "keyring.backends.SecretService.Keyring",
      "namespace_template": "project-secret-${project_dir_hash}",
      "project_dir": ".",
    }

    Args:
        config_file_path (Optional[str], optional): The path to the config file, if not already set on this object. Defaults to None.

    Raises:
        ValueError: If a config file path could not be determined
    """
    if config_file_path is None:
      config_file_path = self.config_file_path
      if config_file_path is None:
        raise ValueError("config_file_path is required")
    config_file_path = os.path.abspath(config_file_path)
    if os.path.is_dir(config_file_path):
      config_dir = config_file_path
      config_file_path = os.path.join(config_dir, self.DEFAULT_FILENAME)
    else:
      config_dir = os.path.dirname(config_file_path)
      if not os.path.is_dir(config_dir):
        raise RuntimeError(f"config file path {config_file_path}: parent directory does not exist")
    version = self.version
    if version is None:
      version = self.DEFAULT_VERSION
    project_dir = self.project_dir
    rel_project_dir: Optional[str] = None
    is_rel_project_dir = self.is_rel_project_dir
    if not project_dir is None:
      project_dir = os.path.abspath(project_dir)
      if is_rel_project_dir:
        rel_project_dir = os.path.relpath(project_dir, config_dir)
      else:
        rel_project_dir = project_dir
    namespace_template = self.namespace_template
    if namespace_template is None:
      namespace_template = self.DEFAULT_NAMESPACE_TEMPLATE
    keyring_backend_package = self.keyring_backend_package
    if keyring_backend_package == '':
      keyring_backend_package = None
    
    data = dict(version=version)
    if not keyring_backend_package is None:
      data.update(keyring_backend_package)
    if not namespace_template is None:
      data.update(namespace_template=namespace_template)
    if not rel_project_dir is None and rel_project_dir != '.' and rel_project_dir != config_dir:
      data.update(project_dir=rel_project_dir)
    
    with open(config_file_path, 'w') as f:
      print(json.dumps(data, sort_keys=True, intent=2), file=f)

    self.version = version
    self.keyring_backend_package = keyring_backend_package
    self.namespace_template = namespace_template
    self.project_dir = project_dir
    self.is_rel_project_dir = not os.path.isabs(rel_project_dir)
    self.config_file_path = config_file_path
  
  def load(self, starting_dir: Optional[str] = None, config_file_path: Optional[str] = None) -> 'ProjectSecretConfig':
    if not config_file_path is None:
      config_file_path = os.path.abspath(config_file_path)
      if os.path.isdir(config_file_path):
        config_file_path = os.path.join(config_file_path, self.DEFAULT_FILENAME)
    else:
      if starting_dir is None:
        starting_dir = '.'
      starting_dir = os.path.abspath(starting_dir)
      cdir = starting_dir
      if os.path.isdir(cdir):
        while True:
          cpath = os.path.join(cdir, self.DEFAULT_FILENAME)
          if os.path.exists(cpath):
            config_file_path = cpath
            break
          ndir = os.path.dirname(cdir)
          if ndir == cdir:
            break
          cdir = ndir
        if config_file_path is None:
          raise NoSecretNamespaceError(f"Could not find {self.DEFAULT_FILENAME} in parent directory chain of {starting_dir}")
    with open(config_file_path) as f:
      json_text = f.read()

    data = json.loads(json_text)
    config_dir = os.path.dirname(config_file_path)

    version = data.get('version', None)
    if version is None:
      raise RuntimeError("Invalid project-secrets config file--no version")
    keyring_backend_package = data.get('keyring_backend_package', None)
    namespace_template = data.get("namespace_template", None)
    rel_project_dir = data.get("project_dir", None)
    if rel_project_dir is None:
      is_rel_project_dir = True
      project_dir = config_dir
    else:
      is_rel_project_dir = not os.path.isabs(project_dir)
      project_dir = os.path.abspath(os.path.join(config_dir, rel_project_dir))
    
    self.version = version
    self.keyring_backend_package = keyring_backend_package
    self.namespace_template = namespace_template
    self.project_dir = project_dir
    self.is_rel_project_dir = is_rel_project_dir
    self.config_file_path = config_file_path
    return self

  @property
  def project_dir_hash(self) -> Optional[str]:
    project_dir = self.project_dir
    if project_dir is None:
      return None

    result = hash(os.path.abspath(project_dir))
    return result

  @property
  def namespace(self) -> Optional[str]:
    project_dir_hash = self.project_dir_hash
    if project_dir_hash is None:
      return None
    namespace_template = self.namespace_template
    if namespace_template is None:
      namespace_template = self.DEFAULT_NAMESPACE_TEMPLATE
    tmpl = Template(namespace_template)
    result = tmpl.safe_substitute(dict(project_dir_hash=project_dir_hash))
    return result

  def get_keyring(self) -> KeyringBackend:
    result = self.key_ring
    if result is None:
      if self.keyring_backend_package is None:
        result = get_default_key_ring()
      else:
        result = keyring.core.load_keyring(self.keyring_backend_package)
      if result is None:
        raise NoSecretNamespaceError("Unable to load keyring")
    return result

def get_config(starting_dir: Optional[str] = None) -> ProjectSecretConfig:
  return ProjectSecretConfig().load(starting_dir=starting_dir)


def get_key_ring(cfg: Optional[ProjectSecretConfig] = None) -> KeyringBackend:
  if cfg is None:
  if key_ring is None:
    key_ring = default_key_ring
    if key_ring is None:
      key_ring = keyring.get_keyring()
  return key_ring

'''
def get_git_root_dir(starting_dir: Optional[str] = None) -> Optional[str]:
  result: Optional[str] = None

  if not starting_dir is None and starting_dir == '':
    starting_dir = None
  cmd = ['git', 'rev-parse', '--show-toplevel']
  try:
    with subprocess.Popen(cmd, cwd=starting_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:
      (stdout_bytes, stderr_bytes) = proc.communicate()
      exit_code = proc.returncode
    if exit_code == 0:
      stdout_s = stdout_bytes.decode('utf-8').rstrip()
      if stdout_s != '':
        result = stdout_s
    else:
      # git returned an error. Probably not in a git repo, but we should make sure
      stderr_s = stderr_bytes.decode('utf-8').split['\n'][0].rstrip()
      if not stderr_s.startswith("fatal: not a git repository"):
        # Unexpected error
        raise subprocess.CalledProcessError(exit_code, cmd)
  except FileNotFoundError:
    # "git" is not in PATH
    pass
  return result

def get_secret_project_dir(project_dir: Optional[str]=None, starting_dir: Optional[str]=None) -> Optional[str]:
  if project_dir is None:
    project_dir = os.environ.get('PROJECT_SECRET_ROOT_DIR', None):
    if not project_dir is None and project_dir == '':
      project_dir = None
    if project_dir is None:
      project_dir = get_git_root_dir(starting_dir=starting_dir)

  return project_dir

def get_secret_namespace(
      namespace: Optional[str]=None,
      project_dir: Optional[str]=None,
      starting_dir: Optional[str]=None,
      require: bool=True,
    ) -> Optional[str]:
  if namespace is None:
    namespace = os.environ.get('PROJECT_SECRET_NAMESPACE', None):
    if not namespace is None and namespace == '':
      namespace = None
    if namespace is None:
      dirname = get_secret_project_dir(project_dir=project_dir, starting_dir=starting_dir)
      if not dirname is None:
        namespace = f"project-{hash(dirname)}"
  if require and namespace is None:
    raise NoSecretNamespaceError()
'''


class Secrets:

  CFG_FILENAME = ".project-secret.json"
  NAMESPACE_PREFIX = "project-secret-"

  key_ring: Optional[KeyringBackend] = None
  namespace: Optional[str] = None

  @classmethod
  def hash(cls, s: str) -> str:
    h = hashlib.sha1(s.encode("utf-8")).hexdigest()
    return h


  @classmethod
  def get_project_root_dir(cls, starting_dir: Optional[str]=None, project_root_dir: Optional[str]=None, require: bool=True) -> Optional[str]:
    if project_root_dir is None:
      project_root_dir = os.environ.get("PROJECT_SECRET_ROOT_DIR")
      if project_root_dir == '':
        project_root_dir = None
      if project_root_dir is None
        if starting_dir is None:
          starting_dir = '.'
        starting_dir = os.path.abspath(starting_dir)
        if os.path.is_dir(starting_dir):
          cdir = starting_dir
          while True:
            cfg_file = os.path.join(cdir, cls.CFG_FILENAME)
            if os.path.exists(cfg_file):
              project_root_dir = cdir
              break
            ndir = os.path.dirname(cdir)
            if ndir == cdir:
              break   # we have reached the system root dir
            cdir = ndir
    if require and project_root_dir is None:
      raise NoRootDirError(starting_dir=starting_dir)

    project_root_dir = os.path.abspath(project_root_dir)
    return project_root_dir

  @classmethod
  def get_project_namespace(
        cls,
        namespace: Optional[str]=None,
        project_root_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require: bool=True,
      ) -> Optional[str]:
    if namespace is None:
      namespace = os.environ.get('PROJECT_SECRET_NAMESPACE', None)
      if namespace == '':
        namespace = None
      if namespace is None:
        project_root_dir = cls.get_project_root_dir(starting_dir=starting_dir, project_root_dir=project_root_dir, require=require)
        if not project_root_dir is None:
          namespace = f"project-secret-{cls.hash(project_root_dir)}"

    if require and namespace is None:
      raise NoNamespaceError()

  def __init__(
        self,
        starting_dir: Optional[str] = None,
        namespace: Optional[str] = None,
        project_root_dir: Optional[str] = None,
        key_ring: Optional[str] = None,
      ):
    namespace = self.get_project_namespace(namespace=namespace, project_root_dir=project_root_dir, require=True)
    self.namespace = namespace
    if key_ring is None:
      key_ring = get_default_key_ring()
    self.key_ring = key_ring

  def get_secret_json_text_if_exists(
        self,
        name: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require_namespace: bool=True,
        key_ring: Optional[KeyringBackend]=None
      ) -> Optional[str]:
    namespace = get_secret_namespace(namespace=namespace, project_dir=project_dir, starting_dir=starting_dir, require=require_namespace)
    if namespace is None:
      return None

    key_ring = get_key_ring(key_ring)

    json_text = key_ring.get_password(namespace, name)
    return (json_text, not json_text is None)

  def get_secret_if_exists(
        self,
        name: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require_namespace: bool=True,
        key_ring: Optional[KeyringBackend]=None
      ) -> Tuple[JSONType, bool]:
    json_text = get_secret_json_text_if_exists(
        name=name, namespace=namespace, project_dir=project_dir,
        starting_dir=starting_dir, require_namespace=require_namespace, key_ring=key_ring
      )
    if json_text is None:
      return (None, False)

    result = json.loads(json_text)
    return (result, True)

  def get_secret(
        self,
        name: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require: bool=True,
        require_namespace: bool=True,
        key_ring: Optional[KeyringBackend]=None
      ) -> JSONType:

    result, exists = get_secret_if_exists(
        name=name, namespace=namespace, project_dir=project_dir,
        starting_dir=starting_dir, require_namespace=require_namespace, key_ring=key_ring
      )
    if require and not exists:
      raise NoSecretError(name, namespace)

  def secret_exists(
        self,
        name: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require_namespace: bool=True,
        key_ring: Optional[KeyringBackend]=None
      ) -> bool:
    json_text = get_secret_json_text_if_exists(
        name=name, namespace=namespace, project_dir=project_dir,
        starting_dir=starting_dir, require_namespace=require_namespace, key_ring=key_ring
      )
    return not json_text is None

  def set_secret_json_text(
        self,
        name: str,
        json_text: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        key_ring: Optional[KeyringBackend]=None,
        validate_json: bool = True,
      ):

    if name is None or name == "":
      raise ValueError("Empty secret name key is not permitted")

    if json_text is None or not isinstance(json_text, str):
      raise ValueError("A string is required for JSON text")

    if validate_json:
      json.loads(json_text)

    namespace = get_secret_namespace(namespace=namespace, project_dir=project_dir, starting_dir=starting_dir, require=True)

    key_ring = get_key_ring(key_ring)

    key_ring.set_password(namespace, name, json_text)

  def set_secret(
        self,
        name: str,
        value: JSONType,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        key_ring: Optional[KeyringBackend]=None
      ):

    json_text = json.dumps(value, sort_keys=True)
    set_secret_json_text(
        name=name,
        json_text = json_text,
        namespace = namespace,
        project_dir = project_dir,
        starting_dir = starting_dir,
        key_ring = key_ring,
        validate = False                # No need to validate since we just serialized to json
      )

  def delete_secret(
        self,
        name: str,
        namespace: Optional[str]=None,
        project_dir: Optional[str]=None,
        starting_dir: Optional[str]=None,
        require: bool=True,
        require_namespace: bool=True,
        key_ring: Optional[KeyringBackend]=None,
      ):

    require_namespace = require_namespace or require
    namespace = get_secret_namespace(namespace=namespace, project_dir=project_dir, starting_dir=starting_dir, require=require_namespace)
    if not namespace is None:
      key_ring = get_key_ring(key_ring)

      try:
        key_ring.delete_password(namespace, name)
      except keyring.errors.PasswordDeleteError as ex:
        if require:
          raise NoSecretError(name, namespace) from ex


  def __contains__(self, item):
      return self.v.__contains__(item)

  def __getitem__(self, key: str) -> JSONType:
    try:
      result = self.get_secret(key, require=True)
    except NoSecretError:




def main(argv: Optional[List[str]]=None):

if __name__ == '__main__':
  pctx = PulumiContext()
  exit_code = pctx.pulumi_call()
  if exit_code != 0:
    sys.exit(exit_code)

  
