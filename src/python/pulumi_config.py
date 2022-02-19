#!/usr/bin/env python3

from typehints import JSONType, Optional, JSONDictType, List, Tuple, Dict

import os
import json
import hashlib
from urllib.parse import urlparse


import config
from config import (
    Dynaconf,
    get_virtualenv_dir,
    settings as default_settings,
    _DEBUG,
    dp
  )

#_DEBUG=True

def parse_s3_url(url: str) -> Tuple[str, str]:
  pr = urlparse(url, allow_fragments=False)
  if pr.scheme != 's3':
    raise ValueError(f"Invalid scheme for S3 URL: {url}")
  bucket = pr.netloc
  if bucket is None or bucket == '':
    raise ValueError(f"Empty bucket name in S3 URL: {url}")
  key: str
  if not pr.query is None and pr.query != "":
    key = f"{pr.path.lstrip('/')}?{pr.query}"
  else:
    key = pr.path.lstrip('/')
  return (bucket, key)


class PulumiConfig:

  settings: Dynaconf
  pulumi_install_dir: str
  pulumi_data_dir: str
  pulumi_workspaces_dir: str
  pulumi_plugins_dir: str
  pulumi_prog: str
  backend: str
  backend_is_s3: bool
  backend_scheme: str
  backend_bucket: str
  backend_key: str
  pulumi_project: str
  pulumi_stack: str
  pulumi_credentials_file: str
  pulumi_main_cfg_file: str
  pulumi_stack_cfg_file: str
  pulumi_workspace_file: str
  pulumi_main_script_target_file: str
  pulumi_main_script_source_file: str
  main_data: JSONDictType
  stack_data: JSONDictType
  osenviron: Dict[str, str]

  stack_config_templates: List[str] = [
    'aws:profile=aws_profile',
    'aws:region=aws_region',
    'owner=owner_email',
    'n_azs',
    'vpc_cidr',
    'n_potential_subnets',
    'managed_zone',
    'zone_name',
    'parent_zone_name',
    'parent_zone_name',
    'zone_prefix',
    'front_end_instance_type',
    'front_end_ssh_public_key',
    'front_end_ssh_public_key_file',
    'front_end_root_volume_size_gb',
  ]

  excluded_env_vars: List[str] = [
      'PULUMI_AUTOMATION_API_SKIP_VERSION_CHECK',
      'PULUMI_ACCESS_TOKEN',
      'PULUMI_BACKEN_URL',
      'PULUMI_CONFIG,',
      'PULUMI_CONFIG_PASSPHRASE,',
      'PULUMI_CONFIG_PASSPHRASE_FILE',
      'PULUMI_CONSOLE_DOMAIN',
      #'PULUMI_DEBUG_PROMISE_LEAKS',
      'PULUMI_ENABLE_LEGACY_APPLY',
      'PULUMI_ENABLE_LEGACY_DIFF',
      'PULUMI_ENABLE_LEGACY_PLUGIN_SEARCH',
      'PULUMI_HOME',
      'PULUMI_PREFER_YARN',
      'PULUMI_PYTHON_CMD',
      'PULUMI_SKIP_CONFIRMATIONS',
      'PULUMI_SKIP_UPDATE_CHECK',
      'PULUMI_TEST_MODE',
      #'NO_COLOR',
    ]

  def __init__(self, settings: Optional[Dynaconf]=None):
    if settings is None:
      settings = default_settings

    self.settings = settings

    project_dir: str = self.settings.project_dir
    install_dir = os.path.join(project_dir, 'install')
    self.pulumi_install_dir = os.path.join(install_dir, 'pulumi')
    self.pulumi_data_dir = os.path.join(self.pulumi_install_dir, 'data')
    self.pulumi_workspaces_dir = os.path.join(self.pulumi_install_dir, "workspaces")
    self.pulumi_plugins_dir = os.path.join(self.pulumi_install_dir, "plugins")

    self.pulumi_prog = os.path.join(self.pulumi_install_dir, 'bin', 'pulumi')

    self.backend: str = self.settings.pulumi_backend
    self.backend_bucket, self.backend_key = parse_s3_url(self.backend)
    self.backend_scheme = 's3'
    self.backend_is_s3 = True

    self.pulumi_project: str = self.settings.pulumi_project
    self.pulumi_stack: str = self.settings.pulumi_stack

    self.pulumi_credentials_file = os.path.join(self.pulumi_install_dir, 'credentials.json')
    self.pulumi_main_cfg_file = os.path.join(self.pulumi_data_dir, 'Pulumi.yaml')
    self.pulumi_stack_cfg_file = os.path.join(self.pulumi_data_dir, f"Pulumi.{self.pulumi_stack}.yaml")
    self.pulumi_main_script_target_file = os.path.join(self.pulumi_data_dir, "__main__.py")
    pulumi_src_dir = os.path.join(project_dir, 'src', 'pulumi')
    self.pulumi_main_script_source_file = os.path.join(pulumi_src_dir, "__main__.py")
    main_cfg_path_hash = hashlib.sha1(self.pulumi_main_cfg_file.encode("utf-8")).hexdigest()
    self.pulumi_workspace_file = os.path.join(self.pulumi_workspaces_dir, f"{self.pulumi_project}-{main_cfg_path_hash}-workspace.json")
    self.main_data = self.build_main_data()
    self.stack_data = self.build_stack_data()
    osenviron = dict(os.environ)
    for key in self.excluded_env_vars:
      if key in osenviron:
        del osenviron[key]
    osenviron['PULUMI_HOME'] = self.pulumi_data_dir
    self.osenviron = osenviron

  def build_main_data(self) -> JSONDictType:
    venv_dir = get_virtualenv_dir()
    python_options: JSONDictType = {}
    if not venv_dir is None:
      python_options['virtualenv'] = venv_dir

    result: JSONDictType = {
        'name': self.settings.pulumi_project,
        'runtime': {
            'name': 'python',
            'options': python_options,
          },
        'description': self.settings.project_description,
      }
    return result

  def apply_config_template(self, output: JSONDictType, template: str):
    eqparts = template.split('=', 1)
    out_key = eqparts[0]

    if len(eqparts) > 1:
      in_key = eqparts[1]
    else:
      in_key = out_key

    if not ':' in out_key:
      out_key = f"{self.pulumi_project}:{out_key}"

    v: JSONType = self.settings.get(in_key, None)
    # dp(f"apply_config_template: in_key=\"{in_key}\", out_key=\"{out_key}\", v={json.dumps(v)}")

    if isinstance(v, str) and v == '':
      v = None

    if not v is None:
      output[out_key] = v

  def build_stack_data(self) -> JSONDictType:
    cfg: JSONDictType = {}
    for template in self.stack_config_templates:
      self.apply_config_template(cfg, template)
    result: JSONDictType = {
        'config': cfg,
      }
    return result
