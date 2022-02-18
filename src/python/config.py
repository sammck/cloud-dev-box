#!/usr/bin/env python3

from typing import List, Optional, Dict, Any, Union, Callable, Tuple

#from dotenv import load_dotenv
from dynaconf import Dynaconf, Validator

import os
import sys
import json
import subprocess
import boto3
import boto3.session
import botocore.config
import pprint
import functools

from dynaconf.utils.parse_conf import jinja_env
from jinja2 import pass_eval_context, pass_context
import jinja2.runtime

_DEBUG: bool = False

if __name__ == "__main__":
  _DEBUG: bool = True

_DEBUG = True

def dp(*args, **kwargs):
  if _DEBUG:
    kwargs['file'] = sys.stderr
    print(*args, **kwargs)

dp(f"config.py file is {__file__}")

project_prefix = "DEVBOX"
project_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
dp(f"project dir is {project_dir}")
default_project_name = os.path.basename(project_dir)

def full_type_name(o):
  klass = o.__class__
  module = klass.__module__
  if module == 'builtins':
    return klass.__qualname__
  return module + '.' + klass.__qualname__

def _removeprefix(s: str, prefix: str) -> str:
  if s.startswith(prefix):
    s = s[len(prefix):]
  return s

def settings_func(func: Callable[..., str]) -> Callable[..., str]:
  @pass_context
  def wrapper(ctx: jinja2.runtime.Context, *args, **kwargs):
    settings: Dynaconf = ctx['this']
    result = func(ctx, settings, *args, **kwargs)
    return result
  fname: str = func.__name__
  fname = _removeprefix(fname, 'func_')
  
  jinja_env.globals[fname] = wrapper
  dp(f"Registered jinja function {fname}")
  return wrapper  

@settings_func
def func_get_project_dir(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  result = project_dir
  return result

@settings_func
def func_get_project_dir_basename(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  result = os.path.basename(project_dir)
  return result

@settings_func
def func_get_default_project_name(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  return default_project_name

@settings_func
def func_get_git_user_email(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  result = subprocess.check_output(['git', 'config', 'user.email']).decode('utf-8').rstrip()
  return result

@settings_func
def func_get_git_user_friendly_name(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  result = subprocess.check_output(['git', 'config', 'user.name']).decode('utf-8').rstrip()
  return result

_default_aws_region_cache: Dict[str, str] = {}  # cache mapping AWS profile name to a default region
@settings_func
def func_get_default_aws_region(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  aws_profile = settings.get('AWS_PROFILE', None)
  if aws_profile == '':
    aws_profile = 'default'
  region = _default_aws_region_cache.get(aws_profile, None)
  if region is None:
    dp(f"Fetching aws region for profile {aws_profile}")
    sess = boto3.session.Session(profile_name=aws_profile)
    region = sess.region_name
    if region is None or region == '':
      region = 'us-east-1'
    _default_aws_region_cache[aws_profile] = region
  return region

_aws_session_cache: Dict[Tuple[str, str], boto3.session.Session] = {}  # Cache mapping (profile, region) to a boto3 session
def get_aws_session(settings: Dynaconf) -> boto3.session.Session:
  aws_profile = settings.get('AWS_PROFILE', None)
  if aws_profile == '':
    aws_profile = 'default'
  aws_region = settings.get('AWS_REGION', None)
  if aws_region == '':
    aws_region = 'us-east-1'
  key = (aws_profile, aws_region)
  sess = _aws_session_cache.get(key, None)
  if sess is None:
    dp(f"Creating boto3 session for profile {aws_profile} in region {aws_region}")
    sess = boto3.session.Session(profile_name=aws_profile, region_name=aws_region)
    _aws_session_cache[key] = sess
  return sess

@settings_func
def func_get_default_aws_account(ctx: jinja2.runtime.Context, settings: Dynaconf) -> str:
  sess = get_aws_session(settings)
  account: Optional[str] = getattr(sess, 'aws_account_id', None)
  if account is None:
    dp(f"Fetching aws account for session {sess}, profile {sess.profile_name}, region {sess.region_name}")
    sts = sess.client('sts')
    resp = sts.get_caller_identity()
    account: str = resp['Account']
    if account == '':
      account = None
    if not account is None:
      sess.aws_account_id = account

  if account is None:
    account = ''
    
  return account

config_dir= os.path.join(project_dir, 'config')
_current_environment_file = os.path.join(config_dir, 'current-environment.txt')

current_environment = os.environ.get('ENV_FOR_DYNACONF', None);

if current_environment is None or current_environment == '':
  if os.path.exists(_current_environment_file):
    with open(_current_environment_file) as _f:
      current_environment =_f.read().rstrip()

if current_environment is None or current_environment == '':
  current_environment = 'development'

default_config_file = os.path.join(config_dir, 'default-config.toml')
config_files: List[str] = [ default_config_file ]
_dot_config_files: List[str] = []

for filename in sorted(os.listdir(config_dir)):
  if filename.endswith('.toml'):
    if filename.find('.local.') < 0:
      pathname = os.path.join(config_dir, filename)
      if filename.startswith('.'):
        if not pathname in _dot_config_files:
          _dot_config_files.append(pathname)
      else:
        if not pathname in config_files:
          config_files.append(pathname)

config_files.extend(_dot_config_files)

dp(f"Config files: {config_files}")

settings = Dynaconf(
    envvar_prefix=project_prefix,
    settings_files=config_files,
    environments=True,
    load_dotenv=True,
    env=current_environment,
    validators=[
        # Validator('OWNER_EMAIL', default=get_default_owner_email),
        # Validator('OWNER_NAME', default=get_default_owner_name),
        # Validator('AWS_PROFILE', default='default'),
        # Validator('AWS_REGION', default=get_default_aws_region),
        # Validator('AWS_ACCOUNT', default=get_default_aws_account),
      ],
  )

if _DEBUG and __name__ == "__main__":
  dp(f"Final settings for env \"{settings.current_env}\": {json.dumps(settings.as_dict(), indent=2)}")
