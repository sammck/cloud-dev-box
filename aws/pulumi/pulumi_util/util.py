#!/usr/bin/env python3

from typing import Any, List, Tuple, TypeVar, Optional

import subprocess
import os
import json
import ipaddress
import yaml

import pulumi
from pulumi import (
  ResourceOptions,
  Output,
)

import pulumi_aws as aws
from pulumi_aws import (
  ec2,
  route53,
  acm,
  cognito,
  ecs,
  ecr,
  elasticloadbalancingv2 as elbv2,
  iam,
  cloudwatch,
  rds,
  kms,
  secretsmanager,
)


TTL_SECOND: int = 1
TTL_MINUTE: int = TTL_SECOND * 60
TTL_HOUR: int = TTL_MINUTE * 60
TTL_DAY: int = TTL_HOUR * 24

def yamlify_promise(future_obj: Output[Any], indent: int=1, default_flow_style: Optional[bool]=None, width: int=80, prefix_text: Optional[str]=None) -> Output[str]:
  """Convert a Promise object to a Promise to yamlify the result of that Promise.
  
  An asyncronous (Promise) version of yaml.dumps() that operates on Pulumi output
  values that have not yet been evaluated. Sorts keys to provide stability of result strings.
  The result is another Pulumi output value that when evaluated will generate the
  yaml string associated with future_obj
  
  :param future_obj:     A Pulumi "output" value that is not yet evaluated
  :type future_obj: Pulumi promise
  :return: A Pulumi "output" value that will resolve to the yaml string corresponding to future_obj
  :rtype: Pulumi Promise
  """
  def gen_yaml(obj: Any) -> str:
    return prefix_text + yaml.dump(obj, sort_keys=True, indent=indent, default_flow_style=default_flow_style, width=width)

  # "pulumi.Output.all(*future_args).apply(lambda args: sync_func(*args))"" is a pattern
  # provided by pulumi. It waits until all promises in future_args have been satisfied,
  # then invokes sync_func with the realized values of all the future_args as *args. Finally
  # it wraps the synchronous function as a promise and returns the new promise as the result.
  # this allows you to write synchronous code in pulumi that depends on future values, and
  # turn it into asynchronous code
  result = Output.all(future_obj).apply(lambda args: gen_yaml(*args))
  return result


def jsonify_promise(future_obj: Output[Any]) -> Output[str]:
  """Convert a Promise object to a Promise to jsonify the result of that Promise.
  
  An asyncronous (Promise) version of json.dumps() that operates on Pulumi output
  values that have not yet been evaluated. Sorts keys to provide stability of result strings.
  The result is another Pulumi output value that when evaluated will generate the
  json string associated with future_obj
  
  :param future_obj:     A Pulumi "output" value that is not yet evaluated
  :type future_obj: Pulumi promise
  :return: A Pulumi "output" value that will resolve to the json string corresponding to future_obj
  :rtype: Pulumi Promise
  """
  def gen_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True)

  # "pulumi.Output.all(*future_args).apply(lambda args: sync_func(*args))"" is a pattern
  # provided by pulumi. It waits until all promises in future_args have been satisfied,
  # then invokes sync_func with the realized values of all the future_args as *args. Finally
  # it wraps the synchronous function as a promise and returns the new promise as the result.
  # this allows you to write synchronous code in pulumi that depends on future values, and
  # turn it into asynchronous code
  result = Output.all(future_obj).apply(lambda args: gen_json(*args))
  return result

def list_of_promises(promises: List[Output[Any]]) -> Output[List[Any]]:
  """Converts a list of promises into a promise to return a list of values
  
  :param promises: A list of promises
  :type promises: List[Output[Any]]
  :return: promise to return list
  :rtype: Output[List[Any]]
  """
  def gen_result(*args: Any) -> List[Any]:
    return list(args)

  return Output.all(*tuple(promises)).apply(lambda args: gen_result(*args))

T = TypeVar("T")
def default_val(x: Optional[T], default: Optional[T]) -> Optional[T]:
  if x is None:
    x = default
  return x

