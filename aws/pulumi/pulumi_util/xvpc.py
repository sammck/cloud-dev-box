#!/usr/bin/env python3

import subprocess
import os
import json
import ipaddress

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


class XVpc(pulumi.ComponentResource):
    def __init__(self, name, opts = None):
        super().__init__('pkg:index:XPpc', name, None, opts)
