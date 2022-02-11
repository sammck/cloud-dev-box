#!/usr/bin/env python3

from typing import Optional, Any, Dict, Tuple, List, Union, Sequence

import subprocess
import os
import json
import ipaddress
import yaml
from docker import APIClient
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

from pulumi_util.util import (
  TTL_SECOND,
  TTL_MINUTE,
  TTL_HOUR,
  TTL_DAY,
  jsonify_promise,
  yamlify_promise,
  list_of_promises,
  default_val,
)

#-----------------------------------------------------
DEFAULT_CIDR: str = '10.77.0.0/16'
DEFAULT_N_AZS: int = 3
DEFAULT_N_POTENTIAL_SUBNETS: int = 16
#-----------------------------------------------------

config = pulumi.Config()

#num_auth_instances = default_val(config.get_int('num_auth_instances'), 1) # simpler and cheaper to debug with 1 container. Scale up for prod. During update, temporarily there will be 2x
long_stack = f"{pulumi.get_project()}-{pulumi.get_stack()}"
stack_short_prefix = pulumi.get_stack()[:5] + '-'

global_region: str = 'us-east-1'
region: Output[str] = aws.get_region().name

caller_identity = aws.get_caller_identity()
account_id: str = caller_identity.account_id

# We create a seperate AWS pulumi provider bound to us-east-1 because certain AWS resources must be provisioned in that region (e.g., cloudfront
# certificates)
global_aws = aws.Provider('aws-%s' % global_region, region=global_region)
resource_options_global_aws = ResourceOptions(provider=global_aws)

owner_tag: str = default_val(config.get('owner'), 'sammck@gmail.com')

default_tags: Dict[str, str] = dict(Owner=owner_tag, PulumiStack=long_stack, Project="apitest")

def with_default_tags(*args: Union[Dict[str, str], Sequence[Tuple[str, str]]], **kwargs: str) -> Dict[str, str]:
  result = dict(default_tags)
  result.update(*args, **kwargs)
  return result


n_azs: int = default_val(config.get_int('n_azs'), DEFAULT_N_AZS) # The number of AZs that we will provision our vpc in

azs: List[str] = sorted(aws.get_availability_zones().names)[:n_azs]

vpc_cidr: str = default_val(config.get('vpc_cidr'), DEFAULT_CIDR)
vpc_ip_network: ipaddress.IPv4Network = ipaddress.ip_network(vpc_cidr)
max_n_subnet_id_bits = 32 - vpc_ip_network.prefixlen
n_potential_subnets: int = default_val(config.get('n_potential_subnets'), DEFAULT_N_POTENTIAL_SUBNETS)
if n_potential_subnets < 8 or n_potential_subnets > (1 << 31) or (n_potential_subnets & (n_potential_subnets - 1)) != 0:
  raise RuntimeError("Config value n_potential_subnets must be a power of 2 >= 8: %d" % n_potential_subnets)
n_subnet_id_bits: int = 0
x = n_potential_subnets
while x > 1:
  x //= 2
  n_subnet_id_bits += 1
if n_subnet_id_bits > max_n_subnet_id_bits:
  raise RuntimeError("Config value n_potential_subnets is greater than maximum allowed (%d) by vpc CIDR %s: %d" % (1 << max_n_subnet_id_bits, vpc_cidr, n_potential_subnets))

vpc_potential_subnet_ip_networks = list(vpc_ip_network.subnets(prefixlen_diff=n_subnet_id_bits))
public_subnet_ip_networks = vpc_potential_subnet_ip_networks[:n_azs]
private_subnet_ip_networks = vpc_potential_subnet_ip_networks[n_potential_subnets//2:n_potential_subnets//2+n_azs]

public_subnet_cidrs = [str(x) for x in public_subnet_ip_networks]
private_subnet_cidrs = [str(x) for x in private_subnet_ip_networks]

zone_name: Optional[str] = config.get('zone_name')
if zone_name is None:
  parent_zone_name: str = default_val(config.get('parent_zone_name'), 'mckelvie.org')
  zone_prefix: str = default_val(config.get('zone_prefix'), pulumi.get_stack())
  zone_name = f"{zone_prefix}.{parent_zone_name}"
else:
  zone_prefix, parent_zone_name = zone_name.split('.', 1)


# create a VPC that our whole stack and dependent services will run in
vpc = ec2.Vpc(
  'vpc',
  cidr_block=vpc_cidr,
  enable_dns_hostnames=True,
  enable_dns_support=True,
  tags=default_tags
)

# create public subnets in separate AZs
public_subnets: List[ec2.Subnet] = []
for i, cidr in enumerate(public_subnet_cidrs):
  public_subnets.append(
    ec2.Subnet(
      'public-subnet-%d' % i,
      availability_zone=azs[i],
      vpc_id=vpc.id,
      cidr_block=cidr,
      map_public_ip_on_launch=True,
      tags=default_tags
    )
  )

public_subnet_ids: List[Output[str]] = [  x.id for x in public_subnets ]

# create private subnets in separate AZs.
# TODO: currently these are the same as public subnets. We can change
# that with a NAT gateway, no-assign public IP, and network ACLs.
private_subnets: List[ec2.Subnet] = []
for i, cidr in enumerate(private_subnet_cidrs):
  private_subnets.append(
    ec2.Subnet(
      'private-subnet-%d' % i,
      availability_zone=azs[i],
      vpc_id=vpc.id,
      cidr_block=cidr,
      map_public_ip_on_launch=True,   # review: probably want to use NAT gateway for private subnets...?
      tags=default_tags
    )
  )

private_subnet_ids: List[Output[str]] = [ x.id for x in private_subnets ]

# convenient list of all subnets, public and private
subnets = public_subnets + private_subnets
subnet_ids = [ x.id for x in subnets ]

# Create an internet gateway to route internet traffic to/from public IPs attached to the VPC
internet_gateway = ec2.InternetGateway('vpc-gateway', tags=default_tags, vpc_id=vpc.id)

# Create a default route table for the VPC that routes everything inside the VPC CIDR locally,
# and everything else to the internet through the internet gateway
# TODO: provide direct VPC routing to AWS services
route_table = ec2.DefaultRouteTable(
  "route-table",
  default_route_table_id=vpc.default_route_table_id,
  routes=[
    dict(cidr_block="0.0.0.0/0", gateway_id=internet_gateway.id)
  ],
  tags=default_tags
)

# Attach all subnets to our default route table
route_table_associations: List[ec2.RouteTableAssociation] = []
for i, subnet in enumerate(subnets):
  route_table_associations.append(
    ec2.RouteTableAssociation(
      "default-route-table-association-%d" % i,
      route_table_id=route_table.id,
      subnet_id=subnet.id
    )
  )

# Get the parent DNS zone under which our subzone will be created. The parent zone is
# not managed by this stack, but must be a Route53 zone.  E.g., "mckelvie.org". We will
# create An NS record in this parent zone that points to our subzone.
public_parent_zone = route53.get_zone(name=parent_zone_name, private_zone=False)

# Create a public DNS zone for us to use; e.g., apitest.mckelvie.org
public_zone = route53.Zone(
  'public-zone',
  # opts=,
  comment='Public zone for pulumi stack %s' % long_stack,
  delegation_set_id=None,
  force_destroy=True,
  name=zone_name,
  tags=default_tags,
  # vpcs=None,
)

# Create an NS record in the parent zone that points to our zone's name servers.
public_parent_zone_ns_record = route53.Record(
  'public-parent-zone-ns-record',
  # opts=None,
  # aliases=None, 
  # allow_overwrite=None, 
  # failover_routing_policies=None,
  # geolocation_routing_policies=None, 
  # health_check_id=None, 
  # latency_routing_policies=None, 
  # multivalue_answer_routing_policy=None, 
  name=zone_name, 
  records=public_zone.name_servers,
  # set_identifier=None, 
  ttl=TTL_MINUTE * 10,
  type='NS',
  # weighted_routing_policies=None,
  zone_id=public_parent_zone.zone_id
)

# Create a security group for the front-end EC2 instance, that allows it to
# listen on port 22 (SSH), 80 (HTTP), and 443 (HTTPS), and send anywhere.
front_end_security_group = ec2.SecurityGroup(
  'front-end-security-group',
  opts=None,
  description='%s front-end security group. Public SSH, HTTP, and HTTPS' % long_stack,
  egress=[
    dict(
      cidr_blocks=[ '0.0.0.0/0' ],
      description="IPV4 ANY",
      protocol='tcp',
      from_port=1,
      to_port=65534
    ),
  ],
  ingress=[
    dict(
      cidr_blocks=[ '0.0.0.0/0' ],
      description="IPV4 SSH",
      protocol='tcp',
      from_port=22,
      to_port=22
    ),
    dict(
      cidr_blocks=[ '0.0.0.0/0' ],
      description="IPV4 HTTP",
      protocol='tcp',
      from_port=80,
      to_port=80
    ),
    dict(
      cidr_blocks=[ '0.0.0.0/0' ],
      description="IPV4 HTTPS",
      protocol='tcp',
      from_port=443,
      to_port=443
    )
  ],
  # name=None,
  name_prefix=long_stack + '-',
  # revoke_rules_on_delete=None,
  tags=default_tags,
  vpc_id=vpc.id
)

# Create an IAM policy to constrain what our front-end EC2 instance is allowed to do.
front_end_role_policy_obj = {
    "Version": "2012-10-17",
    "Statement": [

        # Nondestructive EC2 queries
        {
            "Action": ["ec2:Describe*"],
            "Effect": "Allow",
            "Resource": "*",
          },

        # Read-only access to ECR, to fetch docker images
        {
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:DescribeRepositories",
                "ecr:BatchGetImage",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
              ],
            "Effect": "Allow",
            "Resource": "*",
          },

      ],
  }

front_end_role_policy = aws.iam.Policy(
    "front-end-role-policy",
    path="/",
    description=f"Custom role policy for {long_stack} front end instance",
    policy=json.dumps(front_end_role_policy_obj, sort_keys=True)
  )

# define a policy that allows EC2 to assume our roles for the purposes of creating EC2 instances
ec2_assume_role_policy_obj = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Principal": {
               "Service": "ec2.amazonaws.com",
            },
            "Effect": "Allow",
            "Sid": "",
          },
      ],
  }


# Create an IAM role for ourFront end EC2 instance to run in. Allow it to read the db password secret.
front_end_role = iam.Role(
  'front-end-role',
  # opts=None,
  assume_role_policy=json.dumps(ec2_assume_role_policy_obj, sort_keys=True),
  description="Front-end EC2 instance role in Pulumi stack %s" % long_stack,
  # force_detach_policies=None,
  max_session_duration=12*TTL_HOUR,
  name='%s-front-end-role' % long_stack,
  # name_prefix=None,
  path='/pstack=%s/' % long_stack,
  # permissions_boundary=None,
  tags=default_tags
)

# keep track of things we want to finish doing before we launch the EC2 instance
front_end_dependencies: List[Output] = []

# Attach policy to the EC2 instance role to allow cloudwatch monitoring.
front_end_cloudwatch_agent_attached_policy = aws.iam.RolePolicyAttachment(
    'front-end-attached-policy-cloudwatch-agent',
    role=front_end_role.name,
    policy_arn="arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
  )
front_end_dependencies.append(front_end_cloudwatch_agent_attached_policy)

# Attach policy to the EC2 instance role to allow SSM management.
front_end_ssm_attached_policy = aws.iam.RolePolicyAttachment(
    'front-end-attached-policy-ssm-managed',
    role=front_end_role.name,
    policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
  )
front_end_dependencies.append(front_end_ssm_attached_policy)

# Attach our custom policy to the EC2 instance role.
front_end_attached_policy = aws.iam.RolePolicyAttachment(
    'front-end-attached-policy',
    role=front_end_role.name,
    policy_arn=front_end_role_policy.arn,
  )
front_end_dependencies.append(front_end_attached_policy)

# create an instance profile for our front-end that allows it to assume our front-end role
front_end_instance_profile = aws.iam.InstanceProfile(
    "front-end-instance-profile",
    role=front_end_role.name,
    tags=default_tags,
  )

# select an EC2 instance type for the front end
ec2_front_end_instance_type = default_val(config.get('front_end_instance_type'), 't3.medium')

# select the root volume size for the front end
front_end_root_volume_size_gb: int = default_val(config.get_int('front_end_root_volume_size_gb'), 40)

# create an EC2 keypair to allow SSH login to the front-end
front_end_shh_public_key = config.get('front_end_ssh_public_key')
if front_end_shh_public_key is None:
  front_end_shh_public_key_file: str = default_val(config.get('front_end_ssh_public_key_file'), '~/.ssh/id_rsa.pub')
  front_end_shh_public_key_file = os.path.expanduser(front_end_shh_public_key_file)
  with open(front_end_shh_public_key_file) as f:
    front_end_shh_public_key = f.read().rstrip()

front_end_keypair = aws.ec2.KeyPair(
    'front-end-keypair',
    key_name_prefix='front-end-',
    public_key=front_end_shh_public_key,
    tags=default_tags,
  )

AMI_OWNER_CANONICAL: str = "099720109477"  # The publisher of Ubunti AMI's

# Find the most recent AMI for Ubuntu 20.04
ubuntu = aws.ec2.get_ami(
    most_recent=True,
    filters=[
        aws.ec2.GetAmiFilterArgs(
            name="name",
            values=[ "ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*" ],
          ),
        aws.ec2.GetAmiFilterArgs(
            name="virtualization-type",
            values=[ "hvm" ],
          ),
      ],
    owners=[AMI_OWNER_CANONICAL],
  )

# Create an elastic IP address for the front end. This allows the IP address to remain stable even if the instance is
# shut down and restarted, or even destroyed and recreated. Prevents DNS entries and caches from becoming invalid.
front_end_eip = aws.ec2.Eip(
    'front-end-eip',
    vpc=True,
    tags=with_default_tags(Name=zone_name),
  )
front_end_dependencies.append(front_end_eip)

# Create a special Route53 "alias" DNS entry for "<zone>" that
# makes the bare zone DNS name work and route to the front-end as well.
# This special entry *MUST* be an A record--CNAME is not allowed zone default routes.
front_end_bare_dns_entry = route53.Record(
  'front-end-bare-dns-record',
  # opts=None,
  # aliases=None,
  # allow_overwrite=None, 
  # failover_routing_policies=None, 
  # geolocation_routing_policies=None, 
  # health_check_id=None, 
  # latency_routing_policies=None, 
  # multivalue_answer_routing_policy=None, 
  name=zone_name, 
  records=[ front_end_eip.public_ip ],
  # set_identifier=None, 
  ttl=TTL_MINUTE * 10,
  type='A',
  # weighted_routing_policies=None,
  zone_id=public_zone.zone_id
)
front_end_dependencies.append(front_end_bare_dns_entry)

# We will now create all of our service domain names that point at the front-end box.
# We will create a single A record for "fe.<zone>"  (the front-end box).
# All other domain names will ne CNAME records that point at "fe.<zone>".
front_end_fqdn = f"fe.{zone_name}"

subdomain_records: Dict[str, route53.Record] = {}

subdomain_records["fe"] = route53.Record(
  'fe-dns-record',
  # opts=None,
  # aliases=None,
  # allow_overwrite=None, 
  # failover_routing_policies=None, 
  # geolocation_routing_policies=None, 
  # health_check_id=None, 
  # latency_routing_policies=None, 
  # multivalue_answer_routing_policy=None, 
  name=front_end_fqdn, 
  records=[ front_end_eip.public_ip ],
  # set_identifier=None, 
  ttl=TTL_MINUTE * 10,
  type='A',
  # weighted_routing_policies=None,
  zone_id=public_zone.zone_id
)
front_end_dependencies.append(subdomain_records["fe"])

for subdomain_name in ["monitor", "db-admin", "blog", "www"]:
  fqdn = f"{subdomain_name}.{zone_name}"
  subdomain_records[subdomain_name] = public_db_dns_entry = route53.Record(
      f"{subdomain_name}-dns-record",
      # opts=None,
      # aliases=None, 
      # allow_overwrite=None, 
      # failover_routing_policies=None, 
      # geolocation_routing_policies=None, 
      # health_check_id=None, 
      # latency_routing_policies=None, 
      # multivalue_answer_routing_policy=None, 
      name=fqdn, 
      records=[ front_end_fqdn ],
      # set_identifier=None, 
      ttl=TTL_MINUTE * 10,
      type='CNAME',
      # weighted_routing_policies=None,
      zone_id=public_zone.zone_id              # TODO: if we implement a private internal zone, this could go there
    )
  front_end_dependencies.append(subdomain_records[subdomain_name])

front_end_subnet = public_subnets[0]

# Create an Elastic Container Registry (ECR) repository to hold our bootstrap docker image
front_end_bootstrap_repo_name = '%s-front-end-bootstrap' % long_stack
front_end_bootstrap_repo_tag = "latest"
front_end_bootstrap_repo = aws.ecr.Repository(
    "front-end-bootstrap-ecr-repository",
    name=front_end_bootstrap_repo_name,
    image_scanning_configuration=aws.ecr.RepositoryImageScanningConfigurationArgs(
        scan_on_push=True,
    ),
    image_tag_mutability="MUTABLE",
    tags=default_tags,
  )
ecr_domain: Output[str] = account_id + ".dkr.ecr." + region + ".amazonaws.com"
front_end_bootstrap_full_repo_name: Output[str] = ecr_domain + "/" + front_end_bootstrap_repo_name + ":" + front_end_bootstrap_repo_tag

# build an amd64 version of the bootstrap image, push it to the ECR repository, and
# compute the fully hashed image name. This function returns a future that builds
# and pushes the image after the fully qualified repository name is known.
def get_hashed_bootstrap_image_url() -> Output[str]:
  def gen_hashed_bootstrap_image_url(repository_name: str, repository_url: str, region: str, tag: str) -> str:
    local_image = f"{repository_name}:{tag}"
    image_url = f"{repository_url}:{tag}"

    subprocess.call(['docker', 'buildx', 'create', '--name', 'amd64-arm64'], stderr=subprocess.DEVNULL)
    subprocess.check_call(
        [
            'docker', 'buildx', 'build', '--builder', 'amd64-arm64',
            '-t', image_url,
            '--platform', 'linux/amd64,linux/arm64',
            '--push',
            '.'
          ]
      )    
    manifest_json = subprocess.check_output(['docker', 'manifest', 'inspect', image_url]).decode('utf-8')
    multi_manifest = json.loads(manifest_json)
    arch_manifests: Dict[str, Any] = {}
    for arch_manifest in multi_manifest['manifests']:
      platform: Dict[str, str] = arch_manifest['platform']
      if platform['os'] == 'linux':
        arch = platform['architecture']
        if arch in arch_manifests:
          raise RuntimeError(f"Architecture \"{arch}\" has multiple manifest images for {image_url}")
        arch_manifests[arch] = arch_manifest
    if 


    return hashed_image_url

  result = Output.all(
      front_end_bootstrap_repo.name,
      front_end_bootstrap_repo.repository_url,
      region,
      front_end_bootstrap_repo_tag
    ).apply(lambda args: gen_hashed_bootstrap_image_url(*args))
  return result

hashed_auth_image_url = get_hashed_auth_image_url()

front_end_dependencies.append(front_end_bootstrap_repo)


# create a cloud-config document to attach as user-data to the new ec2 instance.
# we create a sync function to generate the document when all needed outputs have values, and wrap it as a future that can consume outputs. 
def gen_frontend_cloud_config_obj(
      zone_name: str,
      region: str,
      ecr_domain: str,
      bootstrap_repo_name: str,
      bootstrap_repo_tag: str
    ) -> dict:
  docker_config_obj = {
      "credHelpers": {
          "public.ecr.aws": "ecr-login",
          ecr_domain: "ecr-login"
        }
    }
  full_repo_and_tag = f"{ecr_domain}/{bootstrap_repo_name}:{bootstrap_repo_tag}"
  docker_config = json.dumps(docker_config_obj, indent=1, sort_keys=True)
  config_obj = dict(
      repo_update = True,
      repo_upgrade = "all",
      fqdn = f"fe.{zone_name}",
      apt = dict(
          sources = {
            "docker.list": dict(
                source = "deb [arch=amd64] https://download.docker.com/linux/ubuntu $RELEASE stable",
                keyid = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
              ),
            },
        ),

      packages = [
          "jq",
          "awscli",
          "collectd",
          "ca-certificates",
          "curl",
          "gnupg",
          "lsb-release",
          "docker-ce",
          "docker-ce-cli",
          "amazon-ecr-credential-helper",
        ],

      runcmd = [
          [ "bash", "-c", f"mkdir -p /root/.docker && chmod 700 /root/.docker && echo '{docker_config}' > /root/.docker/config.json && chmod 600 /root/.docker/config.json" ],
          [ "docker", "pull", full_repo_and_tag ],
          [ "docker", "run", "--rm", "-v", "/:/host-rootfs", "--privileged", "--net=host", full_repo_and_tag ],
          [ "bash", "-c", 'echo "it works!"' ],
        ],
    )
  return config_obj

def gen_future_frontend_cloud_config_obj(
    zone_name: Union[str, Output[str]],
    region: Union[str, Output[str]],
    ecr_domain: Union[str, Output[str]],
    bootstrap_repo_name: Union[str, Output[str]],
    bootstrap_repo_tag: Union[str, Output[str]],
  ) -> Output[dict]:
  # "pulumi.Output.all(*future_args).apply(lambda args: sync_func(*args))"" is a pattern
  # provided by pulumi. It waits until all promises in future_args have been satisfied,
  # then invokes sync_func with the realized values of all the future_args as *args. Finally
  # it wraps the synchronous function as a promise and returns the new promise as the result.
  # this allows you to write synchronous code in pulumi that depends on future values, and
  # turn it into asynchronous code
  future_obj = Output.all(
        zone_name, region, ecr_domain, bootstrap_repo_name, bootstrap_repo_tag
    ).apply(lambda args: gen_frontend_cloud_config_obj(*args))
  return future_obj

future_frontend_cloud_config_obj = gen_future_frontend_cloud_config_obj(
    zone_name=zone_name,
    region=region,
    ecr_domain=ecr_domain,
    bootstrap_repo_name=front_end_bootstrap_repo_name,
    bootstrap_repo_tag=front_end_bootstrap_repo_tag,
  )

frontend_cloud_config = yamlify_promise(
    future_frontend_cloud_config_obj,
    indent=1,
    default_flow_style=None,
    width=10000,
    prefix_text="#cloud-config\n",
  )

# Create an EC2 instance for our front-end
front_end_ec2_instance = aws.ec2.Instance(
    'ec2-front-end-v1',
    opts=ResourceOptions(depends_on=front_end_dependencies),
    ami=ubuntu.id,
    instance_type=ec2_front_end_instance_type,
    iam_instance_profile=front_end_instance_profile.name,
    key_name=front_end_keypair.key_name,
    associate_public_ip_address=False,  # deferred until EIP is assigned
    subnet_id=front_end_subnet,
    vpc_security_group_ids=[ front_end_security_group.id ],
    root_block_device=dict(volume_size=front_end_root_volume_size_gb),
    user_data=frontend_cloud_config,
    tags=with_default_tags(Name=zone_name),
    volume_tags=with_default_tags(Name=zone_name),
  )

# associate the EIP with the instance. Unfortunately, this cannot be done prior to launch. Downstream
# resources should include a dependency on this association if they want access to the instance.
front_end_eip_assoc = aws.ec2.EipAssociation(
    "front-end-eip-assoc",
    instance_id=front_end_ec2_instance.id,
    allocation_id=front_end_eip.id
  )

pulumi.export('vpc_id', vpc.id)
pulumi.export('zone_name', zone_name)
pulumi.export('public_zone_id', public_zone.zone_id)
pulumi.export('public_parent_zone_id', public_parent_zone.zone_id)
pulumi.export('vpc_cidr', vpc_cidr)
pulumi.export('azs', azs)
pulumi.export('public_subnet_cidrs', public_subnet_cidrs)
pulumi.export('private_subnet_cidrs', private_subnet_cidrs)
pulumi.export('website_url', f"https://www.{zone_name}")
pulumi.export('traefik_admin_url', f"https://monitor.{zone_name}")
pulumi.export('db_admin_url', f"https://db-admin.{zone_name}")
pulumi.export('blog_url', f"https://blog.{zone_name}")
pulumi.export('front_end_public_ip', front_end_eip.public_ip)
pulumi.export('front_end_private_ip', front_end_ec2_instance.private_ip)
pulumi.export('front_end_subnet', front_end_subnet.id)
pulumi.export('front_end_subnet_cidr', front_end_subnet.cidr_block)
pulumi.export('front_end_instance_id', front_end_ec2_instance.id)
pulumi.export('front_end_az', front_end_ec2_instance.availability_zone)
pulumi.export('front_end_dns', f"fe.{zone_name}")
pulumi.export('front_end_ssh_public_key', front_end_shh_public_key)
pulumi.export('front_end_ssh_admin_username', "ubuntu")
pulumi.export('ecr_domain', ecr_domain)
pulumi.export('front_end_bootstrap_repo', front_end_bootstrap_repo.name)
pulumi.export('front_end_bootstrap_full_repo', front_end_bootstrap_full_repo_name)
