# Principal Mapper

Principal Mapper (PMapper) is a script and library for identifying risks in the configuration of AWS Identity and 
Access Management (IAM) in an AWS account.

PMapper allows users to identify which IAM users and roles have access to certain actions and resources in an AWS 
account. This is important for ensuring that sensitive items such as S3 objects with PII are isolated.

PMapper creates a graph of an AWS account's IAM users and roles. This graph, composed of nodes and edges, represents 
the different ways that one node could access another. When running a query to determine if an IAM user or role has 
access to a certain action/resource, it also checks if the user or role could access other users or roles that have 
access to that action/resource. This catches scenarios such as when a user doesn't have direct access to an S3 object, 
but could launch an EC2 instance that has access to the S3 object.

# Installation

## Requirements

Principal Mapper is built using the `botocore` library and Python 3.5+. Python2  is not supported. Principal Mapper 
also requires `pydot` (available on `pip`), and `graphviz` (available on Windows, macOS, and Linux).

## Installation From Source Code

Clone the repository:

~~~bash
git clone git@github.com:nccgroup/PMapper.git
~~~

Then install with Pip:

~~~bash
cd PMapper
pip install .
~~~

# Usage

## Graphing

To start, create a graph for an AWS account.

~~~bash
pmapper graph --create
~~~

This stores information locally on disk about all the IAM users, roles, groups, and policies in the account.


## Querying

After creating a graph, write queries to learn more about which users and roles can access certain actions or resources.

~~~bash
pmapper argquery --action s3:GetObject --resource arn:aws:s3:::bucket/path/to/object 
~~~

`argquery` takes the elements to check for (principal, action, resource, conditions) as arguments of the `pmapper` 
command. When `--principal` is not specified, it runs the query for all IAM  users and roles in the account. When 
`--resource` is not specified, it defaults to the wildcard (`*`).

`query` parses a more human-readable input string into a query and returns the results.

~~~bash
pmapper query "who can do s3:GetObject with arn:aws:s3:::bucket/path/to/object"
~~~

There are two special queries, presets, available:

* `privesc`: Identify privilege escalation risks.
* `connected`: Identify which principals can access other principals.

These presets are accessible from `query` and `argquery`. See the following examples:

~~~bash
# Determine if PowerUser can escalate privileges
pmapper query "preset privesc user/PowerUser"
pmapper argquery --principal user/PowerUser --preset privesc

# Find all users that can escalate privileges
pmapper query "preset privesc *"
pmapper argquery --principal '*' --preset privesc

# Find all users that PowerUser can connect to
pmapper query "preset connected user/PowerUser *"
pmapper argquery --principal user/PowerUser --resource '*' --preset connected

# Find all users that can connect to PowerUser
pmapper query "preset connected * user/PowerUser"
pmapper argquery --principal * --resource user/PowerUser --preset connected
~~~

## REPL

The Read-Evaluate-Print-Loop (REPL) is a program for running several queries at once. The REPL has four commands:

* `query`: Executes human-readable queries.
* `argquery`: Executes queries with a set of parameters.
* `help`: Prints out information on how to use the REPL.
* `exit`: Exits the REPL (Ctrl+C should also work).

When the REPL is launched, it loads the data for a single graph and executes all queries against that graph. You can 
launch the repl like so:

~~~bash
pmapper repl
~~~

## Visualization

PMapper includes a visualization feature, which draws a specified graph. This graph highlights principals with 
administrative privileges in blue, and principals that can escalate privileges in red. It supports SVG, PNG, and DOT 
file outputs. It uses `graphviz` in order to create the image. It can be used like so:

~~~bash
pmapper visualize --filetype svg
~~~

![](example-viz.png)

## Analysis

PMapper provides analysis to identify risks with the configuration in an account. It provides details on the risk, what 
impact it could have on the account, which principals are affected, and a recommendation on how to mitigate the risk. 
The outputs from `analysis` can be in text or JSON format, and can be created with the following command:

~~~bash
pmapper analysis --output-type text
~~~

# Credentials and Global Parameters

PMapper grabs credentials in the following order:

1. The `--profile` argument, when specified, is checked first. If specified, PMapper gets credentials for the 
botocore profile with the same name. 
2. AWS Access Key Environment Variables (`AWS_ACCESS_KEY_ID`, etc.) is checked next.
3. The `default` botocore profile is used last.

For querying, REPL, visualization, and analysis, you can specify the `--account` argument with the 12-digit ID of the 
account being examined. This cannot be specified along with `--profile`. It directs PMapper to use that account 
for the command, rather that deriving the account from the credentials.

# License

    Copyright (c) NCC Group and Erik Steringer 2019. This file is part of Principal Mapper.

      Principal Mapper is free software: you can redistribute it and/or modify
      it under the terms of the GNU Affero General Public License as published by
      the Free Software Foundation, either version 3 of the License, or
      (at your option) any later version.

      Principal Mapper is distributed in the hope that it will be useful,
      but WITHOUT ANY WARRANTY; without even the implied warranty of
      MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
      GNU Affero General Public License for more details.

      You should have received a copy of the GNU Affero General Public License
      along with Principal Mapper.  If not, see <https://www.gnu.org/licenses/>.