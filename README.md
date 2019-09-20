# Principal Mapper

Principal Mapper (PMapper) is a script and library for identifying risks in the configuration of AWS Identity and 
Access Management (IAM) in an AWS account.

PMapper allows users to identify which IAM users and roles have access to certain actions and resources in an AWS 
account. This is important for ensuring that sensitive resources, such as S3 objects with PII, are isolated. 

PMapper creates a graph of an AWS account's IAM users and roles (principals). This graph, composed of nodes and edges, 
represents the different ways that one principal could access another. When running a query to determine if a 
principal has access to a certain action/resource, it also checks if the user or role could access other users or roles 
that have access to that action/resource. This catches scenarios such as when a user doesn't have direct access to an 
S3 object, but could launch an EC2 instance that has access to the S3 object.

# Installation

## Requirements

Principal Mapper is built using the `botocore` library and Python 3.5+. Python 2  is not supported. Principal Mapper 
also requires `pydot` (available on `pip`), and `graphviz` (available on Windows, macOS, and Linux from 
https://graphviz.org/ ).

## Installation from Pip

~~~bash
pip install principalmapper
~~~

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

To start, create a graph for an AWS account:

~~~bash
pmapper graph --create
~~~

This stores information locally on disk about all the IAM users, roles, groups, and policies in the account. Accounts 
that are already graphed can be found using:

~~~bash
pmapper graph --list
~~~

The account IDs that are printed can be used in other `pmapper` subcommands via the `--account` parameter.

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

# Find all principals that can escalate privileges
pmapper query "preset privesc *"
pmapper argquery --principal '*' --preset privesc

# Find all principals that PowerUser can access
pmapper query "preset connected user/PowerUser *"
pmapper argquery --principal user/PowerUser --resource '*' --preset connected

# Find all principals that can access PowerUser
pmapper query "preset connected * user/PowerUser"
pmapper argquery --principal '*' --resource user/PowerUser --preset connected
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

Interacting with the REPL is very similar to running multiple queries from the command-line:

~~~
repl> query "who can do s3:GetObject with *"
...
repl> argquery --principal "*" --preset privesc
~~~

## Visualization

PMapper includes a visualization feature, which draws a specified graph. This graph highlights principals with 
administrative privileges in blue, and principals that can escalate privileges in red. It supports SVG, PNG, and DOT 
file outputs. It uses `graphviz` in order to create the image. It can be used like so:

~~~bash
pmapper visualize --filetype png
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

1. The `--profile` argument, when specified, is checked first. If specified, PMapper grabs credentials from botocore 
for that profile name.
2. PMapper uses the `get_session()` function from `botocore.session`, which should grab credentials from the 
environment variables/metadata service/default profile.

For querying, REPL, visualization, and analysis, you can specify the `--account` argument with the 12-digit ID of the 
account to examine. This cannot be specified along with `--profile`. It directs PMapper to use that account 
for the command, rather that deriving the account from credentials.

# Library Use

Principal Mapper includes a library that can be used instead of the command-line interface. All functions and methods 
have type-hints and a small amount of documentation for reference. See [example_script.py](example_script.py) for 
an example.

Future major-version revisions (e.g. 1.X.X -> 2.0.0) of Principal Mapper may alter/remove functions/classes/methods. 
Minor-version revisions (e.g. 1.1.X -> 1.2.0) will not remove existing functions/classes/methods but may add new ones 
or alter their behaviors.

**Exception:** All instances of the `debug` parameter in all of the functions in this library, which is used by the 
`dprint` function, will eventually be removed as the logging bits are improved. Just keep the `debug` parameter out 
of your production code. `dprint` is gonna be replaced too.

## Packages of Interest

### Common

* `principalmapper.common`
   * Classes `Graph`, `Node`, `Edge`, `Group`, and `Policy`. These can be imported 
   straight through `principalmapper.common` with a single statement:
   
      ~~~python
      from principalmapper.common import Graph, Node, Edge
      ~~~

### Graphing

* `principalmapper.graphing.graph_actions`
   * function `get_existing_graph`: grabs a Graph object from disk, based on current botocore session or account ID, 
   from a standard location on-disk.
   * function `get_graph_from_disk`: grabs a Graph object from disk, user-specified directory.
* `principalmapper.graphing.gathering` 
   * function `create_graph`: generates Graph objects using a botocore Session object.
* `principalmapper.graphing.edge_identification` 
   * variable `checker_map`: a dictionary, the keys of which are services that this version of Principal Mapper can get 
   edge data from. This should always be updated with all services that are supported, and `checker_map.keys()` can 
   always be passed to `create_graph` without error.

### Querying

* `principalmapper.querying.query_interface`
   * function `search_authorization_for`: performs an expansive search to determine if a principal can make a given 
   AWS API call, or if the principal can access another that does have permission. Returns `QueryResult` objects 
   (defined in `principalmapper.querying.query_result`) with information on if the principal is authorized, or if 
   it has to chain through other principals with authorization.
   * function `local_check_authorization`: determines if a principal can make a given AWS API call, but **DOES NOT** 
   perform the expansive search of `search_authorization_for`.
   * function `local_check_authorization_handling_mfa`: determines if a principal can make a given AWS API call, 
   **DOES NOT** perform the expansive search of `search_authorization_for`, but **DOES** manipulate condition keys 
   to test if the AWS API call can be made with or without MFA. Note that you can achieve the same effect by calling 
   `local_check_authorization` and setting the multi-factor auth conditions.

### Visualizing

* `principalmapper.visualizing.graph_writer`:
   * function `handle_request`: creates an image file (PNG/SVG) or graph file (DOT)
   
### Analysis

* `principalmapper.analysis.find_risks`:
   * function `gen_findings_and_print`: dumps findings in markdown(text)/JSON format to stdout. Wraps around 
   `gen_report`, which can be used instead for custom formatting by pulling `Report` and `Finding` objects.
* `principalmapper.analysis.report`: 
   * class `Report`: a simple object containing metadata about generated findings (account ID, date, version of 
   PMapper).
* `principalmapper.analysis.finding`:
   * class `Finding`: a simple object containing data about a risk to the AWS account. 
   
### Utils

* `principalmapper.util.arns`:
   * functions prefixed with `get_`: extract a specific chunk of an ARN, like the account ID or region.
* `principalmapper.util.botocore_tools`:
   * function `get_session`: get a botocore Session object based on optional profile parameter.
* `principalmapper.util.storage`:
   * function `get_storage_root`: returns a path on disk that Principal Mapper will use for storing Graph data by 
   default. Output depends on OS.

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