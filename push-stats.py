#!/usr/bin/env python
# msr-push-stats
# Determine total amount of image data pushed on a per user basis against an
# MSR 2 environment.
# Kyle Squizzato <ksquizzato@mirantis.com>

import argparse
import docker
import logging
import requests
import subprocess
import sys
import humanize
import json

from logrusformatter import LogrusFormatter


"""
setup defines the global values used for querying Rethink.
"""
def setup():
    logging.debug("Setting up DockerClient and RethinkCLI prerequisites")
    try:
        cli = docker.from_env()
    except docker.errors.DockerException as e:
        logging.error("Failed to get DockerClient from client bundle: {0}".format(e))
        logging.info("Ensure a client bundle has been downloaded and DOCKER_HOST=tcp://example.com, DOCKER_CERT_PATH=/certs, DOCKER_TLS_VERIFY=1 are properly set")
        sys.exit(1)
    try:
        db_addr = cli.info()["Swarm"]["NodeAddr"]
        logging.debug("Setting db_addr to {0}".format(db_addr))
    except docker.errors.APIError as e:
        logging.error("Failed to determine MKE db address: {0}".format(e))
        sys.exit(1)
    try:
        replica_id = cli.containers.list(filters={"name":"dtr-rethinkdb"})[0].name
        logging.debug("Using container name for replica_id: {0}".format(replica_id))
    except docker.errors.APIError as e:
        logging.error("Failed to determine MSR replica id: {0}".format(e))
        sys.exit(1)
    replica_id = replica_id.split("-")[-1]
    logging.debug("Setting replica_id to {0}".format(replica_id))
    if replica_id == "":
        logging.error("Failed to get replica_id value from container name: {0}".format(e))
        sys.exit(1)
    return cli, replica_id, db_addr

"""
check_for_rethinkcli check's to ensure the rethinkcli images are present and
obtainable.
"""
def check_for_rethinkcli(cli):
    # Check to see if dockerhubenterprise/rethinkcli:v2.2.0-ni is present by
    # pulling the image, if we can't fetch it assume disconnected.
    try:
        # Pull the images
        logging.debug("Pulling RethinkCLI images")
        cli.images.pull("dockerhubenterprise/rethinkcli", tag="v2.2.0-ni")
        cli.images.pull("squizzi/rethinkcli-ucp", tag="latest")
    except docker.errors.APIError as e:
        logging.error("Unable to pull rethinkcli image: {0}".format(e))
        logging.info("Cannot continue without rethinkcli image -- If you are running in a disconnected environment please 'docker load' the dockerhubenterprise/rethinkcli:v2.2.0-ni and squizzi/rethinkcli-ucp images")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        logging.error("Failed to connect to DockerClient: {0}".format(e))
        sys.exit(1)

def query_msr_rethink(command, replica_id):
    logging.debug("Querying MSR rethink replica: {0} with command: {1}".format(replica_id, command))
    try:
        reql_result = subprocess.check_output("echo \"{0}\" | docker run -i --rm --net dtr-ol -e DTR_REPLICA_ID={1} -v dtr-ca-{1}:/ca dockerhubenterprise/rethinkcli:v2.2.0-ni non-interactive; echo".format(command, replica_id),
            shell=True,
            encoding="utf-8")
    except subprocess.CalledProcessError as e:
        logging.error("Unable to query MSR rethink: {0}".format(e))
        sys.exit(1)
    return reql_result.rstrip()

def query_mke_rethink(command, db_addr):
    logging.debug("Querying MKE rethink: {0} with command: {1}".format(db_addr, command))
    try:
        reql_result = subprocess.check_output("echo \"{0}\" | docker run -i --rm -e DB_ADDRESS={1} -v ucp-auth-api-certs:/tls squizzi/rethinkcli-ucp non-interactive; echo".format(command, db_addr),
            shell=True,
            encoding="utf-8")
    except subprocess.CalledProcessError as e:
        logging.error("Unable to query MKE rethink: {0}".format(e))
        sys.exit(1)
    return reql_result.rstrip()

"""
query_push_stats queries RethinkDB for push statistics for a given username.
Returns userid and the result of the query.
"""
def query_push_stats(username, replica_id, db_addr):
    logging.debug("Querying Rethink for push stats for username: {0}".format(username))
    userid = query_mke_rethink("r.db('enzi').table('accounts').get('{0}')('id')".format(username), db_addr)
    if userid == "":
        logging.error("Failed to determine user id from username: {0}".format(username))
        sys.exit(1)
    result = query_msr_rethink("var digests = r.db('dtr2').table('tags').filter({{'authorNamespace': '{0}'}})('digestPK').coerceTo('array').distinct(); r.db('dtr2').table('manifests').getAll(r.args(digests))('size').sum()".format(userid), replica_id)
    return userid, result

"""
query_user_list iterates a list of users and calls query_push_stats against
each user.  If format_json is set to True, return a json formatted entry via
result_to_json.
"""
def query_user_list(user_list, replica_id, db_addr, humanize_size=True, format_json=False):
    logging.debug("Querying list of users: {0} with humanize_size={1}, format_json={2}".format(user_list, humanize_size, format_json))
    data = []
    for user in user_list:
        userid, result = query_push_stats(user, replica_id, db_addr)
        if humanize_size:
            result = humanize.naturalsize(result)
        else:
            result = int(result)
        if not format_json:
            print(
"""
Username: {0}
Id: {1}
Pushed data: {2}
""".format(user, userid, result))
        else:
            json_result = result_to_json(userid, user, result)
            logging.debug("Appending json result: {0} to data set".format(json_result))
            data.append(json_result)
    # Print the final comprised json data if format_json is True.
    if format_json:
        print(json.dumps(data, indent=4))

"""
result_to_json formats output of statistics as a json:
{
    username: example,
    id: 12345,
    pushed_data: 500,
}
"""
def result_to_json(userid, user, result):
    v = {
        "username": user,
        "id": userid.strip('\"'),
        "pushed_data": result,
    }

    return v

def main():
    parser = argparse.ArgumentParser(
        description="Determine blob push statistics per user for Mirantis \
        Secure Registry (MSR) 2.x. Not intended for use against MSR 3.",
        )
    parser.add_argument("-u",
                        "--users",
                        dest="user_list",
                        required=True,
                        action="extend",
                        nargs="+",
                        type=str,
                        help="Provide a space-delmited list of users to lookup \
                        push statistics against.")
    parser.add_argument("--bytes",
                        dest="bytes",
                        action="store_true",
                        help="Print the pushed data size results in bytes \
                        (Default: humanized size values)")
    parser.add_argument("--json",
                        dest="output_json",
                        action="store_true",
                        help="Output statistic data in json format.")
    parser.add_argument("--debug",
                        dest="debug",
                        action="store_true",
                        help="Enable debug logging")
    parser.add_argument("--no-image-check",
                        dest="no_image_check",
                        action="store_true",
                        help="Disable automatic image checking and pulling \
                        for the RethinkCLI image.")
    args = parser.parse_args()
    # Basic logging that matches logrus format.
    fmt_string = "%(levelname)s %(message)-20s"
    fmtr = LogrusFormatter(colorize=True, fmt=fmt_string)
    logger = logging.getLogger(name=None)
    logger.setLevel(logging.INFO)
    if args.debug:
        logger.setLevel(logging.DEBUG)
    hdlr = logging.StreamHandler(sys.stdout)
    hdlr.setFormatter(fmtr)
    logger.addHandler(hdlr)
    # Setup DockerClient, RethinkCLI images.
    cli, replica_id, db_addr = setup()
    # Check for a rethinkcli image.
    if not args.no_image_check:
        check_for_rethinkcli(cli)
    # Query provided user list.
    humanize_size = True
    if args.bytes:
        humanize_size = False
    query_user_list(args.user_list, replica_id, db_addr, humanize_size, args.output_json)
    sys.exit(0)

"""
Main
"""
if __name__ == '__main__':
    sys.exit(main())
