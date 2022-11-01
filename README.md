# Mirantis Secure Registry Push Statistics
This script can be used to determine total amount of image data pushed on a
per user basis.  This script is intended to be used against MSR 2.x environments
and does not work against MSR 3.

> Note: The provided information from this script will show the amount of pushed
> data per user, but **it will not indicate total data consumed.**  Blobs in MSR
> are shared, meaning that user1 and user2 could push the same image, have the
> same image associated with their accounts but the total consumption of those
> images on the backend blob store would be the size of the single image.

## Usage
1. Download an [MKE client bundle for the environment](https://docs.mirantis.com/mke/3.6/ops/access-cluster/client-bundle/download-client-bundle.html).
2. Extract the client bundle into a new directory, for example: `mke-clientbundle` and `cd` into the directory.
3. Check the included `env.sh` file inside the client bundle directory to
determine what to set needed environment vars to:

```
$ cat env.sh
export DOCKER_TLS_VERIFY=1
export COMPOSE_TLS_VERSION=TLSv1_2
export DOCKER_CERT_PATH=$PWD
export DOCKER_HOST=tcp://123.456.21.234:443
```

4. Run the script via the docker image: `squizzi/msr-push-stats`, ensuring
the environment variables from the client bundle are used:

```
docker run --rm -it \
    -v $PWD:/certs \
    -e DOCKER_HOST=tcp://123.456.21.234:443\
    -e DOCKER_CERT_PATH=/certs \
    -e DOCKER_TLS_VERIFY=1 \
    squizzi/msr-push-stats -u user1 user2 user3
```

### Optional arguments
* `--bytes`: Print the pushed data size results in bytes (Default: humanized size values)
* `--json`: Output statistic data in json format.
* `--debug`: Enable debug logging.
* `--no-image-check`: Disable automatic image checking and pulling for the RethinkCLI images.
