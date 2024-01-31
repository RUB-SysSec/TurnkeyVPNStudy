## repro -- (re)active (pro)ber

This tool was created to help discover network misconfigurations (i.e., missing network filtering) on connected networks
that may lead to unexpected exposures on other networks and hosts on non-Internet routable address spaces.

The working principle behind this tool is straightforward:

1. Send trace routes (using mtr) and ping sweeps (using fping) towards a set of reserved, internal addresses and the Internet.
2. Listen for incoming packets for responses from hosts using internal, private addresses.
3. On receiving a packet from such an address, sweep the newly discovered network and its neighboring networks.
4. At the end, a JSON file with the results is printed out.

## Installation & usage

The simplest way to install this package is by using pip:

```
pip install -r requirements.txt
pip install -e .
```

To listen for incoming packets, the Python executable needs to have the capability to listen promiscuously.
This can be achieved by either running the script as root or granting the Python binary more capabilities:

```
sudo setcap 'cap_net_raw+ep' "$(readlink -f $(which python))"
```

After the installation is complete, you can execute probing using the given network interface:

```
repro enp11s0u1
```

Alternatively, you can build a docker image and use that:

```
docker build . -t tpr/repro
docker run --cap-add=cap_net_raw --net=host tpr/repro repro enp11s0u1
```

All informational output is done using a logger, so you can pipe the results directly into a file or to other tools:

```
repro enp11s0u1|jq .meta
{
  "start_time": "2024-01-30T23:27:31.768718",
  "end_time": "2024-01-30T23:28:03.180069",
  "duration": 31.411351,
  "hosts": 113,
  "networks": 7
}
```

Use `repro --help` for available configuration parameters.
