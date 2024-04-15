# EBPF with Grafana Live Streaming

## About

This project leverages eBPF and [Grafana Live Streams](https://grafana.com/docs/grafana/latest/setup-grafana/set-up-grafana-live/), to demonstrate near real-time observability of network traffic.

![Image depicting intended architecture](/images/ebpf-diagram-transparent.drawio.png)

## eBPF App

On the eBPF side, there are two components:

* An eBPF application that leverages `xdp` to get gather packet information (stored into a map).
* A Go based User Space application that reads the map and forwards information to a Grafana dashboards (which auto updates.)

## How to Run

```

export GRAFANA_TOKEN="YourToken"
export GRAFANA_URL="YourURL"
export INTERFACE_NAME="NICName"

cd /cmd/go

go generate

go run .
```

## Grafana visualisation example

![Dashboard Video](./images/dashboard.gif)