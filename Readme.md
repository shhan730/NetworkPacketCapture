# add-nbo

## Introduction

### 1. Overview

This project is to implement a adder program

This program adds two 32bit network byte order number regardless of Big or Little endian.

### 2. Usage Example & Testing

1. Add Ip Link for Testing

```bash
sudo ip link add dum0 type dummy
sudo ifconfig dum0 up
```

2. Check dum0 is available

```shell
ifconfig
```

3. Start Program with dum0

```
sudo ./pcap dum0
```

4. Test with tcpreplay

```shell
sudo tcpreplay -i dum0 testgil.pcapng
```

