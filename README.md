# Bitcoin P2P Node Handshake

## How to run

### Step 1 - Target Node configuration

#### Option 1 - Use existing bitcoin nodes as target node

In the `target_node_config.json` file specify ipv4 and port of an existing running bitcoin nodes.  
Some running node ips:

```
162.120.69.182:8333
172.92.108.184:8333
82.67.27.185:8333
```

#### Option 2 - Run bitcoin node locally

- Download the Bitcoin Core implementation (https://bitcoin.org/en/download) and run it.
- In the `target_node_config.json` file specify your local IP (local host) and port on which Bitcoin Core is running.

In `target_node_config.json` the following configs are allowed:
- `ipv4` - String - IP address of the target node
- `port` - unsigned 16-bit integer - port on which Bitcoin is running on the target node

### Step 2 - Local Node configuration

Update `local_config.json` file. The following configs are allowed:
- `version` - signed 32-bit integer - bitcoin protocol version supported by the current program (mandatory)
- `services` - unsigned 64-bit integer - bitfield of features (https://en.bitcoin.it/wiki/Protocol_documentation#version) (optional)
- `ipv4` - String - IP address of the local node (optional)
- `port` - unsigned 16-bit integer - port on which current program is running (optional)

### Step 3 - run
 Run the program as follows:
 ```
 $ cargo run
 ```

## Results verification

Program is printing the handshake status at every step.
If the handshake process completed successfully the following message will be displayed:
```
Handshake succeeded.
```
Otherwise, you will see the following message:
```
Handshake failed.
```

After the handshake is performed, the program will drop the connection and terminate.
It's possible to enable the program to read following traffic.
For that run the program with an environment variable turned on:
```
$ READ_NEXT_N_MESSAGES=<number_of_messages> cargo run 
```
Replace `<number_of_messages>` with the number of messages you want the program to read after the handshake.