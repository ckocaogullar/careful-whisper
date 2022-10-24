# Careful Whisper: A scalable peer-to-peer attestation protocol (WIP)

This protocol is a solution to the problem of establishing a peer-to-peer network of Trusted Execution Environments (TEEs), where every node establishes trust with the whole network. This problem can be solved by each node to attesing all other nodes. However, this naive approach has quadratic complexity.

We propose Careful Whisper protocol (patent applied for) to optimise mutual attestation by propogating information of trusted nodes by gossiping. To put it simply, the nodes follow the logic of 'the friend of my friend is my friend'. By removing the need for each node to attest every other node, this mechanism decreases the number of attestation operations from $\theta$(N^2) to O(N) in the best case. 

## Protocol Details

This implementation of Careful Whisper consists of 5 messages exchanged between the prover and the verifier, and uses a modified Sigma protocol (i.e. a 3-round proof) [outlined by Intel](https://www.intel.com/content/www/us/en/developer/articles/code-sample/software-guard-extensions-remote-attestation-end-to-end-example.html). 

Nodes gossip sensitive trusted node information via TLS connections that terminate within enclaves, using an Intel SGX-compatible version of [mbedtls](https://github.com/ARMmbed/mbedtls). Using TLS between enclaves for gossiping enables compatibility with other attestation protocols.

The steps of the implemented protocol are:

1. Two enclaves establish TLS connection between each other
1. They exchange their lists of trusted nodes
1. The server node checks if it already trusts the client node
 1. `TRUE`: It expands its list of trusted nodes with the client node’s
 1. `FALSE`: Execute the [remote attestation protocol]((https://www.intel.com/content/www/us/en/developer/articles/code-sample/software-guard-extensions-remote-attestation-end-to-end-example.html)) 
1. Client and server change roles

## Preliminary benchmarking results

| Operation                 | CPU time (ms) |
|---------------------------|---------------|
| Peer-to-peer attestation  | ~160ms        |
| - Generating msg01          | ~0ms          |
| - Generating msg1           | ~80ms         |
| - Generating msg3           | ~0ms          |
| - Generating msg4           | ~80ms         |
| Gossiping                 | ~14ms         |

## Usage

Use the commands below for building:

```
git clone https://github.com/ckocaogullar/careful-whisper.git --recursive && cd mbedtls-compat-sgx
mkdir build && cd build
cmake .. -DCOMPILE_EXAMPLES=YES
make -j && make install
```

You can then run `s_client` with desired options on multiple terminal windows to run the protocol.


