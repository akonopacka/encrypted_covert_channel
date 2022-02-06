# encrypted_covert_channel

Implementation of encrypted covert channels which are secured with different ciphers.

## Covert channel methods

- Inter-packet Times (PT1)
- Artificial Loss (PT10)
- Message Ordering (PDU Order) (PT11)
- Size Modulation (PS1)
- Random Value (PS10)
- Case Pattern (PS11.a)
- Least Significant Bit (LSB) Pattern (PS11.b)

## Usage

Encryption methods:
aes, des, present, rsa, clefia, grain

Covert channels types:
storage, IP_id, HTTP, LSB, sequence, loss, timing

### Server
--server loss --is_encrypted aes

Start client:
sudo ncat -lkv 5000 -c "sh"

### Client
--client loss --is_encrypted aes


sudo tc qdisc add dev eth0 handle 10: root tbf rate 1mbit burst 1540 latency 10s

sudo tc qdisc add dev eth0 root netem loss 1% delay 0s


TEST CPU and MEMORY USAGE
/usr/bin/time -f "%P; %M" sudo ./encrypted_covert_channel --crypto_test des 1000