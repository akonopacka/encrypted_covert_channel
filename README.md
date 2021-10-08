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
### Server
--server loss
--client loss
--is_encrypted

Encryption methods:
aes, des, present, rsa, clefia, grain

Covert channels types:
"timing", "storage", "IP_id", "HTTP", "LSB", "sequence", "loss"


Start server:
sudo ncat -lkv 5000 -c "sh"

