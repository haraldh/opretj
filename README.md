### How to start:

```bash
$ git clone https://github.com/haraldh/opretj.git
$ cd opretj
$ mvn install
$ mvn package
$ cd opret-testapp
$ mvn exec:java -Dexec.args='--net=TEST'
```

# Key Management on the Blockchain

The blockchain as a distributed immutable ledger is a good tool to use as a public key infrastructure (PKI). On this PKI, we can announce new public keys, sign them and revoke them. Everybody can scan the blockchain for key related announcements and nobody can remove or falsify those afterwards, without notice.

For these key announcements the same properties apply as for the currency. That means an attacker will have to cut those who want new information from the blockchain completely off from the distributed network. By sending the block headers on different media (like satellite, radio or TV), a blockchain receiver can quickly see, that one of his sources diverges from the others and a warning signal can be issued, that something fishy is going on. 

For this implementation of PKI on the blockchain, the bitcoin blockchain is chosen, because it is backed up by enough money and miners to ensure the integrity and immutable nature. An alternative blockchain PKI could be implemented on ethereum, which has more powerful interfaces to implement a PKI.

## Restrictions on the bitcoin blockchain

Arbitrary data can be stored in every bitcoin transaction by using a transaction output script, which begins with OP_RETURN. OP_RETURN can be followed by data chunks. There can only be one OP_RETURN transaction output script in a transaction. The size of the script including OP_RETURN must not exceed 82 bytes. Every data chunk has it's length prepended. For sizes from 1-75 bytes, the size field only consumes one byte.

An example OP_RETURN script with a 32 byte and 16 byte data chunk looks like this:

OP_RETURN 32 [32 bytes data chunk] 16 [16 byte data chunk]

which results in a script length of 51 bytes.

## Bitcoin blockchain for thin clients

Downloading the full bitcoin blockchain requires network bandwidth and storage. Mobile clients therefore use the SPV protocol to get filtered blockchain data from full nodes. For further reading consult the links in the [bitcoin glossary on SPV] (https://bitcoin.org/en/glossary/simplified-payment-verification).

Every data chunk in the OP_RETURN script can be used as a bloom filter element for thin clients. That means, that the PKI key announcements should have on data chunk, which a thin client can use for the filter to save bandwidth.

## PKI

Because of the limited amount of data, which can be stored, this implementation of a PKI on the bitcoin blockchain uses elliptic curve keys and for the ease of implementation curve 25519 and the [libsodium] (https://download.libsodium.org/doc/) functions.

## Mode of operation

* user creates 256bit master key (MK) with Ed25519 ECC curve 25519
* user creates derived 256bit key from master key as signing key 1 (K1)
* K1 public key (K1PK) is announced on the blockchain with 0xECA1 and 0xECA2 
* user creates derived 256bit key from master key as signing key 2 (K2)
* K2 public key (K2PK) is announced as next key of K1 with 0xECA3 and 0xECA4 
* K2 key and MK are removed from device
* K1 secret key is used on device to sign documents and ephemeral encryption keys
* K1 revocation record (K1RR) is stored somewhere for later publication
* If K1SK lost or breached:
    + K1 is revoked on the blockchain with 0xEC0F
    + MK is used to calculate K3
    + K3 is announced  as next key of K2 with 0xECA3 and 0xECA4
    + K3 and MK are removed from device

A MK is stored along with the key birthday, which is the date of the first appearance on the blockchain.

## PKI blockchain announcements in Detail

### MVK announce subkey VK 0xECA[1,2] - A-nnounce

nonce[0:32] = nonce[0:16] | nonce[16:32]
data chunks are prepended with zeros, if its length is smaller than 16.
E.g.

     nonce[0:16]  = 0x1F -> 0x0000000000000000000000000000001F
     nonce[16:32] = 0x2F -> 0x0000000000000000000000000000002F
     nonce[0:32]  = 0x0000000000000000000000000000001F0000000000000000000000000000002F

If nonce is missing completely, then

     nonce[0:32]  = 0x0000000000000000000000000000000000000000000000000000000000000000

is assumed.

A nonce **must** be used only once. Either only one VK_pub is announced per MVK ever and nonce is missing,
or for every MVK announcement, the nonce has to be *unique* or *true random* bytes.

sharedkey  = sha256(sha256(MVK_pub | nonce))
xornonce[24]  = sha256(sharedkey | nonce)[0:24]

sig[64]    = crypto_sign(VK_pub, MKV)
msg[96]    = VK_pub || sig
cipher[96] = crypto_stream_xor(msg, xornonce, sharedkey)

clients may flush T1, if T2 does not follow in the next 20 blocks
clients may flush T2, if T1 does not follow in the next 20 blocks

|      | OP        | Chunk1 |         Chunk2              |           Chunk3          |
|:-----|:---------:|:------:|:---------------------------:|:-------------------------:|
|  T1  | OP_RETURN | 0xECA1 | cipher[00:48] + data[0:16]  | 12 Byte sha256(MVK)[0:12] |
| Size | 1         |   3    |              49             |             13            |
|  T2  | OP_RETURN | 0xECA2 | cipher[48:96] + data[16:32] | 12 Byte sha256(MVK)[0:12] |
| Size | 1         |   3    |              49             |             13            |

### MVK announce next subkey VK_n+1 0xECA[3,4] - A-nnounce
sharedkey  = sha256(sha256(VK_n_pub))
nonce[24]  = sha256(sharedkey)[0:24]

sig[64]    = crypto_sign(VK_n+1_pub, MKV)
msg[96]    = VK_n+1_pub || sig
cipher[96] = crypto_stream_xor(msg, nonce, sharedkey)

clients may flush T1, if T2 does not follow in the next 20 blocks
clients may flush T2, if T1 does not follow in the next 20 blocks

|      | OP        | Chunk1 |     Chunk2     |           Chunk3          |          Chunk4            |
|:-----|:---------:|:------:|:--------------:|:-------------------------:|:--------------------------:|
|  T1  | OP_RETURN | 0xECA3 | cipher[00:48]  | 12 Byte sha256(MVK)[0:12] | 12 Byte sha256(VK_n)[0:12] |
| Size | 1         |   3    |       49       |             13            |           13               |
|  T2  | OP_RETURN | 0xECA4 | cipher[48:96]  | 12 Byte sha256(MVK)[0:12] | 12 Byte sha256(VK_n)[0:12] |
| Size | 1         |   3    |       49       |             13            |           13               |

### Public Doc or other key OK sign 0xEC5[1,2]
sign[64]   = Sign_Key('Sign ' || sha256(Doc/OK))
data       = optional data (max 2*19 bytes)

clients may flush T1, if T2 does not follow in the next 20 blocks
clients may flush T2, if T1 does not follow in the next 20 blocks

|      | OP        | Chunk1 |       Chunk2       |          Chunk3           |          Chunk4              |
|:-----|:---------:|:------:|:------------------:|:-------------------------:|:----------------------------:|
|  T1  | OP_RETURN | 0xEC51 | sign[00:32] + data | 12 Byte sha256(Key)[0:12] | 12 Byte sha256(Doc/OK)[0:12] |
| Size | 1         |   3    |         33         |           13              |           13                 |
|  T2  | OP_RETURN | 0xEC52 | sign[32:64] + data | 12 Byte sha256(Key)[0:12] | 12 Byte sha256(Doc/OK)[0:12] |
| Size | 1         |   3    |         33         |           13              |           13                 |

### Revoke a Key 0xEC0F - 0FF
OP_RETURN 0xEC0F Sign('Revoke ' || sha256(Key)) 64 Bytes + 12 Byte sha256(Key)

### Anonymous Doc/VK sign OxEC1D - ID
Proof, that Key could sign something at that date.
OP_RETURN OxEC1D Sign('Sign ' || sha256(Doc/VK)) 64 Bytes + 12 Byte sha256(Doc/VK)[0:12]

### Doc Proof of Existence 0xEC1C - I see
Proof, that a document existed at that point of time.
OP_RETURN 0xEC1C 32 Byte sha256(Doc)

~~### Key note 0xEC10
annotate a <note> for a Key encrypted with the encryption key EK
OP_RETURN 0xEC10 || Box_ENC(<note>) 64 Bytes || 12 Byte sha256(EK_pub || Key)[0:12]~~

## Example on the Bitcoin Blockchain
An example transaction with a key revocation can be seen on the bitcoin blockchain as transaction [c7457b452c41deea0f2a34ef8bf7596c758002714062e869516b6dd5602b5565](https://www.blocktrail.com/BTC/tx/c7457b452c41deea0f2a34ef8bf7596c758002714062e869516b6dd5602b5565#tx_messages).
In this transaction a VK fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c is revoked as seen with 0xEC0F
The sha256sum of the PK is f5105e87388c219e43ad9a9856c50df9f9b4a0e87a8bd32d0f72534d83a2df74
```
$ echo fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c | xxd -r -p | sha256sum
f5105e87388c219e43ad9a9856c50df9f9b4a0e87a8bd32d0f72534d83a2df74
```

The message to verify is 'Revoke ' followed by the hash of VK:
```
5265766f6b6520 f5105e87388c219e43ad9a9856c50df9f9b4a0e87a8bd32d0f72534d83a2df74
```

and the corresponding signature as seen on the blockchain: 
```
34dccafe91cb0b2b30175ead0eacc1481ee7428da70158035ab657914634801a37056bbf88e27058303e6f9e6cd38d1704a62b54ec9723614e6c1cf04b052e0f 
```

With pysodium, we can check the signature quickly:

```
from pysodium import *
import binascii

if __name__ == '__main__':
    pk = binascii.unhexlify(b'fb2e360caf811b3aaf534d0458c2a2ca3e1f213b244a6f83af1ab50eddacdd8c')
    msg = b'Revoke ' + binascii.unhexlify(b'f5105e87388c219e43ad9a9856c50df9f9b4a0e87a8bd32d0f72534d83a2df74')
    sig = binascii.unhexlify(b'34dccafe91cb0b2b30175ead0eacc1481ee7428da70158035ab657914634801a37056bbf88e27058303e6f9e6cd38d1704a62b54ec9723614e6c1cf04b052e0f')
    try:
        crypto_sign_verify_detached(sig, msg, pk)
        print "Signature OK"
    except ValueError:
        print "sig does not match"
```

and of course it matches.
