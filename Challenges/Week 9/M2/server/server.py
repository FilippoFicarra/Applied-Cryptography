#!/usr/bin/env python3
import random
import secrets
from typing import Tuple
from boilerplate import CommandServer, on_command
from Crypto.PublicKey import ElGamal
from Crypto.Util import number
"""
No more untrusted, dusty carpets!
With this IoT Smart Carpet, you can constantly monitor
the level of dust in your carpet! Moreover, the communication
with your Smart Carpet is protected with Military Grade
Cryptography... You get a carpet you can trust!!!
"""

MAX_DUST_LEVEL = 10000
class ElGamalImpl:

    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """
        p = int(key.p)
        g = int(key.g)
        x = int(key.x)

        c1 = int.from_bytes(c1, 'big')
        c2 = int.from_bytes(c2, 'big')

        K = pow(c1, x, p)
        Z = number.inverse(K, p)

        m = (c2 * Z) % p

        return m.to_bytes((m.bit_length()+7)//8, 'big')

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """

        y_b = int(key.y)
        p = int(key.p)
        g = int(key.g)
        q = int((p-1)//2)


        k = int(random.uniform(0, p-1))

        K = pow(y_b, k, p)

        c1 = pow(g, k, p)
        c2 = (K * int.from_bytes(msg, 'big'))%p

        return c1.to_bytes((c1.bit_length()+7)//8, 'big') , c2.to_bytes((c2.bit_length()+7)//8, 'big')
    


class CarpetServer(CommandServer):
    def __init__(self, flag: str, key: ElGamal.ElGamalKey, *args, **kwargs):
        """Initialize the Server object.

        The Carpet's secret key initializes both the decryption and encryption
        ElGamal keys.

        Args:
            flag (str): the Carpet's secret flag
            key (ElGamal.ElGamalKey): the Carpet's secret key
        """
        self.flag = flag
        # used for decrypting commands
        self.key_dec = key
        # used for encrypting commands' responses (defaults to carpet's key)
        self.key_enc = self.key_dec

        super().__init__(*args, **kwargs)

    @on_command("get_public_parameters")
    def get_public_key_handler(self, msg):
        """Get the ElGamal public parameters used to encrypt commands to the server.

        (p, g): the ElGamal public parameters to be used (by our cloud) for
                   encrypting commands.
        """
        self.send_message(
            {
                "res": "Carpet's ElGamal public parameters",
                "p": str(int(self.key_dec.p)),
                "g": str(int(self.key_dec.g)),
            }
        )

    @on_command("set_response_key")
    def set_response_key_handler(self, msg):
        """Set the ElGamal key used for encrypting commands' responses.

        (p, g, y): the ElGamal public key to be used (by the server) for
                   encrypting the responses.
        """
        try:
            self.key_enc = ElGamal.construct(
                (int(msg["p"]), int(msg["g"]), int(msg["y"]))
            )
            self.send_message({"res": "Response key was successfully updated"})
        except (KeyError, ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

    @on_command("encrypted_command")
    def encrypted_command_handler(self, msg):
        response = None
        try:
            enc_command = msg["encrypted_command"]
            enc_command_c1 = bytes.fromhex(enc_command["c1"])
            enc_command_c2 = bytes.fromhex(enc_command["c2"])

            command = ElGamalImpl.decrypt(
                self.key_dec, enc_command_c1, enc_command_c2
            )
            print(command)

            match command:
                case b"get_status":
                    response = self.get_status()
                case b"backdoor":
                    response = self.get_flag()
                case _:
                    response = (
                        b"The command you tried to execute was not recognized: "
                        + command
                    )
        except (KeyError, ValueError) as e:
            response = str(e).encode()

        c1, c2 = ElGamalImpl.encrypt(self.key_enc, response)
        self.send_message({"encrypted_res": {"c1": c1.hex(), "c2": c2.hex()}})

    def get_status(self) -> bytes:
        dust_lev = secrets.randbelow(MAX_DUST_LEVEL) + 1
        msg = f"There's an awful lot of dust on your carpet: {dust_lev}kg"

        return msg.encode()

    def get_flag(self) -> bytes:
        return self.flag.encode()


if __name__ == "__main__":
    flag = "flag{test_flag}"
    # A key for locally running the Server
    p = 159326835256483747648683076552682480331934665910988420126125732402886077697040405547527521052897522971639414942528584820613412700564266171035566397568340970436590658287081846532208510854817985267864719388059404226126504848548282569940069730875333836687798954359620574875378036236852092341101685569338013749763
    g = 150988509186006229012634482071480382735449339154979059535519938500904353232673070656631345315464282941110540904488251642513304425357449197751364751848365122613530810708258187291141210645471300804655435331215972818402518171327475917779224923635112870077847351127800902471675259673445273165189869519993489513141
    y = 81031794553590424746805781583782590804952656371985350721984600080078536983496464284475718059229163152986451870054746269473117218771763388681221118924918938194763797451851120953721150647503975829226719008651941292632830009249992062005592663114980777782674598027011233125508037873137612002496382949433960370978
    x = 40230525246845515396879425357478057082343481758084701839686386301099139466834105175935399204235110685076486575306483891146707489513646682351652071953683716849353698690476041058648653225806163618699277166876237570666284332302766981309757140653555899524639357725790626210484312349331840047444976726304723293903
    key = ElGamal.construct((p, g, y, x))
    CarpetServer.start_server("0.0.0.0", 50902, flag=flag, key=key)
