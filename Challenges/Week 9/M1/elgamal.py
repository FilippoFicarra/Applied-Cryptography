from typing import Tuple
from Crypto.Util import number
from Crypto.PublicKey import ElGamal

import telnetlib
import json

server = "aclabs.ethz.ch"
tn = telnetlib.Telnet(server, 50901)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")




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
        p = key.p
        q = (p-1)//2
        g = key.g
        x = key.x

        K = pow(int(c1), x, p)
        Z = number.inverse(K, p)

        m = (c2 * Z) % p

        return m.to_bytes((m.bit_length() + 7) // 8, 'big')

    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """

        raise NotImplementedError
    
if __name__ == "__main__":

    p = 159326835256483747648683076552682480331934665910988420126125732402886077697040405547527521052897522971639414942528584820613412700564266171035566397568340970436590658287081846532208510854817985267864719388059404226126504848548282569940069730875333836687798954359620574875378036236852092341101685569338013749763
    g = 150988509186006229012634482071480382735449339154979059535519938500904353232673070656631345315464282941110540904488251642513304425357449197751364751848365122613530810708258187291141210645471300804655435331215972818402518171327475917779224923635112870077847351127800902471675259673445273165189869519993489513141
    y = 81031794553590424746805781583782590804952656371985350721984600080078536983496464284475718059229163152986451870054746269473117218771763388681221118924918938194763797451851120953721150647503975829226719008651941292632830009249992062005592663114980777782674598027011233125508037873137612002496382949433960370978
    x = 40230525246845515396879425357478057082343481758084701839686386301099139466834105175935399204235110685076486575306483891146707489513646682351652071953683716849353698690476041058648653225806163618699277166876237570666284332302766981309757140653555899524639357725790626210484312349331840047444976726304723293903

    request = {
        'command': 'set_response_key',
        'p': p,
        'g': g,
        'y': y,
    }

    json_send(request)
    response = json_recv()

    print(response)

    key = ElGamal.construct((p, g, y, x))

    e = ElGamalImpl()
    

    request = {
        'command': 'get_public_key', 
    }
    json_send(request)

    response = json_recv()
    print(response)

    p = response['p']
    g = response['g']
    y = response['y']


    # request = {
    #     'command': 'get_public_key', 
    # }
    # json_send(request)

    # response = json_recv()
    # print(response)

    # {
    #     'command': 
    #     'encrypted_command', 
    #     'encrypted_command': {
    #         'c1': '390b1ebfc6b8a730b003b423b384038f081e3cd6767c4e0d92f53487a93d0cca26fc48bb92f511874fd89ed8393f76663e434f2f8bb1dff7da3110771a199a0eb3e2b203189073e2fbedc63c1d2ff8e1d6820556b7e8548dbc9b59be04588c6ee41d41db36868581060723f4bc9d1857ddbb5c3e306ce97e54c102e48844f931', 
    #         'c2': '734aae69697f3c27bdba17ae8c3cc9903c4eb86bd095bf8cdc7c1a5d714c012ce69a0ab734f9d3e11f262f083ac7d92c4dd730c71c411bed568edf722a2c70e8d6173ec962214b2cd42e8408d99d22bccf99bdbcef27fe53387c3ed82f7ad2f89126ba4a3b015dd00168a5ba30d8c6849badffe118edebb0a37a5536577b7d80'
    #         }
    #     }
    # {
    #     'encrypted_res': {
    #         'c1': '4ffb5c04d089eeebf471c630d6405146111a8f1de9834c8079bab9225c87a2e68d70aaea67a4c408e0bbb68debad734e4e4245a9a3baa3581f9e87579eb8f973dca4d6333da593e8efc860307502897ac9bc5133130fe76f340e67efb79c20476c5fab621b1ae66158517a0c4ede49f37c0f88e03c9336ff627babf7996f5842', 
    #         'c2': '7b0c6d4ccc8de52ea0a21d0c130b345845a2d1fa1fdce23aa3450dc7dc1031294333acf59fa2f58199f86307e101c8c765a6c58c208ec781d4b33115876d60b5519d89c14fd0d509b0b0c2c37b18a9973f17b3c52bf90eb303b2cb68b90d767128edb25eec964a0ba5cb1197b69cf32452cec68b79c09aa089fc4c4e5cb349b1'
    #         }
    # }
