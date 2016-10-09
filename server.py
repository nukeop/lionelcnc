import asyncio
import base64
import binascii
import cryptography
import discord
import json
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import messages
from config import DISCORD_INVITE

logger = logging.getLogger(__name__)

class LionelServer(discord.Client):
    def __init__(self, cryptokeys):
        super(LionelServer, self).__init__()
        self.cryptokeys = cryptokeys


    @asyncio.coroutine
    def on_message(self, message):
        logger.info("{}: {}".format(message.author, message.content))
        self.receive_encrypted(message.content)


    @asyncio.coroutine
    def on_ready(self):
        logger.info("LionelServer ready")
        logger.info("Logged in as {}".format(self.user.name))
        logger.info("ID: {}".format(self.user.id))

        invite = yield from self.get_invite(DISCORD_INVITE)
        accept = yield from self.accept_invite(invite)

        self.channel = list(self.servers)[0].default_channel


    def receive_encrypted(self, msg):
        """Receive an encrypted message and display its contents.
        """
        message = None
        try:
            message = base64.b64decode(msg).decode('utf-8')
        except:
            logger.error("Message is not base64-encoded")
            return

        ciphertext = binascii.unhexlify(message)
        plaintext = self.cryptokeys.private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        ).decode('utf-8')
        magic = plaintext.split('::')[0]
        if magic != messages.LionelMessage.magic:
            logger.error("Magic number doesn't match, skipping message")
            return

        logger.info("Decrypted message: {}".format(plaintext))
        logger.info(json.loads(plaintext.split('::')[3]))


    def send_signed(self, msg, header):

        #Sign the message for verification
        message="{}::{}::{}::{}".format(
            messages.LionelMessage.magic,
            'SERVER',
            header,
            msg
        )

        message=message.encode('utf-8')
        signature = self.cryptokeys.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        signature = binascii.hexlify(signature).decode('utf-8')

        message = messages.LionelMessage(
            msg,
            origin="SERVER",
            header=header,
            signature=signature
        )

        logger.info(message)

        message=base64.b64encode(str(message).encode('utf-8')).decode('utf-8') 

        yield from self.send_message(self.channel, message)
