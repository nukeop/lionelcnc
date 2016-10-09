"""
Lionel3 Command And Control client template.
"""


import asyncio
import base64
import binascii
import json
import logging
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import cryptography
import discord

import messages
from config import DISCORD_INVITE

logger = logging.getLogger(__name__)


class LionelClient(discord.Client):
    """This is an example implementation of a client.
    This class can be extended to create custom clients, but you can also write
    independent clients provided they can send and receive messages defined in
    messages.py.

    This client only verifies messages it receives, and shows contents of json
    type messages.
    """
    def __init__(self, serverkey):
        super(LionelClient, self).__init__()
        self.serverkey = serverkey


    @asyncio.coroutine
    def on_message(self, message):
        logger.info("{}: {}".format(message.author, message.content))
        self.receive_signed(message.content)


    @asyncio.coroutine
    def on_ready(self):
        logger.info("LionelClient ready")
        logger.info("Logged in as {}".format(self.user.name))
        logger.info("ID: {}".format(self.user.id))

        invite = yield from self.get_invite(DISCORD_INVITE)
        accept = yield from self.accept_invite(invite)

        self.channel = list(self.servers)[0].default_channel


    def send_encrypted(self, msg):
        msg = json.dumps({'message':msg})
        message = str(messages.LionelMessage(
            msg,
            origin="CLIENT",
            header="JSON"
        ))

        ciphertext = self.serverkey.encrypt(
            bytes(message.encode('utf-8')),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )
        ciphertext = binascii.hexlify(ciphertext)
        ciphertext = base64.b64encode(ciphertext).decode('utf-8')

        yield from self.send_message(self.channel, ciphertext)

    def receive_signed(self, msg):
        """Verify if the message has been signed with the private key
        corresponding to the public key we have.
        """
        message = None
        try:
            message = base64.b64decode(msg).decode('utf-8')
        except:
            logger.error("Message is not base64-encoded")
            return

        try:
            logger.info(message)
            orig_message = '::'.join(message.split('::')[:-1])
            magic, origin, header, content, sig = message.split('::')

            if magic != messages.LionelMessage.magic:
                logger.error("Wrong magic number")
                raise ValueError

            if origin != 'SERVER':
                logger.error("Message not from a server, skipping")
                return

            logger.info("{} type message".format(header))
            if header == 'JSON':
                content = json.loads(content)
            logger.info("Contents: {}".format(content))
            logger.info("Verifying...")

            try:
                sig = binascii.unhexlify(sig)
                self.serverkey.verify(
                    sig,
                    orig_message.encode('utf-8'),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                logger.info("Message is authentic")
            except cryptography.exceptions.InvalidSignature:
                logger.error("Signature doesn't match, message could be"
                             "forged") 

        except ValueError:
            logger.error("Received a malformed message, or a message from"
            " external source")
