"""
Lionel3 Command And Control message format.

Every client needs to start with a public key of the server it will respond to.
This key can be changed later, but it needs to be synchronized between server
and clients. This is to ensure that no one can impersonate the server.

Server sends unencrypted base64-encoded messages, clients encrypt their
messages with the server's public key. 

This is the structure of a message:
MAGIC::ORIGIN::HEADER::CONTENT::SIGNATURE

MAGIC is a magic number defined in this module. It is included to ensure only
correctly decrypted messages are interpreted. It can be useful in cases when we
want only one client to receive a particular message - in this case we can
encrypt the message with its public key, and only this one client will be able
to decrypt it.

ORIGIN can only contain either SERVER or CLIENT.

HEADER is a single word containing the type of the message and it might
influence the way it is interpreted by the server and the clients.

Allowed header values:
PUBKEY - asks the server to send its public key
MYPUBKEY - the contents of this message contain the public key of the sender.
If this is different from a previously sent key, it means the key has been
changed.

The above two are the only two message types that clients are allowed to send
unencrypted. Any other messages sent unencrypted will be ignored.

JSON - the message contains a json string
COMMAND - the message contains a command to be interpreted and executed by
clients. This can be either sent unencrypted by the server if contents can be
publicly revealed, or can be sent encrypted to particular clients

CONTENT - a block of arbitrary data, how it's interpreted depends on the header

SIGNATURE - to prove authenticity of a message, it has to be signed with
sender's own key. Not required in client messages. The form of the message that
is to be signed is MAGIC::ORIGIN::HEADER::CONTENT.

"""


class LionelMessage(object):
    magic = "LIONEL3"

    def __init__(self, content, origin="CLIENT", header="JSON", signature="0"):
        self.magic = LionelMessage.magic
        self.origin = origin
        self.header = header
        self.content = content
        self.signature = signature

    def __str__(self):
        return "{}::{}::{}::{}::{}".format(
            self.magic,
            self.origin,
            self.header,
            self.content,
            self.signature
            )
