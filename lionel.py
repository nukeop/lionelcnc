"""
Lionel3

Command and control system using encrypted messages in a discord channel to
coordinate independent agents.
"""
__author__="nukeop"


import argparse
import json
import logging

import asyncio
import cryptography
import discord


def main():
    import crypto, server, client, messages
    from config import DISCORD_USER, DISCORD_PASS

    parser = argparse.ArgumentParser()
    parser.add_argument("--client", help="run in client mode", action="store_true")
    parser.add_argument("--server", help="run in server mode", action="store_true")
    args = parser.parse_args()

    if (not args.server and not args.client) or (args.server and args.client):
        print("You have to choose either server or client")
        exit()

    if args.server:
        c = crypto.Crypto()
        dc = server.LionelServer(c)
        dc.run(DISCORD_USER, DISCORD_PASS)
    elif args.client:
        c = crypto.Crypto()
        dc = client.LionelClient(c.public_key)
        dc.run(DISCORD_USER, DISCORD_PASS)


if __name__=='__main__':
    import logging.config
    logging.config.fileConfig('logging.conf', disable_existing_loggers=True)
    main()
