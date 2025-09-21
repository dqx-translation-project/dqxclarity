from dqxcrypt.frida_agent import FridaAgent

import sys


def start_logger(ready_event):
    agent = FridaAgent()

    agent.attach_game()
    agent.init_logging()
    agent.install_hash_logger()
    agent.install_blowfish_logger()

    if ready_event:
        ready_event.set()

    while True:
        sys.stdin.read()

    # agent.detach_game()
