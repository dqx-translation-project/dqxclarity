from dqxcrypt.frida_agent import FridaAgent

import sys


def start_logger():
    agent = FridaAgent()

    agent.attach_game()
    agent.init_logging()
    agent.install_hash_logger()
    agent.install_blowfish_logger()
    sys.stdin.read()

    # Detach from game
    agent.detach_game()
