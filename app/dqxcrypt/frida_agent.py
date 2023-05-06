import frida
import os

this_dir = os.path.split(__file__)[0]
LOG_DIR = f'{this_dir}/../logs/'

class FridaAgent():
    def __init__(self) -> None:
        self.session = None
        self.script = None
        self.hash_log_file = None
        self.blowfish_log_file = None

    def _get_agent_script(self):
        this_dir = os.path.split(__file__)[0]
        with open(f'{this_dir}/dqx-blowfish-frida-agent/_agent.js', 'rt', encoding='utf-8') as f:
            return f.read()

    def attach_game(self):
        self.session = frida.attach("DQXGame.exe")
        self.script = self.session.create_script(self._get_agent_script())
        self.script.on('message', self.on_message)
        self.script.load()

        init_result = self.script.exports.init_agent()
        if init_result != True:
            raise RuntimeError("Failed to initalize frida agent (AOB scans, etc)")

    def on_message(self, message, data):
        payload = message['payload']
        message_type = payload['message_type']
        if message_type == 'log':
            log_type = payload['log_type']
            if log_type == "hashlog":
                self.hash_log_file.write(f"\"{payload['hash_type']}\",\"{payload['hash_input']}\",\"{payload['hash_output']}\",\n")
                self.hash_log_file.flush()

            elif log_type == 'bflog':
                self.blowfish_log_file.write(f"\"{payload['filepath']}\",\"{payload['file_size']}\",\"{payload['blowfish_key']}\",\n")
                self.blowfish_log_file.flush()

        else:
            print("Frida Agent: [%s] => %s" % (message, data))

    def detach_game(self):
        self.script.unload()

    def init_logging(self):
        try:
            os.makedirs(LOG_DIR)
        except:
            pass

    def install_blowfish_logger(self):
        blowfishlog_path = LOG_DIR + 'blowfish_log.csv'
        self.blowfish_log_file = open(blowfishlog_path, 'a+')
        if self.blowfish_log_file.tell() == 0:
            self.blowfish_log_file.write(f"filepath,file_size,blowfish_key,\n")
        self.script.exports.install_blowfish_logger()

    def install_hash_logger(self):
        hashlog_path = LOG_DIR + 'hashlog.csv'
        self.hash_log_file = open(hashlog_path, 'a+')
        if self.hash_log_file.tell() == 0:
            self.hash_log_file.write(f"hash_type,hash_input,hash_output,\n")
        self.script.exports.install_hash_logger()
