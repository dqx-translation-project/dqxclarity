from common.db_ops import generate_m00_dict
from common.translate import transliterate_player_name
from hooking.hooks.packets.buffer import PacketReader


_player_names = generate_m00_dict(files="'local_player_names'")


class CommWindowListPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        self.data = bytearray(raw)

        reader.seek(12)
        self.number_of_players = reader.read_u32()

        self.modified_data = None

    def __pad(self, string: str):
        str_len = len(string.encode("utf-8"))

        # 20 is the buffer size allocated for names
        difference = 20 - str_len - 1  # leave one off for null terminiator.

        return string + ("\x00" * difference)

    def __translate(self, name: str) -> str:
        translated_name = _player_names.get(name)
        if not translated_name:
            translated_name = transliterate_player_name(name)

        return translated_name

    def build(self) -> bytes:
        """
        We only care about finding player names. We jump through
        the packet at fixed offsets to find player names and
        replace them with ours.
        """
        start = 16
        entry_size = 213
        name_position = 108
        name_buffer_size = 19  # don't include null terminator in buffer.

        # if the name exceeds this length, the game will crash
        # when you navigate to the chat window.
        max_name_length = 11

        for i in range(self.number_of_players):
            name_offset = start + (i * entry_size) + name_position
            name_end = name_offset

            while self.data[name_end : name_end + 1] != b"\x00":
                name_end += 1

            jp_name = self.data[name_offset:name_end].decode("utf-8")
            trl_name = self.__translate(jp_name)

            replacement = self.__pad(trl_name[:max_name_length]).encode("utf-8")[:name_buffer_size]

            self.data[name_offset : name_offset + name_buffer_size] = replacement

        self.modified_data = self.data
