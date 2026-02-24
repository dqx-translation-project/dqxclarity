from common.db_ops import generate_m00_dict
from common.translate import transliterate_player_name
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


_concierge_names = generate_m00_dict(files="'custom_concierge_mail_names', 'local_mytown_names'")


class MyTownAmenityPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)

        # read data up to first string
        self.header_data = reader.read_bytes(12)
        self.name = reader.read_cstring()

        self.modified_data = None

    def __translate(self, name: str) -> str:
        translated_name = _concierge_names.get(name)
        if not translated_name:
            translated_name = transliterate_player_name(name, 25)

        return translated_name

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        trl_name = self.__translate(self.name)
        writer.write_cstring(trl_name)

        self.modified_data = writer.build()
