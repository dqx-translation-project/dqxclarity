from hooking.hooks.packets.buffer import PacketReader, PacketWriter


class WeeklyRequestPacket:
    """
    Format for request windows like:

    - Demon Lord's Ghostwriter (v5)
    - Sky High Fitness (v6)

    These are the weekly quest windows that contain the objectives.
    """
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.header_data = reader.read_bytes(60)

        # there's no indicator on how many strings are in this packet,
        # but it always starts with the quest name, followed by the
        # quest objective.
        self.quest_name = reader.read_cstring()
        self.quest_objective = reader.read_cstring()

        self.remaining = reader.remaining()

        self.modified_data = None

    def build(self) -> bytes:
        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        # look up quest name logic here. self.quest_name
        #writer.write_cstring(self.quest_name)
        writer.write_cstring("quest name")

        # look up quest objectives logic here.
        #writer.write_cstring(self.quest_objective)
        writer.write_cstring("some quest objective")

        # append nulls read to keep structure the same.
        writer.write_bytes(self.remaining)

        self.modified_data = writer.build()
