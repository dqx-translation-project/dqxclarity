from common.db_ops import generate_m00_dict
from hooking.hooks.packets.buffer import PacketReader, PacketWriter


_master_quest_strings = generate_m00_dict("'custom_master_quests'")


class MasterQuestPacket:
    def __init__(self, raw: bytes):
        self.raw = raw

        reader = PacketReader(raw)
        self.header_data = reader.read_bytes(52)

        # there's no indicator on how many strings are in this packet,
        # but it always starts with the quest name, followed by any
        # number of quest objectives.
        quest_data = reader.remaining().split(b"\x00")

        # each quest has some random determination of nulls at the
        # end of the last quest objective. this could be junk data,
        # but it's probably best to keep the packet structure the same.
        self.number_of_nulls = len([n for n in quest_data if not n])

        # as the last string in the structure also has a null terminator,
        # exclude it from the list as write_cstring() will add it back.
        if self.number_of_nulls != 0:
            self.number_of_nulls = self.number_of_nulls - 1

        quest_data = [s.decode("utf-8") for s in quest_data if s]

        # if user does not have master quest unlocked, this will be blank!
        # these packets are received on player login.
        if not quest_data:
            self.unlocked = False
            return

        self.unlocked = True

        self.quest_name = quest_data.pop(0)

        # remaining list are objectives. quests always have at least
        # one objective.
        self.quest_objectives = quest_data

        self.modified_data = None

    def _translate(self, string: str) -> str:
        return _master_quest_strings.get(string, string)

    def build(self) -> bytes:
        if not self.unlocked:
            self.modified_data = self.raw
            return

        writer = PacketWriter()

        writer.write_bytes(self.header_data)

        trl_quest_name = self._translate(self.quest_name)
        writer.write_cstring(trl_quest_name[:34])

        for quest in self.quest_objectives:
            trl_quest_objective = self._translate(quest)
            writer.write_cstring(trl_quest_objective)

        # append nulls read to keep structure the same.
        writer.write_bytes(b"\x00" * self.number_of_nulls)

        self.modified_data = writer.build()
