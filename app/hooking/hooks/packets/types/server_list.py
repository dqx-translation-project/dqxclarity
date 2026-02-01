from hooking.hooks.packets.buffer import PacketReader


class ServerListPacket:
    def __init__(self, raw: bytes):
        reader = PacketReader(raw)
        self.data = reader.remaining()

        self.modified_data = None

    def __pad_string(self, source: str, target: str):
        encoded_jp = source.encode('utf-8')
        encoded_en = target.encode('utf-8')

        if len(encoded_en) < len(encoded_jp):
            encoded_en += b"\x00" * (len(encoded_jp) - len(encoded_en))

        return encoded_en

    def build(self) -> bytes:
        # we don't want to mess around with the structure here.
        # just swap out the server names, keep the same length and
        # return the text-swapped list.
        self.modified_data = self.data

        # any server names should not exceed 9 characters. this is used:
        #   - on the server list when logging in
        #   - on the map
        #   - in the friend/team list
        #
        # the server names in the packet have padding after them, so
        # if they are shorter, we can artificially extend the source
        # replacement with \x00 bytes to make sure the replacement
        # is covered.
        servers = {
            "サーバー０１": "Server 01",
            "サーバー０２": "Server 02",
            "サーバー０３": "Server 03",
            "サーバー０４": "Server 04",
            "サーバー０５": "Server 05",
            "サーバー０６": "Server 06",
            "サーバー０７": "Server 07",
            "サーバー０８": "Server 08",
            "サーバー０９": "Server 09",
            "サーバー１０": "Server 10",
            "サーバー１１": "Server 11",
            "サーバー１２": "Server 12",
            "サーバー１３": "Server 13",
            "サーバー１４": "Server 14",
            "サーバー１５": "Server 15",
            "サーバー１６": "Server 16",
            "サーバー１７": "Server 17",
            "サーバー１８": "Server 18",
            "サーバー１９": "Server 19",
            "サーバー２０": "Server 20",
            "サーバー２１": "Server 21",
            "サーバー２２": "Server 22",
            "サーバー２３": "Server 23",
            "サーバー２４": "Server 24",
            "サーバー２５": "Server 25",
            "サーバー２６": "Server 26",
            "サーバー２７": "Server 27",
            "サーバー２８": "Server 28",
            "サーバー２９": "Server 29",
            "サーバー３０": "Server 30",
            "サーバー３１": "Server 31",
            "サーバー３２": "Server 32",
            "サーバー３３": "Server 33",
            "サーバー３４": "Server 34",
            "サーバー３５": "Server 35",
            "サーバー３６": "Server 36",
            "サーバー３７": "Server 37",
            "サーバー３８": "Server 38",
            "サーバー３９": "Server 39",
            "サーバー４０": "Server 40",
            "［オ］住宅村": "O Housing",
            "イベント会場": "Event",
            "魔法の迷宮": "Mag. Maze",
            "ＰＴ同盟空間": "Alliance",
            "［ウ］住宅村": "W Housing",
            "［エ］住宅村": "E Housing",
            "［ド］住宅村": "D Housing",
            "［プ］住宅村": "P Housing",
            "コロシアム": "Coliseum",
            "カジノ": "Casino",
            "特殊エリア": "Special",
            "強戦士の間": "Boss Book",
            "王家の迷宮": "Roy. Maze",
            "クイズエリア": "Quiz Area",
            "バトルロード": "Btl. Road",
            "不思議の魔塔": "M. Tower",
            "幻想画エリア": "Painting",
            "［レ］住宅村": "L Housing",
            "竜王の城": "DQ1 Event",
            "学園特殊室内": "Classroom",
            "学園教練区域": "Drill",
            "ゾーマの城": "DQ3 Event",
            "バトエン": "Batoen",
            "大富豪": "Tycoon",
            "防衛軍エリア": "ADF",
            "謎の遺跡島内": "Zelmea",
            "プレイエリア": "Play Area",
            "マイタウン": "My Town",
            "万魔の塔": "Banma",
            "源世庫エリア": "Panigalm",
            "咎人エリア": "Criminals",
            "訓練場エリア": "Training",
            "アスタルジア": "Astalgia",
            "劇場\x00\x00\x00": "Theatre",
        }

        for server in servers:
            self.modified_data = self.modified_data.replace(
                server.encode('utf-8'),
                self.__pad_string(server, servers[server])
            )
