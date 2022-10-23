SHELL=cmd

build:
	make clean
	mkdir .\build\dqxclarity
	copy .\requirements.txt .\build\dqxclarity\requirements.txt
	xcopy app .\build\dqxclarity /s /e /h /i
	-rd /s/q .\build\dqxclarity\json
	xcopy .\json\_lang\en .\build\dqxclarity\json\_lang\en /s /e /h /i
	xcopy .\venv .\build\dqxclarity\venv /s /e /h /i
	-rmdir /s /q .\build\dqxclarity\__pycache__
	-rmdir /s /q .\build\dqxclarity\api_translate\__pycache__
	-rmdir /s /q .\build\dqxclarity\hook_mgmt\__pycache__
	-rmdir /s /q .\build\dqxclarity\pymem\__pycache__
	-rmdir /s /q .\build\dqxclarity\pymem\ressources\__pycache__
	-del /F .\build\dqxclarity\out.log
	-del /F .\build\dqxclarity\game_text.log
	-rd /s/q .\build\dqxclarity\new_adhoc_dumps
	-rmdir /s /q .\build\dqxclarity\new_adhoc_dumps
	-rmdir /s /q .\build\dqxclarity\game_file_dumps
	"C:\Program Files\AutoHotkey\Compiler\Ahk2Exe.exe" /bin "C:\Program Files\AutoHotkey\Compiler\ANSI 32-bit.bin" /in ".\build\dqxclarity\clarity.ahk" /icon "imgs/dqxclarity.ico"
	-del /F ".\build\dqxclarity\clarity.ahk"

release:
	make clean
	git pull origin weblate
	make build
	-del /F ".\build\dqxclarity\user_settings.ini"
	-rmdir /s /q .\build\dqxclarity\venv
	"C:\Program Files\7-Zip\7z.exe" a -tzip dqxclarity.zip .\build\dqxclarity

lint:
	pylint --rcfile=.pylintrc app/

clean:
	-rd /s/q "build\"
	-rd /s/q "dist\"
	-rd /s/q "app\game_file_dumps\"
	-del /F "dqxclarity.zip"
	-rd /s/q "app\bms\json"
	-rd /s/q "app\bms\hyde_json_merge\src"
	-rd /s/q "app\bms\hyde_json_merge\dst"
	-rd /s/q "app\bms\hyde_json_merge\out"
	-del /F "app\bms\hex_dict.csv"

run:
	git pull origin weblate
	xcopy json .\app\json /s /e /h /i /Y
	cd app && python main.py -pnvc
