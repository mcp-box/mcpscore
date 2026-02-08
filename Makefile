.PHONY: test windows-weather-py windows-weather-ts windows-my-mcp-server mac-weather-py mac-weather-ts

test:
	uv run pytest -q

windows-weather-py:
	uv run main.py c:/mcp/weather-server-python/weather.py

windows-weather-ts:
	uv run main.py c:/mcp/weather-server-typescript/build/index.js

windows-my-server:
	uv run main.py c:/mcp/MyMCPServer/server.py

windows-time-server:
	uv run main.py c:/mcp/time/src/mcp_server_time/server.py

windows-git-server:
	uv run main.py c:/mcp/git/src/mcp_server_git/server.py

mac-weather-py:
	uv run main.py /Users/alex/GitHub/alex-a/quickstart-resources/weather-server-python/weather.py

mac-weather-ts:
	uv run main.py /Users/alex/GitHub/alex-a/quickstart-resources/weather-server-typescript/build/index.js

