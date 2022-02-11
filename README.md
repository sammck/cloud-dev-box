# py-api-test
Sandbox for playing with web apis, authentication, etc in python


# Packages/tools used:

## VS Code - Visual Studio Code useful extensions
[Visual Studio Code](https://code.visualstudio.com/) has a marketplace for extensions. Here are a few that are helpful with this project:

- [Python](https://marketplace.visualstudio.com/items?itemName=ms-python.python) - Official Python support for VS Code
- [Better TOMl](https://marketplace.visualstudio.com/items?itemName=bungcip.better-toml) - Syntax highlighting, etc for `.toml` file extension used by Poetry
- [FastAPI Snippets](https://marketplace.visualstudio.com/items?itemName=damildrizzy.fastapi-snippets) - Snippets for Python FastAPI framework

## Python packages:

- [fastapi](https://pypi.org/project/fastapi/) - Web API server framework, build on starlette. Supports sync or asyncio, infers schema from python type hints, automatically generates documentation
- [pydantic](https://pypi.org/project/pydantic/) - Schema definition/inference using Python 3.6+ type hinting
- [python-dotenv](https://pypi.org/project/python-dotenv/) - Makes python inherit env vars from the `.env` file
- [fastapi-sso](https://pypi.org/project/fastapi-sso/) - Single signon support for FastAPI. Used to implement Google sign-in
- [fastapi-jwt-auth](https://pypi.org/project/fastapi-jwt-auth/) - Support for Javascript Web Tokens (JWS) for session auth
- [uvicorn](https://pypi.org/project/fastapi/) - ASGI server, OpenAPI doc browser, local web API tester. To start a test server on port 8000, run
`uvicorn hw:app --reload`, then navigate to `http://localhost:8000/docs`
- [sqlalchemy](https://pypi.org/project/sqlalchemy/) - Object relational model, maps SQL and schema onto python objects
- [keyring](https://pypi.org/project/keyring/) - Read and write locally stored named secrets. Used to access OAUTH client secret without committing to github
- _deprecated_ [python-jose\[cryptography\]](https://pypi.org/project/python-jose/) - JWT library, more up-to-date than PyJWT

## Poetry - A modern python package/dependency manager

[Poetry](https://python-poetry.org/) handles all the stuff that would otherwise be handled by `pip`, `pipenv`, `pyenv`, `virtualenv`, "`python3 -m venv`", etc. It creates and maintains the project's virtualenv (in `.venv/` as configured here), project dependencies in `pyproject.toml`, and detailed version locking in `poetry.lock`.

Poetry should be installed outside the project, and the command tool should be in the user's path. To install it, do not use the `get-poetry.py` script, which is deprecated. Also, do not install Poetry with `pip`, which will suck a lot of sensitive version dependencies into your user or global python environment.
Instead, install poetry in its own private environment under `$HOME/.local/share/pypoetry` using `https://install.python-poetry.org`.
Make sure you are not in a virtualenv. A link to the poetry command tool will be added at `$HOME/.local/bin/poetry`:

```
curl -sSL https://install.python-poetry.org | python3 -
poetry --version
```
Version as of this memo is 1.1.12.

To initialize poetry in a preexisting python project directory:

```
cd <project-dir>
poetry init
poetry config virtualenvs.in-project true
```
This will create `pyproject.toml`.  The config command causes a virtualenv for the project to be maintained in a `.venv` subdirectory
of the project rather than under `$HOME/.cache/pypoetry`. This is my preference and makes configuring vscode easier IMO.

After a project is initialized, invoking `poetry` from the directory containing `pyproject.toml` or any subdirectory thereof will
apply the command to that project.

You can view the poetry configuration of a project with:
```
poetry config --list
```

Poetry automatically creates and manages a virtualenv for your project the first time it is needed. To create this virtualenv or
install/update all package dependencies into the environment, use:
```
cd <project-dir-or-subdir>
poetry install
```

Note that in addition to the virtualenv, this will create/maintain a `poetry.lock` file that describes the exact
version of each package that actually got put into the virtualenv. In general, this is not something you need to
share between users, so yo might want to add `/poetry.lock` to your `.gitignore` file.

After the virtualenv has been initialized, you can tell vscode to use it as the default python interpreter with `<F1>Python:Select Interpreter`.

To add a new dependent package to the virtualenv:
```
cd <project-dir-or-subdir>
poetry add <package-name>
```

To spawn a bash shell in the virtualenv, use:
```
cd <project-dir-or-subdir>
poetry shell
```

Or, to simply run a single command in the virtualenv, use:
```
cd <project-dir-or-subdir>
poetry run <command> [arg...]
```
## Google single-signon

See [Google SSO](google-sso.md)