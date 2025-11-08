"""Intramural Team Tracker Webserver - Intramural Team Tracker website.

Copyright (C) 2025  CoolCat467

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

from __future__ import annotations

__title__ = "Intramural Team Tracker Webserver"
__author__ = "CoolCat467"
__version__ = "0.0.0"
__license__ = "GNU General Public License Version 3"


import functools
import logging
import socket
import sys
import time
import traceback
import uuid
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterable,
)
from os import getenv, makedirs, path
from pathlib import Path
from typing import TYPE_CHECKING, Final, TypeVar
from urllib.parse import urlencode

import trio
from hypercorn.config import Config
from hypercorn.trio import serve
from quart import request
from quart.templating import stream_template
from quart_auth import (
    AuthUser,
    QuartAuth,
    Unauthorized,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from quart_trio import QuartTrio
from werkzeug.exceptions import HTTPException

from imtrackerweb import (
    csvrecords,
    database,
    elapsed,
    security,
)

if sys.version_info < (3, 11):
    import tomli as tomllib
    from exceptiongroup import BaseExceptionGroup
else:
    import tomllib

if TYPE_CHECKING:
    from typing_extensions import ParamSpec
    from werkzeug import Response

    PS = ParamSpec("PS")

HOME: Final = trio.Path(getenv("HOME", path.expanduser("~")))
XDG_DATA_HOME: Final = trio.Path(
    getenv("XDG_DATA_HOME", HOME / ".local" / "share"),
)
XDG_CONFIG_HOME: Final = trio.Path(getenv("XDG_CONFIG_HOME", HOME / ".config"))

FILE_TITLE: Final = __title__.lower().replace(" ", "-").replace("-", "_")
CONFIG_PATH: Final = XDG_CONFIG_HOME / FILE_TITLE
DATA_PATH: Final = XDG_DATA_HOME / FILE_TITLE
MAIN_CONFIG: Final = CONFIG_PATH / "config.toml"

FORMAT = "[%(asctime)s] [%(levelname)s] %(message)s"
logging.basicConfig(format=FORMAT, level=logging.DEBUG, force=True)

PEPPER = "TODO: Load from configuration file"

T = TypeVar("T")


def combine_end(data: Iterable[str], final: str = "and") -> str:
    """Return comma separated string of list of strings with last item phrased properly."""
    data = list(data)
    if len(data) >= 2:
        data[-1] = f"{final} {data[-1]}"
    if len(data) > 2:
        return ", ".join(data)
    return " ".join(data)


async def send_error(
    page_title: str,
    error_body: str,
    return_link: str | None = None,
) -> AsyncIterator[str]:
    """Stream error page."""
    return await stream_template(
        "error_page.html.jinja",
        page_title=page_title,
        error_body=error_body,
        return_link=return_link,
    )


async def get_exception_page(
    code: int,
    name: str,
    desc: str,
    return_link: str | None = None,
) -> tuple[AsyncIterator[str], int]:
    """Return Response for exception."""
    resp_body = await send_error(
        page_title=f"{code} {name}",
        error_body=desc,
        return_link=return_link,
    )
    return (resp_body, code)


def pretty_exception_name(exc: BaseException) -> str:
    """Make exception into pretty text (split by spaces)."""
    exc_str, reason = repr(exc).split("(", 1)
    reason = reason[1:-2]
    words = []
    last = 0
    for idx, char in enumerate(exc_str):
        if char.islower():
            continue
        word = exc_str[last:idx]
        if not word:
            continue
        words.append(word)
        last = idx
    words.append(exc_str[last:])
    error = " ".join(w for w in words if w not in {"Error", "Exception"})
    return f"{error} ({reason})"


def pretty_exception(
    function: Callable[PS, Awaitable[T]],
) -> Callable[PS, Awaitable[T | tuple[AsyncIterator[str], int]]]:
    """Make exception pages pretty."""

    @functools.wraps(function)
    async def wrapper(  # type: ignore[misc]
        *args: PS.args,
        **kwargs: PS.kwargs,
    ) -> T | tuple[AsyncIterator[str], int]:
        code = 500
        name = "Exception"
        desc = (
            "The server encountered an internal error and "
            + "was unable to complete your request. "
            + "Either the server is overloaded or there is an error "
            + "in the application."
        )
        try:
            return await function(*args, **kwargs)
        except Exception as exception:
            traceback.print_exception(exception)

            if isinstance(exception, HTTPException):
                code = exception.code or code
                desc = exception.description or desc
                name = exception.name or name
            else:
                exc_name = pretty_exception_name(exception)
                name = f"Internal Server Error ({exc_name})"

        return await get_exception_page(
            code,
            name,
            desc,
        )

    return wrapper


# Stolen from WOOF (Web Offer One File), Copyright (C) 2004-2009 Simon Budig,
# available at http://www.home.unix-ag.org/simon/woof
# with modifications

# Utility function to guess the IP (as a string) where the server can be
# reached from the outside. Quite nasty problem actually.


def find_ip() -> str:
    """Guess the IP where the server can be found from the network."""
    # we get a UDP-socket for the TEST-networks reserved by IANA.
    # It is highly unlikely, that there is special routing used
    # for these networks, hence the socket later should give us
    # the IP address of the default route.
    # We're doing multiple tests, to guard against the computer being
    # part of a test installation.

    candidates: list[str] = []
    for test_ip in ("192.0.2.0", "198.51.100.0", "203.0.113.0"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((test_ip, 80))
        ip_addr: str = sock.getsockname()[0]
        sock.close()
        if ip_addr in candidates:
            return ip_addr
        candidates.append(ip_addr)

    return candidates[0]


app: Final = QuartTrio(  # pylint: disable=invalid-name
    __name__,
    static_folder="static",
    template_folder="templates",
)

# Attributes users might have and what they do:
# password : sha3_256 hash of password as string
# type : "student", "teacher", "manager", "admin"
# status : "not_created", "joining", "created_auto_password", "created"
#   Not created is when teacher has assigned points but student has not
#     set up account yet.
#   Joining is when student has visited sign up page and has join code
#     assigned, but has not used join code link yet.
#   Created Auto Password is when teacher account created with
#     automatic password, flag so account can be remade if forgotten
#     generated password.
#   Created is when join code link visited and account is verified.
# join_code : None or string of join code UUID
# join_code_expires : UNIX epoch time after which join code is expired


def get_user_by(**kwargs: str) -> set[str]:
    """Get set of usernames of given type."""
    users = database.load(Path(app.root_path) / "records" / "users.json")
    table = users.table("username")
    usernames: tuple[str, ...] = table["username"]

    result: set[str] = set(usernames)

    for raw_key, value in kwargs.items():
        key = raw_key.removesuffix("_")
        sub_result: set[str] = set()
        for index, entry_type in enumerate(table[key]):
            if entry_type == value:
                sub_result.add(usernames[index])
        result &= sub_result
    return result


def login_require_only(
    **attrs: str | set[str],
) -> Callable[[Callable[PS, Awaitable[T]]], Callable[PS, Awaitable[T]]]:
    """Require login and some attribute match."""

    def get_wrapper(
        function: Callable[PS, Awaitable[T]],
    ) -> Callable[PS, Awaitable[T]]:
        """Get handler wrapper."""

        @login_required
        @functools.wraps(function)
        async def wrapper(*args: PS.args, **kwargs: PS.kwargs) -> T:
            """Make sure current user matches attributes."""
            if current_user.auth_id is None:
                raise Unauthorized()

            users = database.load(
                Path(app.root_path) / "records" / "users.json",
            )
            username = get_login_from_cookie_data(current_user.auth_id)

            if username is None or username not in users:
                logging.error(
                    f"Invalid login UUID {current_user.auth_id} "
                    "in authenticated user",
                )
                logout_user()
                raise Unauthorized()

            user = users[username]
            for raw_key, raw_value in attrs.items():
                value = (
                    {raw_value} if isinstance(raw_value, str) else raw_value
                )
                key = raw_key.removesuffix("_")
                if user.get(key) not in value:
                    raise Unauthorized()

            return await function(*args, **kwargs)

        return wrapper

    return get_wrapper


def create_login_cookie_data(username: str) -> str:
    """Generate UUID associated with a specific user.

    Only one instance of an account should be able
    to log in at any given time, subsequent will invalidate older
    sessions. This will make remembering instances easier
    """
    # Get login database
    logins = database.load(Path(app.root_path) / "records" / "login.json")

    # Make new random code until it does not exist
    while (code := str(uuid.uuid4())) in logins:
        continue

    # Make logins expire after a while
    expires = int(time.time()) + 2628000  # Good for 1 month

    # Write data back
    logins[code] = {
        "user": username,
        "expires": expires,
    }
    logins.write_file()
    return code


def get_login_from_cookie_data(code: str) -> str | None:
    """Get username from cookie data.

    If cookie data is invalid return None
    """
    # Get login database
    logins = database.load(Path(app.root_path) / "records" / "login.json")

    # Attempt to get entry for code. Using get instead of
    # "in" search and then index means is faster
    entry = logins.get(code, None)
    # If not exists or malformed entry, is bad
    if entry is None or not isinstance(entry, dict):
        return None
    # If expires not exist in entry or time expired, is bad and delete entry
    if entry.get("expires", 0) < int(time.time()):
        logging.info(f"Login UUID {code!r} expired")
        del logins[code]
        logins.write_file()
        return None
    # Otherwise attempt to return username field or is bad because malformed
    value = entry.get("user", None)
    assert isinstance(value, str) or value is None
    return value


def create_uninitialized_account(
    username: str,
    type_: str | None = None,
) -> None:
    """Create uninitialized account. If type is None do not set."""
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username in users:
        error = f"Attempted to create new account for {username} which exists"
        logging.error(error)
        return
    users[username] = {
        "status": "not_created",
    }
    if type_ is not None:
        users[username]["type"] = type_
    users.write_file()
    logging.info(f"Created uninitialized account {username!r}")


async def add_tickets_to_user(username: str, count: int) -> None:
    """Add ticket count to username. Create account if it doesn't exist."""
    assert count > 0, f"Use subtract_user_tickets instead of adding {count}"

    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        records[username] = {}

    current_tickets = get_user_ticket_count(username)
    assert isinstance(current_tickets, int)

    records[username]["tickets"] = current_tickets + count
    await records.async_write_file()
    logging.info(f"User {username!r} received {count!r} ticket(s)")


def get_user_ticket_count(username: str) -> int:
    """Get number of tickets user has at this time.

    Raises LookupError if username does not exist
    """
    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        raise LookupError(f"User {username!r} does not exist")

    raw_count: str | int = records[username].get("tickets", 0)
    if isinstance(raw_count, int):
        return raw_count
    assert isinstance(raw_count, str)
    if not raw_count.isdecimal():
        logging.error(
            f"Count from tickets was {raw_count!r} instead of decimal",
        )
        return 0
    return int(raw_count)


async def subtract_user_tickets(username: str, count: int) -> int:
    """Remove tickets from user. Return number of tickets left.

    Raises LookupError if username does not exist
    Raises ValueError if count is greater than number of tickets in account
    """
    assert count > 0, f"Use add_user_tickets instead of subtracting {count}"

    records = csvrecords.load(
        Path(app.root_path) / "records" / "tickets.csv",
        "student_id",
    )

    if username not in records:
        raise LookupError(f"User {username!r} does not exist")

    current_tickets = get_user_ticket_count(username)

    assert isinstance(current_tickets, int)
    new = current_tickets - count

    if new < 0:
        raise ValueError(
            f"Insufficient tickets for user {username!r} to subtract {count}",
        )
    records[username]["tickets"] = new
    if new == 0:  # Maybe free up a bit of memory then, since default is zero
        del records[username]

    await records.async_write_file()
    logging.info(f"User {username!r} lost {count!r} ticket(s)")

    return new


def convert_joining(code: str) -> bool:
    """Convert joining record to student record."""
    # Get usernames with matching join code and who are joining
    users = database.load(Path(app.root_path) / "records" / "users.json")
    usernames = get_user_by(join_code=code, status="joining")
    if len(usernames) != 1:
        logging.info(f"Invalid code {code!r}")
        return False
    username = usernames.pop()

    # If expired, erase and continue
    now = int(time.time())
    expires = users[username].get("join_code_expires", 0)

    del users[username]["join_code"]
    del users[username]["join_code_expires"]

    if now > expires:
        users.write_file()

        delta = elapsed.get_elapsed(now - expires)
        logging.info(f"{username!r} join code expired by {delta}")
        return False

    users[username]["status"] = "created"
    users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    logging.info(f"User {username!r} logged in from join code")

    return True


# @app.get("/signup")
# async def signup_get() -> str | Response:
#    """Handle sign up get including code register"""
#    # Get code from request arguments if it exists
#    code = request.args.get("code", None)
#    if code is not None:
#        success = convert_joining(code)
#        if success:
#            return app.redirect("/")
#        return await send_error(
#            "Signup Code Error",
#            "Signup code is invalid. It may have expired.",
#            request.url
#        )
#    return await stream_template(
#        "signup_get.html.jinja",
#    )


# @app.post("/signup")
# async def signup_post() -> Response | str:
#    """Handle sign up form"""
#    multi_dict = await request.form
#    response = multi_dict.to_dict()
#
#    # Validate response
#    username = response.get("username", "")
#    password = response.get("password", "")
#
#    if bool(set(username) - set("0123456789")) or len(username) != 6:
#        return await send_error(
#            "Signup Error",
#            "Student usernames can only be numbers and must be exactly 6 "+
#            "digits long.",
#            request.url
#        )
#    if len(set(password)) < 7:
#        return await send_error(
#            "Signup Error",
#            "Password must have at least seven different characters "+
#            "for security reasons. Please use a more secure password.",
#            request.url
#        )
#
#    users = database.load(Path(app.root_path) / "records" / "users.json")
#
#    create_link = True
#
#    if username in users:
#        status = users[username].get("status", "not_created")
#        if status == "created":
#            return await send_error(
#                "Signup Error",
#                "A user with the requested username already exists",
#                request.url
#            )
#        if status == "joining":
#            now = int(time.time())
#            if users[username].get("join_code_expires", now + 5) < now:
#                create_link = False
#
#    # If not already in joining list, add and send code
#    email = f"{username}@class.lps.org"
#
#    if create_link:
#        table = users.table("username")
#        existing_codes = table["join_code"]
#        while (code := str(uuid.uuid4())) in existing_codes:
#            continue
#        link = (
#            app.url_for("signup_get", _external=True)
#            + "?"
#            + urlencode({"code": code})
#        )
#        expires = int(time.time()) + 10 * 60  # Expires in 10 minutes
#
#        expire_time = elapsed.get_elapsed(expires - int(time.time()))
#        title = "Please Verify Your Account"
#        message_body = "\n".join(
#            (
#                "There was a request to create a new account for the",
#                f"Caught In the Act Store with the username {username!r}.",
#                f"Please click {htmlgen.create_link(link, 'this link')}",
#                "to verify your account.",
#                "",
#                "If you did not request to make an account, please ignore",
#                f"this message. This link will expire in {expire_time}.",
#            )
#        )
#        sendmail.send(email, title, message_body)
#
#        if username not in users:
#            create_uninitialized_account(username)
#
#        users[username].update(
#            {
#                "password": security.create_new_login_credentials(
#                    password, PEPPER
#                ),
#                "email": users[username].get("email", email),
#                "type": users[username].get("type", "student"),
#                "status": "joining",
#                "join_code": code,
#                "join_code_expires": expires,
#            }
#        )
#        users.write_file()
#        logging.info(f"User {username!r} signed up")
#
#    return await stream_template(
#        "signup_post.html.jinja",
#        email=email,
#    )


@app.get("/login")
async def login_get() -> AsyncIterator[str]:
    """Get login page."""
    return await stream_template(
        "login_get.html.jinja",
    )


@app.post("/login")
async def login_post() -> AsyncIterator[str] | Response:
    """Handle login form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    username = response.get("username", "")
    password = response.get("password", "")

    if not username or not password:
        return await send_error(
            "Login Error",
            "Username or password field not found",
            request.url,
        )

    # Check Credentials here, e.g. username & password.
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username not in users:
        return await send_error(
            "Login Error",
            "Username or password is invalid.",
            request.url,
        )

    if users[username].get("type", "student") == "student":
        return await send_error(
            "Login Error",
            "Students are not allowed to log in at this time.",
            request.url,
        )

    database_value = users[username].get("password", None)
    if database_value is None:
        return await send_error(
            "Login Error",
            "User data is missing password field (Please report to CSHS).",
            request.url,
        )
    if not await security.compare_hash(password, database_value, PEPPER):
        # Bad password
        return await send_error(
            "Login Error",
            "Username or password is invalid.",
            request.url,
        )

    # Make sure to change status of auto password accounts
    if users[username].get("status") == "created_auto_password":
        users[username]["status"] = "created"
        users.write_file()

    user = AuthUser(create_login_cookie_data(username))
    login_user(user)
    logging.info(f"User {username!r} logged in")
    # print(f"{current_user = }")

    return app.redirect("/")


@app.get("/logout")
async def logout() -> Response:
    """Handle logout."""
    if await current_user.is_authenticated:
        code = current_user.auth_id
        assert code is not None
        username = get_login_from_cookie_data(code)
        if username is not None:
            logging.info(f"User {username!r} ({code}) logged out")
        else:
            logging.error(f"Invalid UUID {code} logged out")
    logout_user()
    return app.redirect("login")


# @app.get("/user_data")
# @login_required
# async def user_data_route() -> Response | Response:
#    """Dump user data
#
#    Warning, potential security issue, do not run in production"""
#    assert current_user.auth_id is not None
#    users = database.load(Path(app.root_path) / "records" / "users.json")
#    username = get_login_from_cookie_data(current_user.auth_id)
#
#    if username is None or username not in users:
#        logging.error(
#            f"Invalid login UUID {current_user.auth_id} "
#            "in authenticated user",
#        )
#        logout_user()
#        return app.redirect("login")
#    user = users[username] | {"username": username}
#    logging.debug(f"Record dump for {username!r}")
#    return Response(
#        json.dumps(user, sort_keys=True),
#        content_type="application/json",
#    )


@app.get("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager", "admin"})
async def add_tickets_get() -> AsyncIterator[str]:
    """Add tickets page for teachers."""
    return await stream_template(
        "add_tickets_get.html.jinja",
    )


@app.post("/add-tickets")
@pretty_exception
@login_require_only(type_={"teacher", "manager", "admin"})
async def add_tickets_post() -> AsyncIterator[str]:
    """Handle post for add tickets form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    student_id = response.get("id", "")
    ticket_count_raw = response.get("ticket_count", "")

    try:
        if not ticket_count_raw.isdigit():
            raise ValueError
        ticket_count = int(ticket_count_raw)
        if ticket_count < 1 or ticket_count > 10:
            raise ValueError
    except ValueError:
        return await send_error(
            "Ticket Count Error",
            "Ticket count is not in range.",
            request.url,
        )

    await add_tickets_to_user(student_id, ticket_count)

    plural = "" if ticket_count == 1 else "s"
    return await stream_template(
        "add_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        student_id=student_id,
    )


@app.get("/subtract-tickets")
@pretty_exception
@login_require_only(type_={"manager", "admin"})
async def subtract_tickets_get() -> AsyncIterator[str]:
    """Subtract tickets page for managers."""
    return await stream_template(
        "subtract_tickets_get.html.jinja",
    )


@app.post("/subtract-tickets")
@pretty_exception
@login_require_only(type_={"manager", "admin"})
async def subtract_tickets_post() -> AsyncIterator[str]:
    """Handle post for subtract tickets form."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    student_id = response.get("id", "")
    ticket_count_raw = response.get("ticket_count", "")

    try:
        if not ticket_count_raw.isdigit():
            raise ValueError
        ticket_count = int(ticket_count_raw)
        if ticket_count < 1 or ticket_count > 100:
            raise ValueError
    except ValueError:
        return await send_error(
            "Ticket Count Error",
            "Ticket count is not in range.",
            request.url,
        )

    try:
        tickets_left = await subtract_user_tickets(student_id, ticket_count)
    except LookupError:
        # Username not exist
        return await send_error(
            "Not Enough Tickets Error",
            "Requested student has zero tickets.",
            request.url,
        )
    except ValueError:
        # Count > number of tickets in account
        return await send_error(
            "Not Enough Tickets Error",
            "Student does not have enough tickets for the requested "
            + "transaction",
            request.url,
        )

    plural = "" if ticket_count == 1 else "s"
    plural_left = "" if tickets_left == 1 else "s"
    return await stream_template(
        "subtract_tickets_post.html.jinja",
        ticket_count=ticket_count,
        plural=plural,
        plural_left=plural_left,
        student_id=student_id,
        tickets_left=tickets_left,
    )


@app.get("/settings")
@pretty_exception
@login_required
async def settings_get() -> AsyncIterator[str]:
    """Handle settings page get request."""
    return await stream_template(
        "settings_get.html.jinja",
    )


@app.get("/settings/change-password")
@pretty_exception
@login_required
async def settings_change_password_get() -> AsyncIterator[str]:
    """Handle setting page for password change get."""
    return await stream_template(
        "settings_change_password_get.html.jinja",
    )


@app.post("/settings/change-password")
@pretty_exception
@login_required
async def settings_password_post() -> AsyncIterator[str] | Response:
    """Handle password change form."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    username = get_login_from_cookie_data(current_user.auth_id)

    if username is None or username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    # Validate response
    current_password = response.get("current_password", "")
    new_password = response.get("new_password", "")

    if not current_password or not new_password:
        return await send_error(
            "Request Error",
            "Current password or new password field not found.",
            request.url,
        )

    # Check Credentials here, e.g. username & password.
    users = database.load(Path(app.root_path) / "records" / "users.json")

    if username not in users:
        logout_user()
        return app.redirect("login")

    if not await security.compare_hash(
        current_password,
        users[username]["password"],
        PEPPER,
    ):
        # Bad password
        logging.info(
            f"{username!r} did not enter own password in " + "change password",
        )
        return await send_error(
            "Password Does Not Match Error",
            "Entered password does not match current password.",
            request.url,
        )

    users[username]["password"] = security.create_new_login_credentials(
        new_password,
        PEPPER,
    )
    users.write_file()
    logging.info(f"{username!r} changed their password")

    return await stream_template(
        "settings_change_password_post.html.jinja",
    )


@app.get("/invite-teacher")
@pretty_exception
@login_require_only(type_="admin")
async def invite_teacher_get() -> AsyncIterator[str]:
    """Create new teacher account."""
    return await stream_template(
        "invite_teacher_get.html.jinja",
    )


@app.post("/invite-teacher")
@pretty_exception
@login_require_only(type_="admin")
async def invite_teacher_post() -> AsyncIterator[str] | Response:
    """Invite teacher form post handling."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )
    length = len(new_account_username)
    if length < 3 or length > 16:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )

    possible_name = set("abcdefghijklmnopqrstuvwxyz23456789")
    if bool(set(new_account_username) - possible_name):
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )

    users = database.load(Path(app.root_path) / "records" / "users.json")

    if (
        new_account_username in users
        and users[new_account_username]["status"] != "created_auto_password"
    ):
        return await send_error(
            "Invite User Error",
            "An account with the requested username already exists",
            request.url,
        )

    password = security.create_new_password(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "teacher",
        "status": "created_auto_password",
    }

    users.write_file()

    logging.info(
        f"{creator_username!r} invited {new_account_username!r} as teacher",
    )

    return await stream_template(
        "invite_teacher_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


@app.get("/invite-manager")
@pretty_exception
@login_require_only(type_="admin")
async def invite_manager_get() -> AsyncIterator[str]:
    """Create a new manager account."""
    return await stream_template(
        "invite_manager_get.html.jinja",
    )


@app.post("/invite-manager")
@pretty_exception
@login_require_only(type_="admin")
async def invite_manager_post() -> AsyncIterator[str] | Response:
    """Invite manager form post handling."""
    assert current_user.auth_id is not None
    users = database.load(Path(app.root_path) / "records" / "users.json")
    creator_username = get_login_from_cookie_data(current_user.auth_id)

    if creator_username is None or creator_username not in users:
        logging.error(
            f"Invalid login UUID {current_user.auth_id} "
            "in authenticated user",
        )
        logout_user()
        return app.redirect("login")

    multi_dict = await request.form
    response = multi_dict.to_dict()

    new_account_username = response.get("new_account_username", "")

    if not new_account_username:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )
    length = len(new_account_username)
    if length < 3 or length > 16:
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )

    possible_name = set("abcdefghijklmnopqrstuvwxyz23456789")
    if bool(set(new_account_username) - possible_name):
        return await send_error(
            "Invite User Error",
            "New account username must be between 3 and 16 characters long "
            + "and cannot contain special characters",
            request.url,
        )

    users = database.load(Path(app.root_path) / "records" / "users.json")

    if (
        new_account_username in users
        and users[new_account_username]["status"] != "created_auto_password"
    ):
        return await send_error(
            "Invite User Error",
            "An account with the requested username already exists",
            request.url,
        )

    password = security.create_new_password(16)

    users[new_account_username] = {
        "password": security.create_new_login_credentials(password, PEPPER),
        "type": "manager",
        "status": "created_auto_password",
    }

    users.write_file()

    logging.info(
        f"{creator_username!r} invited {new_account_username!r} as manager",
    )

    return await stream_template(
        "invite_manager_post.html.jinja",
        new_account_username=new_account_username,
        password=password,
    )


@pretty_exception
async def ticket_get_form() -> AsyncIterator[str]:
    """Generate form for ticket GET when no ID given."""
    return await stream_template(
        "ticket_form.html.jinja",
    )


@pretty_exception
async def ticket_count_page(username: str) -> AsyncIterator[str]:
    """Ticket count page for given username."""
    user_type = None

    if current_user.auth_id is not None:
        users = database.load(Path(app.root_path) / "records" / "users.json")
        logged_in_username = get_login_from_cookie_data(current_user.auth_id)

        if logged_in_username is not None and logged_in_username in users:
            user_type = users[logged_in_username].get("type")

    try:
        count = get_user_ticket_count(username)
    except LookupError:
        count = 0

    user_link = app.url_for("tickets_get") + "?" + urlencode({"id": username})

    return await stream_template(
        "ticket_count_page.html.jinja",
        username=repr(username),
        count=repr(count),
        user_link=user_link,
        user_type=user_type,
    )


@app.get("/tickets")
@pretty_exception
async def tickets_get() -> AsyncIterator[str]:
    """Tickets view page."""
    # Get username from request arguments if it exists
    username = request.args.get("id", None)

    if not username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")) or len(username) != 6:
        # If username has any character except 0-9, bad
        return await send_error(
            "User Error",
            "Username is invalid.",
            request.url,
        )

    return await ticket_count_page(username)


@app.post("/tickets")
@pretty_exception
async def tickets_post() -> AsyncIterator[str]:
    """Invite teacher form post handling."""
    multi_dict = await request.form
    response = multi_dict.to_dict()

    username = response.get("student_id", None)

    if not username:
        return await ticket_get_form()

    if bool(set(username) - set("0123456789")):
        # If username has any character except 0-9, bad
        print(f"{username!r} bad")
        return await ticket_get_form()

    return await ticket_count_page(username)


@app.get("/")
async def root_get() -> AsyncIterator[str] | Response:
    """Handle main page GET request."""
    # print(f"{current_user = }")

    user_name = ""
    user_type = ""
    if await current_user.is_authenticated:
        users = database.load(Path(app.root_path) / "records" / "users.json")
        assert current_user.auth_id is not None
        loaded_user = get_login_from_cookie_data(current_user.auth_id)

        if loaded_user is None or loaded_user not in users:
            logging.error(
                f"Invalid login UUID {current_user.auth_id} "
                "in authenticated user",
            )
            logout_user()
            return app.redirect("login")
        user_name = loaded_user

        user = users[user_name]

        user_type = user["type"]

    return await stream_template(
        "root_get.html.jinja",
        user_name=user_name,
        user_type=user_type,
    )


async def serve_async(app: QuartTrio, config_obj: Config) -> None:
    """Serve app within a nursery."""
    await serve(app, config_obj)


def serve_scanner(
    device_name: str,
    *,
    secure_bind_port: int | None = None,
    insecure_bind_port: int | None = None,
    ip_addr: str | None = None,
    hypercorn: dict[str, object] | None = None,
) -> None:
    """Asynchronous Entry Point."""
    if secure_bind_port is None and insecure_bind_port is None:
        raise ValueError(
            "Port must be specified with `port` and or `ssl_port`!",
        )

    if not ip_addr:
        ip_addr = find_ip()

    if not hypercorn:
        hypercorn = {}

    logs_path = DATA_PATH / "logs"
    if not path.exists(logs_path):
        makedirs(logs_path)

    print(f"Logs Path: {str(logs_path)!r}\n")

    try:
        # Hypercorn config setup
        config: dict[str, object] = {
            "accesslog": "-",
            "errorlog": logs_path / time.strftime("log_%Y_%m_%d.log"),
        }
        # Load things from user controlled toml file for hypercorn
        config.update(hypercorn)
        # Override a few particularly important details if set by user
        config.update(
            {
                "worker_class": "trio",
            },
        )
        # Make sure address is in bind

        if insecure_bind_port is not None:
            raw_bound = config.get("insecure_bind", [])
            if not isinstance(raw_bound, Iterable):
                raise ValueError(
                    "main.bind must be an iterable object (set in config file)!",
                )
            bound = set(raw_bound)
            bound |= {f"{ip_addr}:{insecure_bind_port}"}
            config["insecure_bind"] = bound

            # If no secure port, use bind instead
            if secure_bind_port is None:
                config["bind"] = config["insecure_bind"]
                config["insecure_bind"] = []

            insecure_locations = combine_end(
                f"http://{addr}" for addr in sorted(bound)
            )
            print(f"Serving on {insecure_locations} insecurely")

        if secure_bind_port is not None:
            raw_bound = config.get("bind", [])
            if not isinstance(raw_bound, Iterable):
                raise ValueError(
                    "main.bind must be an iterable object (set in config file)!",
                )
            bound = set(raw_bound)
            bound |= {f"{ip_addr}:{secure_bind_port}"}
            config["bind"] = bound

            secure_locations = combine_end(
                f"https://{addr}" for addr in sorted(bound)
            )
            print(f"Serving on {secure_locations} securely")

        app.config["EXPLAIN_TEMPLATE_LOADING"] = False

        # We want pretty html, no jank
        app.jinja_options = {
            "trim_blocks": True,
            "lstrip_blocks": True,
        }

        app.add_url_rule("/<path:filename>", "static", app.send_static_file)

        config_obj = Config.from_mapping(config)

        QuartAuth(app)

        print("(CTRL + C to quit)")

        trio.run(serve_async, app, config_obj)
    except BaseExceptionGroup as exc:
        caught = False
        for ex in exc.exceptions:
            if isinstance(ex, KeyboardInterrupt):
                print("Shutting down from keyboard interrupt")
                caught = True
                break
        if not caught:
            raise


def run() -> None:
    """Run scanner server."""
    if not path.exists(CONFIG_PATH):
        makedirs(CONFIG_PATH)
    if not path.exists(MAIN_CONFIG):
        with open(MAIN_CONFIG, "w", encoding="utf-8") as fp:
            fp.write(
                """[main]
# Name of scanner to use on default as displayed on the webpage
# or by model as listed with `scanimage --formatted-device-list "%m%n"`
printer = "None"

# Port server should run on.
# You might want to consider changing this to 80
port = 6001

# Port for SSL secured server to run on
#ssl_port = 443

# Helpful stack exchange website question on how to allow non root processes
# to bind to lower numbered ports
# https://superuser.com/questions/710253/allow-non-root-process-to-bind-to-port-80-and-443
# Answer I used: https://superuser.com/a/1482188/1879931

[hypercorn]
# See https://hypercorn.readthedocs.io/en/latest/how_to_guides/configuring.html#configuration-options
use_reloader = false
# SSL configuration details
#certfile = "/home/<your_username>/letsencrypt/config/live/<your_domain_name>.duckdns.org/fullchain.pem"
#keyfile = "/home/<your_username>/letsencrypt/config/live/<your_domain_name>.duckdns.org/privkey.pem"
""",
            )

    print(f"Reading configuration file {str(MAIN_CONFIG)!r}...\n")

    with open(MAIN_CONFIG, "rb") as fp:
        config = tomllib.load(fp)

    main_section = config.get("main", {})

    target = main_section.get("printer", None)
    insecure_bind_port = main_section.get("port", None)
    secure_bind_port = main_section.get("ssl_port", None)

    hypercorn: dict[str, object] = config.get("hypercorn", {})

    print(f"Default Printer: {target}\n")

    if target == "None":
        print("No default device in config file.\n")

    ip_address: str | None = None
    if "--local" in sys.argv[1:]:
        ip_address = "127.0.0.1"

    try:
        serve_scanner(
            target,
            secure_bind_port=secure_bind_port,
            insecure_bind_port=insecure_bind_port,
            ip_addr=ip_address,
            hypercorn=hypercorn,
        )
    finally:
        database.unload_all()


if __name__ == "__main__":
    run()
