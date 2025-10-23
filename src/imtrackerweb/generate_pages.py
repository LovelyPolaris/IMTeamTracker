#!/usr/bin/env python3

"""Generate pages for the sane scanner web server.

Copyright (C) 2022-2025  CoolCat467

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

__title__ = "Generate Pages"
__author__ = "CoolCat467"
__license__ = "GNU General Public License Version 3"


import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

from imtrackerweb import htmlgen, server

if TYPE_CHECKING:
    from collections.abc import Callable

MODULE: Final = Path(__file__).absolute().parent
SOURCE_ROOT: Final = MODULE.parent.parent

TEMPLATE_FOLDER: Final = MODULE / "templates"
TEMPLATE_FUNCTIONS: dict[Path, Callable[[], str]] = {}
STATIC_FOLDER: Final = MODULE / "static"
STATIC_FUNCTIONS: dict[Path, Callable[[], str]] = {}


def save_content(path: Path, content: str) -> None:
    """Save content to given path."""
    path.write_text(content + "\n", encoding="utf-8")
    print(f"Saved content to {path}")


def save_template_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated template as filename."""
    path = TEMPLATE_FOLDER / f"{filename}.html.jinja"

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if path in TEMPLATE_FUNCTIONS:
            raise NameError(
                f"{filename!r} already exists as template filename",
            )
        TEMPLATE_FUNCTIONS[path] = function
        return function

    return function_wrapper


def save_static_as(
    filename: str,
) -> Callable[[Callable[[], str]], Callable[[], str]]:
    """Save generated static file as filename."""
    path = STATIC_FOLDER / filename

    def function_wrapper(function: Callable[[], str]) -> Callable[[], str]:
        if path in STATIC_FUNCTIONS:
            raise NameError(f"{filename!r} already exists as static filename")
        STATIC_FUNCTIONS[path] = function
        return function

    return function_wrapper


@save_static_as("style.css")
def generate_style_css() -> str:
    """Generate style.css static file."""
    mono = "SFMono-Regular,SF Mono,Menlo,Consolas,Liberation Mono,monospace"
    return "\n".join(
        (
            htmlgen.css(
                ("*", "*::before", "*::after"),
                box_sizing="border-box",
                font_family="Lucida Console",
            ),
            htmlgen.css(("h1", "footer"), text_align="center"),
            htmlgen.css(("html", "body"), height="100%"),
            htmlgen.css(
                "body",
                line_height=1.5,
                _webkit_font_smoothing="antialiased",
                display="flex",
                flex_direction="column",
            ),
            htmlgen.css(".content", flex=(1, 0, "auto")),
            htmlgen.css(
                ".footer",
                flex_shrink=0,
            ),
            htmlgen.css(
                ("img", "picture", "video", "canvas", "svg"),
                display="block",
                max_width="100%",
            ),
            htmlgen.css(
                ("input", "button", "textarea", "select"),
                font="inherit",
            ),
            htmlgen.css(
                ("p", "h1", "h2", "h3", "h4", "h5", "h6"),
                overflow_wrap="break-word",
            ),
            htmlgen.css(
                ("#root", "#__next"),
                isolation="isolate",
            ),
            htmlgen.css(
                "code",
                padding=("0.2em", "0.4em"),
                background_color="rgba(158,167,179,0.4)",
                border_radius="6px",
                font_family=mono,
                line_height=1.5,
            ),
            htmlgen.css(
                "::placeholder",
                font_style="italic",
            ),
            htmlgen.css(
                ".box",
                background="ghostwhite",
                padding="0.5%",
                border_radius="4px",
                border=("2px", "solid", "black"),
                margin="0.5%",
                width="fit-content",
            ),
            htmlgen.css(
                "#noticeText",
                font_size="10px",
                display="inline-block",
                white_space="nowrap",
            ),
            htmlgen.css(
                'input[type="submit"]',
                border=("1.5px", "solid", "black"),
                border_radius="4px",
                padding="0.5rem",
                margin_left="0.5rem",
                margin_right="0.5rem",
                min_width="min-content",
            ),
            htmlgen.css(
                "@media (prefers-color-scheme: dark)",
                htmlgen.css(
                    "body",
                    background_color="#181818",
                    color="#e0e0e0",
                ),
                htmlgen.css(
                    ".box",
                    background_color="#1e1e1e",
                    border=("2px", "solid", "#444"),
                ),
                htmlgen.css(
                    "code",
                    background_color="rgba(255, 255, 255, 0.1)",
                ),
                htmlgen.css(
                    ("input", "button"),
                    background_color="#1e1e1e",
                    color="#e0e0e0",
                    border=("2px", "solid", "#444"),
                ),
            ),
        ),
    )


def template(
    title: str,
    body: str,
    *,
    head: str = "",
    body_tag: dict[str, htmlgen.TagArg] | None = None,
    lang: str = "en",
) -> str:
    """HTML Template for application."""
    head_data = "\n".join(
        (
            htmlgen.tag(
                "link",
                rel="stylesheet",
                type_="text/css",
                href="/style.css",
            ),
            head,
        ),
    )

    join_body = (
        htmlgen.wrap_tag("h1", title, False),
        body,
    )

    footer = f"{server.__title__} v{server.__version__} © {server.__author__}"

    body_data = "\n".join(
        (
            htmlgen.wrap_tag(
                "div",
                "\n".join(join_body),
                class_="content",
            ),
            htmlgen.wrap_tag(
                "footer",
                "\n".join(
                    (
                        # Maybe remove in the future, but kind of funny
                        htmlgen.wrap_tag(
                            "i",
                            "If you're reading this, the web server was installed correctly.™",
                            block=False,
                        ),
                        htmlgen.tag("hr"),
                        htmlgen.wrap_tag(
                            "p",
                            footer,
                            block=False,
                        ),
                    ),
                ),
            ),
        ),
    )

    return htmlgen.template(
        title,
        body_data,
        head=head_data,
        body_tag=body_tag,
        lang=lang,
    )


@save_template_as("error_page")
def generate_error_page() -> str:
    """Generate error response page."""
    error_text = htmlgen.wrap_tag("p", htmlgen.jinja_expression("error_body"))
    content = "\n".join(
        (
            error_text,
            htmlgen.tag("br"),
            htmlgen.jinja_if_block(
                {
                    "return_link": "\n".join(
                        (
                            htmlgen.create_link(
                                htmlgen.jinja_expression("return_link"),
                                "Return to previous page",
                            ),
                            htmlgen.tag("br"),
                        ),
                    ),
                },
            ),
            htmlgen.create_link("/", "Return to main page"),
        ),
    )
    body = htmlgen.contain_in_box(content)
    return template(
        htmlgen.jinja_expression("page_title"),
        body,
    )


@save_template_as("signup_get")
def generate_signup_get() -> str:
    """Generate /signup get page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "username",
                "Username:",
                attrs={
                    "placeholder": "Your LPS ID",
                    "autocomplete": "off",
                    "autofocus": "",
                    "required": "",
                },
            ),
            htmlgen.input_field(
                "password",
                "Password:",
                field_type="password",
                attrs={
                    "placeholder": "Secure password",
                    "required": "",
                },
            ),
        ),
    )

    form = htmlgen.form("signup", contents, "Sign up")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.wrap_tag(
                "i",
                "Password needs at least 7 different characters",
                block=False,
            ),
            htmlgen.link_list(
                {
                    "/login": "Already have an account?",
                },
            ),
        ),
    )
    return template("Sign up", body)


@save_template_as("signup_post")
def generate_signup_post() -> str:
    """Generate /signup post page."""
    text = (
        "Sent an email to {{ email }} containing "
        + "your a link to verify your account."
    )
    body = htmlgen.wrap_tag("p", text, False)
    return template("Check your email", body)


@save_template_as("login_get")
def generate_login_get() -> str:
    """Generate /login get page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "username",
                "Username:",
                attrs={
                    "placeholder": "Username",
                    "autofocus": "",
                    "required": "",
                },
            ),
            htmlgen.input_field(
                "password",
                "Password:",
                field_type="password",
                attrs={
                    "placeholder": "Password",
                    "required": "",
                },
            ),
        ),
    )

    form = htmlgen.form("login", contents, "Sign In")
    body = "<br>\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.wrap_tag(
                "i",
                "Ask an administrator if you need to create an account",
            ),
        ),
    )
    return template("Login", body)


@save_template_as("add_tickets_get")
def generate_add_tickets_get() -> str:
    """Generate /add-tickets get page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "id",
                "Student ID Number",
                field_type="text",
                attrs={
                    "autofocus": "",
                    "autocomplete": "off",
                    "required": "",
                    "placeholder": "LPS Student ID",
                    "pattern": "[0-9]{6}",
                },
            ),
            htmlgen.input_field(
                "ticket_count",
                "Number of Tickets",
                field_type="number",
                attrs={
                    "required": "",
                    "value": 1,
                    "min": 1,
                    "max": 10,
                },
            ),
        ),
    )
    form = htmlgen.form("add-tickets", contents, "Submit")
    body = htmlgen.contain_in_box(form)
    return template("Add Tickets For Student", body)


@save_template_as("add_tickets_post")
def generate_add_tickets_post() -> str:
    """Generate /add-tickets post page."""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "p",
                    "Added {{ ticket_count }} ticket{{ plural }} "
                    + "for {{ student_id }}",
                    block=False,
                ),
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/tickets": "Display tickets for user",
                    "/logout": "Log Out",
                },
            ),
        ),
    )
    return template("Added Tickets", body)


@save_template_as("subtract_tickets_get")
def generate_subtract_tickets_get() -> str:
    """Generate /subtract-tickets get page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "id",
                "Student ID Number",
                field_type="text",
                attrs={
                    "autofocus": "",
                    "autocomplete": "off",
                    "required": "",
                    "placeholder": "LPS Student ID",
                    "pattern": "[0-9]{6}",
                },
            ),
            htmlgen.input_field(
                "ticket_count",
                "Number of Tickets",
                field_type="number",
                attrs={
                    "required": "",
                    "value": 1,
                    "min": 1,
                    "max": 100,
                },
            ),
        ),
    )
    form = htmlgen.form("add-tickets", contents, "Submit")
    body = htmlgen.contain_in_box(form)
    return template("Subtract Tickets From Student", body)


@save_template_as("subtract_tickets_post")
def generate_subtract_tickets_post() -> str:
    """Generate /subtract-tickets post page."""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "p",
                    "Subtracted {{ ticket_count }} ticket{{ plural }} "
                    "from {{ student_id }}. They now have {{ tickets_left }} "
                    "ticket{{ plural_left }}.",
                    block=False,
                ),
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/tickets": "Display tickets for user",
                    "/logout": "Log Out",
                },
            ),
        ),
    )
    return template("Subtracted Tickets", body)


@save_template_as("settings_get")
def generate_settings_get() -> str:
    """Generate /settings get page."""
    links = {
        "/settings/change-password": "Change Password",
    }
    body = "\n".join(
        (
            htmlgen.contain_in_box(htmlgen.link_list(links)),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                },
            ),
        ),
    )
    return template("User Settings", body)


@save_template_as("settings_change_password_get")
def generate_settings_change_password_get() -> str:
    """Generate /settings/change-password get page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "current_password",
                "Current Password:",
                field_type="password",
                attrs={
                    "placeholder": "Your current password",
                    "autofocus": "",
                    "required": "",
                },
            ),
            htmlgen.input_field(
                "new_password",
                "New Password:",
                field_type="password",
                attrs={
                    "placeholder": "New secure password",
                    "required": "",
                },
            ),
        ),
    )
    form = htmlgen.form(
        "change_password",
        contents,
        "Change Password",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "All Account Settings",
                },
            ),
        ),
    )
    return template("Change Password", body)


@save_template_as("settings_change_password_post")
def generate_settings_change_password_post() -> str:
    """Generate /settings/change-password post page."""
    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "p",
                    "Password changed successfully",
                    block=False,
                ),
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "All Account Settings",
                },
            ),
        ),
    )
    return template("Password Changed", body)


@save_template_as("invite_teacher_get")
def generate_invite_teacher_get() -> str:
    """Generate /invite-teacher get page."""
    contents = htmlgen.input_field(
        "new_account_username",
        "New Account Username (3-16 lowercase characters)",
        attrs={
            "placeholder": "LPS Staff Username",
            "autocomplete": "off",
            "autofocus": "",
            "required": "",
            "pattern": "[a-z2-9]{3,16}",
        },
    )
    form = htmlgen.form(
        "invite-teacher",
        contents,
        "Create New Account",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                },
            ),
        ),
    )
    return template("Invite A Teacher", body)


@save_template_as("invite_teacher_post")
def generate_invite_teacher_post() -> str:
    """Generate /invite-teacher post page."""
    body = "\n".join(
        (
            htmlgen.wrap_tag(
                "p",
                "Created new account with login credentials:",
                block=False,
            ),
            htmlgen.contain_in_box(
                "".join(
                    (
                        "Username: ",
                        htmlgen.wrap_tag(
                            "code",
                            "{{ new_account_username }}",
                            block=False,
                        ),
                        "\n",
                        htmlgen.tag("br"),
                        "\n",
                        "Password: ",
                        htmlgen.wrap_tag(
                            "code",
                            "{{ password }}",
                            block=False,
                        ),
                    ),
                ),
            ),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "i",
                "Password can be changed in settings later",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "strong",
                "Please write this down, it will not be viewable again!",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                    "/invite-teacher": "Invite Another Teacher",
                },
            ),
        ),
    )

    return template("Created New Account!", body)


@save_template_as("invite_manager_get")
def generate_invite_manager_get() -> str:
    """Generate /invite-manager get page."""
    contents = htmlgen.input_field(
        "new_account_username",
        "New Account Username (3-16 lowercase characters)",
        attrs={
            "placeholder": "LPS Staff Username",
            "autofocus": "",
            "autocomplete": "off",
            "required": "",
            "pattern": "[a-z2-9]{3,16}",
        },
    )
    form = htmlgen.form(
        "invite-manager",
        contents,
        "Create New Account",
    )
    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                },
            ),
        ),
    )
    return template("Invite A Manager", body)


@save_template_as("invite_manager_post")
def generate_invite_manager_post() -> str:
    """Generate /invite-manager post page."""
    body = "\n".join(
        (
            htmlgen.wrap_tag(
                "p",
                "Created new account with login credentials:",
                block=False,
            ),
            htmlgen.contain_in_box(
                "".join(
                    (
                        "Username: ",
                        htmlgen.wrap_tag(
                            "code",
                            htmlgen.jinja_expression("new_account_username"),
                            block=False,
                        ),
                        "\n",
                        htmlgen.tag("br"),
                        "\n",
                        "Password: ",
                        htmlgen.wrap_tag(
                            "code",
                            htmlgen.jinja_expression("password"),
                            block=False,
                        ),
                    ),
                ),
            ),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "i",
                "Password can be changed in settings later",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag(
                "strong",
                "Please write this down, it will not be viewable again!",
                block=False,
            ),
            htmlgen.tag("br"),
            htmlgen.tag("br"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                    "/logout": "Log Out",
                    "/settings": "Account Settings",
                    "/add-tickets": "Add Tickets for Student",
                    "/invite-teacher": "Invite a Teacher",
                    "/invite-manager": "Invite Another Manager",
                },
            ),
        ),
    )

    return template("Created New Account!", body)


@save_template_as("ticket_form")
def generate_ticket_form() -> str:
    """Generate tickets get ticket form page."""
    contents = "<br>\n".join(
        (
            htmlgen.input_field(
                "student_id",
                "Student ID:",
                attrs={
                    "placeholder": "Student ID Number",
                    "autocomplete": "off",
                    "autofocus": "",
                    "required": "",
                    "pattern": "[0-9]{6}",  # If ever more than 6 change here
                },
            ),
        ),
    )

    form = htmlgen.form(
        "get_student_id",
        contents,
        "Display Tickets",
    )

    body = "\n".join(
        (
            htmlgen.contain_in_box(form),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/": "Return to main page",
                },
            ),
        ),
    )
    return template("Enter ID", body)


@save_template_as("ticket_count_page")
def generate_ticket_count_page() -> str:
    """Generate tickets get ticket count page."""
    teacher_case = {
        'user_type in ("teacher", "manager", "admin")': htmlgen.link_list(
            {
                "/add-tickets": "Add Tickets for Student",
            },
        ),
    }

    manager_case = {
        'user_type in ("manager", "admin")': htmlgen.link_list(
            {
                "/subtract-tickets": "Subtract Tickets for Student",
            },
        ),
    }

    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.wrap_tag(
                    "h3",
                    "{{ username }} currently has {{ count }} tickets",
                    block=False,
                ),
            ),
            htmlgen.create_link("{{ user_link }}", "Link to this user"),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.link_list(
                {
                    "/tickets": "Display tickets for user",
                    "/": "Return to main page",
                },
            ),
            htmlgen.jinja_if_block(teacher_case),
            htmlgen.jinja_if_block(manager_case),
        ),
    )
    return template("Ticket Count", body)


@save_template_as("root_get")
def generate_root_get() -> str:
    """Generate / (root) get page."""
    login_link = htmlgen.create_link("/login", "this link")

    teacher_case = {
        'user_type in ("teacher", "manager", "admin")': htmlgen.link_list(
            {
                "/add-tickets": "Add Tickets for Student",
            },
        ),
    }

    manager_case = {
        'user_type in ("manager", "admin")': htmlgen.link_list(
            {
                "/subtract-tickets": "Subtract Tickets for Student",
            },
        ),
    }

    admin_case = {
        'user_type in ("admin")': htmlgen.link_list(
            {
                "/invite-teacher": "Invite Teacher",
                "/invite-manager": "Invite Manager",
            },
        ),
    }

    body = "\n".join(
        (
            htmlgen.contain_in_box(
                htmlgen.jinja_if_block(
                    {
                        'user_name == ""': htmlgen.wrap_tag(
                            "p",
                            f"Please log in at {login_link}.",
                        ),
                        "": htmlgen.wrap_tag(
                            "p",
                            "Hello logged in user {{ user_name }}.",
                        ),
                    },
                ),
            ),
            htmlgen.wrap_tag("p", "Links:", block=False),
            htmlgen.jinja_if_block(
                {
                    'user_name == ""': htmlgen.link_list(
                        {
                            "/login": "Log In",
                            # "/signup": "Sign Up",
                        },
                    ),
                    "": "\n".join(
                        (
                            htmlgen.link_list(
                                {
                                    # "/user_data": "[DEBUG] View user data",
                                    "/logout": "Log Out",
                                    "/settings": "Account Settings",
                                    "/tickets": "View ticket count",
                                },
                            ),
                            htmlgen.jinja_if_block(teacher_case),
                            htmlgen.jinja_if_block(manager_case),
                            htmlgen.jinja_if_block(admin_case),
                        ),
                    ),
                },
            ),
        ),
    )
    return template("Intramural Team Tracker", body)


def matches_disk_files(new_files: dict[Path, str]) -> bool:
    """Return if all new file contents match old file contents.

    Copied from src/trio/_tools/gen_exports.py, dual licensed under
    MIT and APACHE2.
    """
    for path, new_source in new_files.items():
        if not path.exists():
            return False
        # Strip trailing newline `save_content` adds.
        old_source = path.read_text(encoding="utf-8")[:-1]
        if old_source != new_source:
            return False
    return True


def process(do_test: bool) -> int:
    """Generate all page templates and static files. Return exit code."""
    new_files: dict[Path, str] = {}
    for filename, function in TEMPLATE_FUNCTIONS.items():
        new_files[filename] = function()
    for filename, function in STATIC_FUNCTIONS.items():
        new_files[filename] = function()

    matches_disk = matches_disk_files(new_files)

    if do_test:
        if not matches_disk:
            print("Generated sources are outdated. Please regenerate.")
            return 1
    elif not matches_disk:
        for path, new_source in new_files.items():
            save_content(path, new_source)
        print("\nRegenerated sources successfully.")
        # With pre-commit integration, show that we edited files.
        return 1
    print("Generated sources are up to date.")
    return 0


def run() -> int:
    """Regenerate all generated files."""
    parser = argparse.ArgumentParser(
        description="Generate static and template files",
    )
    parser.add_argument(
        "--test",
        "-t",
        action="store_true",
        help="test if code is still up to date",
    )
    parsed_args = parser.parse_args()

    # Double-check we found the right directory
    assert (SOURCE_ROOT / "LICENSE").exists()

    return process(do_test=parsed_args.test)


if __name__ == "__main__":
    print(f"{__title__}\nProgrammed by {__author__}.\n")
    sys.exit(run())
