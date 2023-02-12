# -*- coding: utf-8 -*-
"""Generate files using Jinja2 Module."""

import logging
import os
from jinja2 import Environment, FileSystemLoader

LOGGER = logging.getLogger(__name__)


class JinjaTemplate:
    """Define Jinja Template object to generate files."""

    def __init__(self, vars_to_render: dict, template_name: str, file_name: str):
        """Create Dynamo DB resource."""
        self.var_to_render = vars_to_render
        self.template = template_name
        self.file_rendered = file_name

    def file(self, templates_dir='templates') -> None:
        """Render a file. Default location is ./templates"""
        # chroot to the current directory
        root = os.path.dirname(os.path.abspath(__file__))
        # Specify the directory where the jinja2 templete files are located.
        templates_dir = os.path.join(root, templates_dir)
        env = Environment(loader=FileSystemLoader(templates_dir))
        # Full path to the Jinja2 template file.
        template = env.get_template(self.template)
        # Render a file from the Jinja2 template
        # output_dir = '/tmp/'
        output_dir = './files/'
        output_file = output_dir + self.file_rendered
        with open(output_file, 'w+', encoding="utf8") as new_file:
            new_file.write(template.render(self.var_to_render))


def render_file(vars_to_render: dict, jinja_template: str, rendered_file: str) -> None:
    """Render Jinja2 Template."""

    render = JinjaTemplate(
        vars_to_render,     # Variables mentioned in the Jinja2 template
        jinja_template,     # Jinja2 template file name
        rendered_file       # Output file name
    )

    render.file()
    LOGGER.info(f"File {rendered_file} has been successfully rendered.")

    del render
