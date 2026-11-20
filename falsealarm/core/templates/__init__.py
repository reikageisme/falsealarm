"""Nuclei-compatible template engine (loader, DSL, matchers, executor)."""

from falsealarm.core.templates.executor import TemplateExecutor, target_variables
from falsealarm.core.templates.loader import (
    DEFAULT_EXCLUDE_TAGS,
    LoadReport,
    Template,
    TemplateFilter,
    load_template_file,
    load_templates,
)

__all__ = [
    "DEFAULT_EXCLUDE_TAGS",
    "LoadReport",
    "Template",
    "TemplateExecutor",
    "TemplateFilter",
    "load_template_file",
    "load_templates",
    "target_variables",
]
