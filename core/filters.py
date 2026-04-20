"""
Template filters for ARISE SOAR
"""
import json


def register_filters(app):
    @app.template_filter('from_json')
    def from_json_filter(value):
        try:
            return json.loads(value or "[]")
        except (ValueError, TypeError):
            return []
