"""Application configuration settings for the AOL."""

# App metadata
APP_TITLE = "AOL"
APP_VERSION = "0.1"
DESCRIPTION = """
## AOL interactive API documentation
"""

# Contact information
CONTACT_INFO = {
    "name": "Lars Ursprung",
    "url": "https://github.com/dev-lu",
    "email": "larsursprung@gmail.com",
}

# License information
LICENSE_INFO = {
    "name": "MIT License",
    "url": "https://mit-license.org/",
}

# OpenAPI tags metadata
TAGS_METADATA = [
    {"name": "AI Templates", "description": ""},
    {"name": "Alerts", "description": ""},
    {"name": "IOC Lookup", "description": "Services to lookup Indicators of Compromise."},
    {"name": "IOC Extractor", "description": ""},
    {"name": "Mail Analyzer", "description": ""},
    {"name": "Newsfeed", "description": ""},
    {"name": "Settings", "description": ""},
]

# Swagger UI parameters
SWAGGER_UI_PARAMETERS = {"docExpansion": "none"}