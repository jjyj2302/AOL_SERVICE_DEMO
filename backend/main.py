import logging
import os
from typing import List
import asyncio
import json
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

import app.core.config.fastapi_config as fastapi_config

from app.core import healthcheck
from app.core.database import SessionLocal, engine, Base
from app.core.settings.api_keys.routers import api_keys_settings_routes, service_config_routes
from app.core.settings.modules.routers import modules_settings_routes
from app.core.settings.general.routers import general_settings_routes
from app.core.settings.keywords.routers import keywords_settings_routes
from app.core.settings.cti_profile.routers import cti_profile_settings_routes
from app.core.settings.api_keys.crud import api_keys_settings_crud

from app.core.settings.api_keys.config.create_defaults import add_default_api_keys

# IOC Tools imports
from app.features.ioc_tools.ioc_extractor.routers import internal_ioc_extractor_routes
from app.features.ioc_tools.ioc_defanger.routers import internal_defang_routes
from app.features.ioc_tools.ioc_lookup.bulk_lookup.routers import bulk_ioc_lookup_routes
from app.features.ioc_tools.ioc_lookup.single_lookup.routers import single_ioc_lookup_routes

# Threat Hunter imports
from app.features.threat_hunter_copy.routers.threat_hunter_routes import threat_hunter_routes as threat_hunter_router
# from app.features.threat_hunter_copy.test_router import router as threat_hunter_test_router
from app.features.crew_solo.solo_router import router as crew_solo_router

from app.core.settings.general.models.general_settings_models import Settings
from app.core.settings.modules.models.modules_settings_models import ModuleSettings


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

allowed_origins = os.getenv("ALLOWED_ORIGINS", "*").split(",")


# Create database tables
try:
    Base.metadata.create_all(bind=engine)
    logger.info("Database tables created successfully")
except Exception as e:
    logger.error(f"Failed to create database tables: {str(e)}")
    raise


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    logger.info("Application starting up...")
    db = SessionLocal()
    try:
        await initialize_defaults(db)

        # API Key Cache 초기화
        from app.core.settings.api_keys.cache import APIKeyCache
        api_cache = APIKeyCache.get_instance()
        api_cache.load_all_keys(db)

        logger.info("Application startup completed successfully")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise
    finally:
        db.close()

    yield

    # Shutdown
    logger.info("Application shutting down...")
    logger.info("Application shutdown completed successfully")


app = FastAPI(
    title=fastapi_config.APP_TITLE,
    description=fastapi_config.DESCRIPTION,
    version=fastapi_config.APP_VERSION,
    contact=fastapi_config.CONTACT_INFO,
    license_info=fastapi_config.LICENSE_INFO,
    openapi_tags=fastapi_config.TAGS_METADATA,
    swagger_ui_parameters=fastapi_config.SWAGGER_UI_PARAMETERS,
    lifespan=lifespan 
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Router includes
routers = [
    # System
    healthcheck.router,

    # Settings
    api_keys_settings_routes.router,
    service_config_routes.router,
    general_settings_routes.router,
    modules_settings_routes.router,
    keywords_settings_routes.router,
    cti_profile_settings_routes.router,

    # IOC Tools
    internal_ioc_extractor_routes.router,
    internal_defang_routes.router,
    bulk_ioc_lookup_routes.router,
    single_ioc_lookup_routes.router,

    # Threat Hunter
    threat_hunter_router,
    # threat_hunter_test_router,  # Temporary test endpoint for Pydantic outputs
    crew_solo_router,  # Individual agent execution endpoints
]

for router in routers:
    app.include_router(router)




async def add_default_general_settings(db: Session) -> None:
    """Add default general settings if they don't exist."""
    try:
        existing_settings = db.query(Settings).filter(Settings.id == 0).first()
        if not existing_settings:
            default_settings = Settings(id=0, darkmode=True)
            db.add(default_settings)
            db.commit()
            logger.info('Created default general settings')
    except SQLAlchemyError as e:
        logger.error(f'Failed to add default general settings: {str(e)}')
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to add default settings")

async def add_default_module_settings(db: Session) -> None:
    """Add default module settings if they don't exist."""
    default_modules = [
        ("Newsfeed", True),
        ("IOC Tools", True),
        ("Email Analyzer", True),
        ("Domain Finder", True),
        ("AI Templates", True),
        ("CVSS Calculator", True),
        ("Detection Rules", True)
    ]
    
    try:
        for name, enabled in default_modules:
            existing = db.query(ModuleSettings).filter(ModuleSettings.name == name).first()
            if not existing:
                db.add(ModuleSettings(name=name, enabled=enabled))
        
        db.commit()
        logger.info('Default module settings checked/created')
    except SQLAlchemyError as e:
        logger.error(f'Failed to add default module settings: {str(e)}')
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to add module settings")

async def initialize_defaults(db: Session) -> None:
    """Initialize all default settings concurrently."""
    try:
        await asyncio.gather(
            add_default_general_settings(db),
            add_default_module_settings(db),
            add_default_api_keys(db)
        )
    except Exception as e:
        logger.error(f"Failed to initialize defaults: {str(e)}")
        raise
