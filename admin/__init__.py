"""Web admin panel (/admin). Phase 1: login, sessions, CSRF, layout, dashboard, settings, activity log.

Plain-Python layers (testable without FastAPI):  config, security, store, service, dashboard, envcheck
FastAPI layer (thin):                            core (route decorator + wiring), routes (built-in routes)

Later phases add routes with one decorator:

    from admin.core import admin_route
    @admin_route("POST", "/files/delete", action="files.delete", model=DeleteBody, confirm=True)
    async def files_delete(ctx, body): ...
"""
