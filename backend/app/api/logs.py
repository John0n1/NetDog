from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Depends, Query, status
from fastapi.exceptions import WebSocketException
from sqlalchemy.ext.asyncio import AsyncSession
import redis.asyncio as redis
import json
from typing import Set, Optional
import asyncio

from app.config import get_settings
from app.database import get_db
from app.api.auth import decode_token

settings = get_settings()
router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
    
    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)
    
    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)
    
    async def broadcast(self, message: str):
        for connection in self.active_connections.copy():
            try:
                await connection.send_text(message)
            except Exception:
                self.active_connections.discard(connection)


manager = ConnectionManager()


@router.websocket("/ws/logs")
async def websocket_logs(websocket: WebSocket, token: Optional[str] = Query(None)):
    """WebSocket endpoint for streaming logs"""
    
    # Verify token before accepting connection
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    try:
        decode_token(token)
    except Exception as e:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await manager.connect(websocket)
    
    # Connect to Redis for pub/sub
    r = await redis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe("logs:general")
    
    try:
        # Send initial connection message
        await websocket.send_json({
            "type": "console.log",
            "data": {
                "timestamp": asyncio.get_event_loop().time(),
                "level": "INFO",
                "source": "console",
                "text": "Connected to log stream"
            }
        })
        
        # Listen for messages from Redis and client
        async def listen_redis():
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        await websocket.send_text(message["data"])
                    except Exception:
                        break
        
        async def listen_client():
            while True:
                try:
                    data = await websocket.receive_text()
                    # Echo pong for ping messages
                    await websocket.send_json({"type": "pong"})
                except WebSocketDisconnect:
                    break
                except Exception:
                    break
                await asyncio.sleep(0.1)
        
        # Run both listeners concurrently
        await asyncio.gather(listen_redis(), listen_client())
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)
        await pubsub.unsubscribe()
        await r.aclose()


@router.websocket("/ws/scan/{scan_id}")
async def websocket_scan_updates(websocket: WebSocket, scan_id: str, token: Optional[str] = Query(None)):
    """WebSocket endpoint for scan progress updates"""
    
    # Verify token before accepting connection
    if not token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    try:
        decode_token(token)
    except Exception as e:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    
    await manager.connect(websocket)
    
    # Connect to Redis for pub/sub
    r = await redis.from_url(settings.redis_url, encoding="utf-8", decode_responses=True)
    pubsub = r.pubsub()
    await pubsub.subscribe(f"scan:{scan_id}")
    
    try:
        # Send initial connection confirmation
        await websocket.send_json({
            "type": "connected",
            "scan_id": scan_id
        })
        
        # Listen for scan updates
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    await websocket.send_text(message["data"])
                except Exception:
                    break
    
    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        manager.disconnect(websocket)
        await pubsub.unsubscribe()
        await r.aclose()
