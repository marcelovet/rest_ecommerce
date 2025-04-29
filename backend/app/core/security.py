
        """Get statistics about IP security checks"""
        if not cls._redis_client:
            return {"error": "Redis not available"}
            
        try:
            # Get basic stats
            total_checks = int(await cls._redis_client.get("ip_security:checks_total") or 0)
            suspicious_total = int(await cls._redis_client.get("ip_security:suspicious_total") or 0)
            
            # Get recent suspicious IPs
            recent_suspicious = await cls._redis_client.smembers("ip_security:recent_suspicious")
            
            # Get recent events
            recent_event_ids = await cls._redis_client.lrange("ip_security:recent_events", 0, 9)
            recent_events = []
            
            for event_id in recent_event_ids:
                event_data = await cls._redis_client.hgetall(f"ip_event:{event_id}")
                if event_data:
                    try:
                        if "details" in event_data:
                            event_data["details"] = json.loads(event_data["details"])
                    except json.JSONDecodeError:
                        pass
                    recent_events.append(event_data)
            
            # Return stats
            return {
                "total_checks": total_checks,
                "suspicious_total": suspicious_total,
                "suspicious_rate": round(suspicious_total / total_checks * 100, 2) if total_checks else 0,
                "recent_suspicious_count": len(recent_suspicious),
                "recent_suspicious": list(recent_suspicious),
                "recent_events": recent_events,
                "updated_at": datetime.now(UTC).isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get IP security stats: {e}")
            return {"error": str(e)}