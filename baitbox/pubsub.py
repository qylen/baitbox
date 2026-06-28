import asyncio
from typing import Set

class PubSub:
    def __init__(self):
        self.waiters: Set[asyncio.Queue] = set()

    async def publish(self, message: dict):
        for queue in self.waiters:
            await queue.put(message)

    async def subscribe(self) -> asyncio.Queue:
        queue = asyncio.Queue()
        self.waiters.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue):
        self.waiters.discard(queue)

pubsub = PubSub()
