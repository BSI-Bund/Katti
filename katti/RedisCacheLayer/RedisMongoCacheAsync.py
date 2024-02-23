

class RedisMongoCacheAsyncio:
    def __init__(self, connection, signal_id=None):
        self._connection = connection
        self._signal_id = signal_id

    async def set_stop_signal(self, signal_id: str, set=True):
        await self.insert_value_pair(key=f'stop_signal_{signal_id}', value=str(set))

    async def is_stop_signal_set(self, signal_id: str):
        if not await self.get_value(f'stop_signal_{signal_id}'):
            return False
        return True

    async def get_signal(self, signal):
        if not await self._connection.get(f'{self._signal_id}{signal}'):
            return False
        else:
            return True

    async def set_signal(self, signal: str, ex=60):
        await self._connection.set(name=f'{self._signal_id}{signal}', value=1, ex=ex)

    async def delete_stop_signal(self, signal_id):
        await self._connection.delete(f'stop_signal_{signal_id}')

    async def insert_value_pair(self, key, value, ttl: int=0):
        if ttl <= 0:
            await self._connection.set(key, value)
        else:
            await self._connection.set(key, value, ex=ttl)

    async def get_value(self, key: str):
        return await self._connection.get(key)
