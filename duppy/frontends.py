import abc


class Frontend(abc.ABC):
    def __init__(self, backend):
        self.backend = backend

    @abc.abstractmethod
    async def get_tasks(self):
        ...
