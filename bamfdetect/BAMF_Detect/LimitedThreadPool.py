from multiprocessing.pool import ThreadPool
import Queue


class LimitedThreadPool(ThreadPool):
    def __init__(self, processes=None, initializer=None, initargs=(), max_queue_size=10000):
        self._max_queue_size = max_queue_size
        ThreadPool.__init__(self, processes, initializer, initargs)

    def _setup_queues(self):
        self._inqueue = Queue.Queue(self._max_queue_size)
        self._outqueue = Queue.Queue()
        self._quick_put = self._inqueue.put
        self._quick_get = self._outqueue.get