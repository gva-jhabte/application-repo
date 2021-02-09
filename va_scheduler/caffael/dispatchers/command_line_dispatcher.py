from .base_dispatcher import BaseDispatcher
import subprocess  #nosec - CYBASIMP-162
import warnings


class CommandLineDispatcher(BaseDispatcher):
    """
    A simple dispatcher which executes the command line.

    DO NOT USE IN PRODUCTION
    """
    def __init__(self, *args, **kwargs):
        warnings.warn("CommandLineDispatcher is not safe for production systems.")
        super().__init__(*args, **kwargs)

    def on_event(self, payload):
        result = subprocess.run(*self.args, **self.kwargs, stdout=subprocess.PIPE) #nosec - CYBASIMP-163
        result = result.stdout.decode('utf8').rstrip('\n')
        self.on_completion(result)
