"""
Job Orchestration
"""

from caffael.controllers import Scheduler
from caffael.dispatchers import CommandLineDispatcher
from caffael.triggers import CronTrigger
import time
import datetime

orchestrator_dispatcher = CommandLineDispatcher(["python", "main.py"], cwd="../va_orchestrator")
orchestrator_trigger = CronTrigger(schedule="30 06 * * *", dispatcher=orchestrator_dispatcher)

scheduler = Scheduler()
scheduler.add_trigger(orchestrator_trigger)
scheduler.execute()

while scheduler.running():          # this should be forever
    print(F'beat @ {datetime.datetime.now().isoformat()}')
    time.sleep(1800)                 # 30 minute loop
