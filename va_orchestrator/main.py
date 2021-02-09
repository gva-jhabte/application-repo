import networkx as nx
import yaml
from subprocess import call  #nosec - CYBASIMP-158
import datetime

CONFIG_FILE = r'../config/va_orchestrator.yaml'

# load the orchestration yaml
with open(CONFIG_FILE, 'r') as f:
    yaml_config = yaml.safe_load(f)


# build a graph of the jobs
job_graph = nx.DiGraph()
for job_name in yaml_config.get('jobs'):
    job = yaml_config.get('jobs').get(job_name)
    job_graph.add_node(job_name, 
                       id=job_name, 
                       type=job.get('type'), 
                       working_directory=job.get('working_directory'), 
                       script=job.get('script'),
                       executed=False)
    job_requirements = job.get('requires')
    if job_requirements != None and job_requirements != 'NONE':
        for job_requirement in job_requirements:
            job_graph.add_edge(job_requirement, job_name, relationship='feeds')


# validate there's no loops and no missing dependencies
pass

limiter = 100

# while there are uncompleted jobs
not_run_jobs = [x for x,y in job_graph.nodes(data=True) if y.get('executed') == False]
while len(not_run_jobs) > 0 and limiter > 50:
    limiter = limiter - 1
    
    print("Jobs left to run: {}".format(len(not_run_jobs)))
    
    for job in not_run_jobs:
        # find a job with no unmet dependencies
        dependencies_run = True
        for dependency in job_graph.nodes()[job].get('requires') or []:
            dependencies_run = dependencies_run and job_graph.nodes()[dependency].get('executed')
        if dependencies_run:
            # execute the job
            
            print('running job: {}'.format(job))
            job_details = job_graph.nodes()[job]
            job_details['start_time'] = datetime.datetime.today().isoformat()

            if (job_details.get('type') == 'python-script'):
                try:
                    result = call(["python", job_details.get('script')], cwd=job_details.get('working_directory')) #nosec - CYBASIMP-160, CYBASIMP-161
                except:
                    result = -1
                print('result:{}'.format(result))
            
            job_details['execution_result'] = result
            job_details['executed'] = True
            job_details['end_time'] = datetime.datetime.today().isoformat()

            continue

    #not_run_jobs = [x for x,y in job_graph.nodes(data=True) if y.get('executed') == False]
    not_run_jobs = []


# save the graph with the results
nx.write_graphml(job_graph, datetime.datetime.today().strftime(yaml_config.get('output_file')))