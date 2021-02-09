"""
MITRE_EDB_MAP
"""
from flask import Flask
from gva.data.validator import Schema
from gva.flows.operators import EndOperator, SaveToBucketOperator
from operators import AcquireExploitDbReference
from gva.utils.common import build_context
from flask_sslify import SSLify
from flask_cors import CORS


from gva.logging import get_logger
logger = get_logger()
logger.setLevel(5)

app = Flask(__name__)
CORS(app, supports_credentials=True)
sslify = SSLify(app)

def build_flow(context: dict):

    # define the operations in the flow
    acquire = AcquireExploitDbReference()
    save_to_bucket = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            date=context.get('date'),
            compress=context['config'].get('compress'))
    end = EndOperator()

    # chain the operations to create the flow
    flow = acquire > save_to_bucket > end

    # attach the writers
    flow.attach_writers(context['config'].get('writers', []))

    return flow

@app.route('/ingest', methods=["POST"])
def main(context: dict = {}):
    context['config_file'] = 'MITRE_EDB_MAP.metadata'
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    # create the flow
    flow = build_flow(context)
    flow.run(
        data={},
        context=context,
        trace_sample_rate=context['config'].get('sample_rate'))

    # finalize the operators
    summary = flow.finalize()
    logger.trace(summary)
    return 'Finished Ingest'

if __name__ == "__main__":
    app.run(ssl_context="adhoc", host="0.0.0.0", port=8080)