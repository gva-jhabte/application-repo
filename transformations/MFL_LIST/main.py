"""
MFL_LIST
"""
from flask import Flask
import datetime
from gva.data import Reader
from gva.data.validator import Schema
from gva.flows.operators import EndOperator, SaveToBucketOperator
from gva.data.formats.dictset import distinct
from operators import ExtractCvesFromTextOperator
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
    extract_cves = ExtractCvesFromTextOperator()
    save_to_bucket = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            date=context.get('date'),
            compress=context['config'].get('compress'))
    end = EndOperator()

    # chain the operations to create the flow
    flow = extract_cves > save_to_bucket > end

    # attach the writers
    flow.attach_writers(context['config'].get('writers', []))

    return flow


def create_data_reader(context: dict):
    reader = Reader(
            project=context['config'].get('source_project'),
            from_path=context['config'].get('source_path'),
            extention=context['config'].get('source_extention'),
            data_format=context['config'].get('source_format'),
            date_range=(context.get('look_at_date'), context.get('look_at_date')))
    return reader

@app.route('/ingest', methods=["POST"])
def main(context: dict = {}):
    context['config_file'] = 'MFL_LIST.metadata'
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    # the MFL isn't updated every day, so we probably need to look
    # back over previous days for the latest MFL
    found_mfl = False
    look_at_date = datetime.datetime.today()

    while not found_mfl:

        # the day to look for a copy of the MFL
        my_context = context.copy()
        my_context['look_at_date'] = look_at_date

        # create the data reader
        # convert to a list, the MFL is tiny (about 1Kb at time of writing)
        reader = list(create_data_reader(my_context))

        # if we found an MFL we can stop, otherwise look a day further in the past
        found_mfl = len(reader) > 0
        look_at_date = look_at_date - datetime.timedelta(1)

    # build the flow
    flow = build_flow(context)

    # execute the pipeline for each record in the reader
    for line in distinct(reader):
        flow.run(
                data=line,
                context=context,
                trace_sample_rate=context['config'].get('sample_rate'))

    # finalize the operators
    summary = flow.finalize()
    logger.trace(summary)
    return 'Finished Ingest'


if __name__ == "__main__":
    # app.run(ssl_context="adhoc", host="0.0.0.0", port=8080)
    app.run(host="0.0.0.0", port=8080)
