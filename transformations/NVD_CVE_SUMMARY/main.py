"""
NVD_CVE_SUMMARY
"""
import datetime
from gva.data.validator import Schema
from gva.flows.operators import EndOperator, SaveToBucketOperator
from operators import ExtractCveDetailsOperator
from gva.utils.common import build_context
from gva.data import Reader

from gva.logging import get_logger
logger = get_logger()
logger.setLevel(5)


def build_flow(context: dict):

    # define the operations in the flow
    extract = ExtractCveDetailsOperator()

    save_to_bucket = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            date=context.get('date'),
            compress=context['config'].get('compress'))

    end = EndOperator()

    # chain the operations to create the flow
    flow = extract > save_to_bucket > end

    # attach the writers
    flow.attach_writers(context['config'].get('writers', []))

    return flow


def create_data_reader(context: dict):
    reader = Reader(
            project=context['config'].get('source_project'),
            from_path=context['config'].get('source_path'),
            extention=context['config'].get('source_extention'),
            data_format=context['config'].get('source_format'),
            date_range=(context.get('date'), context.get('date')))
    return reader


def main(context: dict = {}):
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    reader = create_data_reader(context)

    # create the flow
    flow = build_flow(context)

    for record in reader:
        flow.run(
            data=record,
            context=context,
            trace_sample_rate=context['config'].get('sample_rate'))

    # finalize the operators
    summary = flow.finalize()
    logger.trace(summary)


if __name__ == "__main__":
    context = {}
    context['config_file'] = 'NVD_CVE_SUMMARY.metadata'
    main(context)
