"""
QVM_FINDINGS
"""
import xmltodict
import datetime
from gva.data import Reader
from gva.data.validator import Schema
from gva.flows.operators import EndOperator, SaveToBucketOperator
from operators import ExtractFindingsPerHost
from gva.utils.common import date_range, build_context

from gva.logging import get_logger
logger = get_logger()
logger.setLevel(5)


def build_flow(context: dict):

    # define the operations in the flow
    extract_findings = ExtractFindingsPerHost()
    save_to_bucket = SaveToBucketOperator(
            project=context['config'].get('target_project'),
            to_path=context['config'].get('target_path'),
            schema=Schema(context),
            date=context.get('date'),
            compress=context['config'].get('compress'))
    end = EndOperator()

    # chain the operations to create the flow
    flow = extract_findings > save_to_bucket > end

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


def execute_day_of_processing(context: dict = {}):
    # create the data reader and the flow
    reader = create_data_reader(context)
    flow = build_flow(context)

    # execute the pipeline for each record in the reader
    for line in reader:
        finding = xmltodict.parse(line)['HOST']
        
        my_context = context.copy()
        flow.run(
                data=finding,
                context=my_context,
                trace_sample_rate=context['config'].get('sample_rate'))

    # tell the flow to finalize any actions
    summary = flow.finalize()
    logger.trace(summary)


def main(context: dict = {}):
    # create the run context from the config and context passed to main
    # this would allow dates etc to be passed from something external
    context = build_context(**context)

    # get or default the dates
    start_date = context.get('start_date', datetime.date.today())
    end_date = context.get('end_date', datetime.date.today())

    # for each date in the range - run the daily job
    for date in date_range(start_date, end_date):
        logger.info(F'Starting QVM_FINDINGS job for {date}')
        my_context = context.copy()
        my_context['date'] = date
        execute_day_of_processing(context=my_context)
        logger.info(F'Completed QVM_FINDINGS job for {date}')


if __name__ == "__main__":
    context = {}
    context['config_file'] = 'QVM_FINDINGS.metadata'
    # context['start_date'] = datetime.date(2020, 12, 9)
    main(context)
