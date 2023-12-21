# -*- coding: utf-8 -*-
"""Class to make a loop through a list and run function ."""

import concurrent.futures
import logging
import traceback
import botocore.exceptions  # pylint: disable=import-error

LOGGER = logging.getLogger(__name__)


def catch_errors(func: object) -> object:
    """Decorator for display errors from parallel processing."""

    def function_wrapper(arg):
        """Run the function and catch errors if any.

        https://stackoverflow.com/questions/64168385/returning-values-from-decorated-functions-in-python
        """

        result = None
        line_long = 80
        try:
            result = func(arg)

        except botocore.exceptions.ClientError as err:
            print(f"{'~' * line_long}\n{arg}\n{'~' * line_long}\n\n{err}\n{'-' * line_long}")  # pylint: disable=line-too-long # noqa: E501
            if err.response['Error']['Code'] == 'AccessDeniedException':
                LOGGER.error("Message: %s", err.response['Message'])
            elif err.response['Error']['Code'] == 'InvalidAccessException':
                LOGGER.error("Message: %s", err.response['Message'])
            else:
                LOGGER.error("Full error response:\n%s", err.response)

            traceback.print_tb(err.__traceback__)
            print('-' * line_long)

        except Exception as err:  # pylint: disable=broad-exception-caught
            print(f"{'~' * line_long}\n{arg}\n{'~' * line_long}\n\n{err}\n{'-' * line_long}")  # pylint: disable=line-too-long # noqa: E501
            traceback.print_tb(err.__traceback__)
            print('-' * line_long)

        return result

    return function_wrapper


class Looper:
    """Loop through AWS accounts inventory."""
    def __init__(self, items: list, f_callback: object):
        """Initialize class variables."""
        self.items = items
        self.f_callback = f_callback

    def serial(self) -> None:
        """Loop through all AWS accounts one by one."""

        @catch_errors
        def _run_func(item: dict) -> list:
            """Run function with item as argument."""
            self.f_callback(item)

        # Run process by item sequentially
        for item in self.items:
            _run_func(item)

    def parallel(self) -> None:
        """Loop through all AWS accounts in parallel."""

        @catch_errors
        def _run_func(item: dict) -> None:
            """Run function with item as argument."""
            self.f_callback(item)

        # Fan out processes by item in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            executor.map(_run_func, self.items)

    def parallel_return(self, summary=False) -> list:
        """Loop through all AWS accounts in parallel and fetch the result of
        each thread.

        https://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
        """

        @catch_errors
        def _run_func(item: dict) -> list:
            """Run function with item as argument."""
            result = self.f_callback(item)
            return result

        # Fan out processes by item in parallel
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = [
                executor.submit(_run_func, account) for account in self.items
            ]

        results = []
        result_counter = 0
        for future in futures:
            if future.result():
                results += future.result()
                result_counter += 1

        if summary:
            self.report_summary(len(futures), result_counter, len(results))

        return results

    def parallel_return_opt_1(self) -> list:
        """Loop through all AWS accounts in parallel and fetch the result of
        each thread.

        https://docs.python.org/3/library/concurrent.futures.html
        """
        @catch_errors
        def _run_func(item: dict) -> list:
            """Run function with item as argument."""
            result = self.f_callback(item)
            return result

        items = []
        result_counter = 0
        results = []
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_accounts = {
                executor.submit(_run_func, account): account for account in self.items  # noqa: E501
            }
            for future in concurrent.futures.as_completed(future_accounts):
                items.append(future_accounts[future])
                try:
                    if future.result():
                        results += future.result()
                        result_counter += 1

                except Exception as exc:  # pylint: disable=broad-exception-caught # noqa: E501
                    LOGGER.error(exc)

        self.report_summary(len(items), result_counter, len(results))
        return results

    def report_summary(self, items: int, with_result: int, results: int) -> None:  # noqa: E501
        """Display report summary."""
        print(f"\nNumber of processed items    : {items}")
        print(f"Number of items with results : {with_result}")
        print(f"Number of results            : {results}\n")
