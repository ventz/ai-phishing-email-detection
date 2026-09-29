"""Lambda handler shim: keeps the long-standing ``lambda_function.lambda_handler`` handler setting valid."""

from phishing_detector.handler import lambda_handler

__all__ = ["lambda_handler"]
