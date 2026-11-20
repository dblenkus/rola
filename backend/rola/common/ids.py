"""The range of ids that the API accepts."""

# The range of the 64-bit integers the databases store; a larger value would
# fail in the database instead of in the API's validation.
ID_RANGE = {"min_value": -(2**63), "max_value": 2**63 - 1}
