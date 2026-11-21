"""The range of ids that the API accepts."""

# The range of the 64-bit integers the databases store; a larger value would
# fail in the database instead of in the API's validation.
ID_RANGE = {"min_value": -(2**63), "max_value": 2**63 - 1}

# A path id of at most 18 digits, so it fits a signed 64-bit integer in the
# query; a longer one answers 404 instead of failing in the database.
ID_PATH_PATTERN = "[0-9]{1,18}"
