import pytest
from botocore.exceptions import ClientError

from phishing_detector import services


class FakeDynamo:
    def __init__(self, existing=None):
        self.existing = existing
        self.calls = []

    def put_item(self, **kw):
        self.calls.append(("put", kw))
        if self.existing is not None:
            err = {"Error": {"Code": "ConditionalCheckFailedException"}, "Item": self.existing}
            raise ClientError(err, "PutItem")

    def update_item(self, **kw):
        self.calls.append(("update", kw))

    def delete_item(self, **kw):
        self.calls.append(("delete", kw))


@pytest.fixture
def dynamo(monkeypatch):
    def install(existing=None):
        fake = FakeDynamo(existing)
        monkeypatch.setitem(services._clients, "dynamodb", fake)
        return fake

    return install


def test_claim_complete_release_are_token_scoped(dynamo):
    fake = dynamo()
    idem = services.Idempotency("t", stale_after=240)
    token = idem.claim("b/k")
    assert token
    idem.complete("b/k", token, "phishing")
    idem.release("b/k", token)
    for op, kw in fake.calls[1:]:
        assert kw["ExpressionAttributeValues"][":t"] == {"S": token}, op


def test_done_record_is_a_duplicate(dynamo):
    dynamo({"status": {"S": "done"}})
    assert services.Idempotency("t").claim("b/k") is None


def test_fresh_in_progress_claim_raises(dynamo):
    dynamo({"status": {"S": "in_progress"}})
    with pytest.raises(services.InFlight):
        services.Idempotency("t").claim("b/k")


def test_no_table_always_claims():
    assert services.Idempotency(None).claim("b/k")
