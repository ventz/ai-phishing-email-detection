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


def test_mark_sending_is_token_scoped(dynamo):
    fake = dynamo()
    idem = services.Idempotency("t")
    token = idem.claim("b/k")
    idem.mark_sending("b/k", token)
    op, kw = fake.calls[-1]
    assert op == "update" and kw["ExpressionAttributeValues"][":g"] == {"S": "sending"}
    assert kw["ExpressionAttributeValues"][":t"] == {"S": token}


def test_sending_record_blocks_any_retry(dynamo):
    dynamo({"status": {"S": "sending"}})
    assert services.Idempotency("t").claim("b/k") is None  # never re-send after a send began


def test_ses_error_response_is_send_rejected(monkeypatch):
    from phishing_detector.render import Reply

    class FakeSES:
        def send_email(self, **kw):
            raise ClientError(
                {"Error": {"Code": "Throttling"}, "ResponseMetadata": {"HTTPStatusCode": 429}}, "SendEmail"
            )

    monkeypatch.setitem(services._clients, "sesv2", FakeSES())
    with pytest.raises(services.SendRejected):
        services.send_reply(Reply("s", "<p>h</p>", "t"), sender="a@b.c", to="d@e.f", configuration_set=None)


def test_threading_headers_are_added(monkeypatch):
    from phishing_detector.render import Reply

    sent = {}

    class FakeSES:
        def send_email(self, **kw):
            sent.update(kw)
            return {"MessageId": "m"}

    monkeypatch.setitem(services._clients, "sesv2", FakeSES())
    services.send_reply(Reply("s", "h", "t"), sender="a@b.c", to="d@e.f", configuration_set=None, in_reply_to="<x@y>")
    names = {h["Name"]: h["Value"] for h in sent["Content"]["Simple"]["Headers"]}
    assert names == {"Auto-Submitted": "auto-replied", "In-Reply-To": "<x@y>", "References": "<x@y>"}


def test_ses_5xx_is_ambiguous_not_rejected(monkeypatch):
    from phishing_detector.render import Reply

    class FakeSES:
        def send_email(self, **kw):
            raise ClientError({"Error": {"Code": "InternalFailure"}, "ResponseMetadata": {"HTTPStatusCode": 500}}, "x")

    monkeypatch.setitem(services._clients, "sesv2", FakeSES())
    with pytest.raises(ClientError) as info:
        services.send_reply(Reply("s", "h", "t"), sender="a@b.c", to="d@e.f", configuration_set=None)
    assert not isinstance(info.value, services.SendRejected)


def test_malformed_message_id_is_not_sent_as_a_header(monkeypatch):
    from phishing_detector.render import Reply

    sent = {}

    class FakeSES:
        def send_email(self, **kw):
            sent.update(kw)
            return {"MessageId": "m"}

    monkeypatch.setitem(services._clients, "sesv2", FakeSES())
    services.send_reply(Reply("s", "h", "t"), sender="a@b.c", to="d@e.f", configuration_set=None, in_reply_to="<ü@x>")
    assert [h["Name"] for h in sent["Content"]["Simple"]["Headers"]] == ["Auto-Submitted"]
