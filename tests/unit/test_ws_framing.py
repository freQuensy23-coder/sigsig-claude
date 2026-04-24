from sigsig._proto import WebSocketResources_pb2 as ws_pb


def _serialize_request(verb: str, path: str, body: bytes, rid: int) -> bytes:
    msg = ws_pb.WebSocketMessage()
    msg.type = ws_pb.WebSocketMessage.REQUEST
    msg.request.verb = verb
    msg.request.path = path
    msg.request.body = body
    msg.request.id = rid
    return msg.SerializeToString()


def test_request_round_trip() -> None:
    raw = _serialize_request("PUT", "/api/v1/message", b"payload", 42)
    parsed = ws_pb.WebSocketMessage()
    parsed.ParseFromString(raw)
    assert parsed.type == ws_pb.WebSocketMessage.REQUEST
    assert parsed.request.verb == "PUT"
    assert parsed.request.path == "/api/v1/message"
    assert parsed.request.body == b"payload"
    assert parsed.request.id == 42


def test_response_round_trip() -> None:
    msg = ws_pb.WebSocketMessage()
    msg.type = ws_pb.WebSocketMessage.RESPONSE
    msg.response.id = 7
    msg.response.status = 200
    msg.response.message = "OK"
    raw = msg.SerializeToString()
    parsed = ws_pb.WebSocketMessage()
    parsed.ParseFromString(raw)
    assert parsed.response.id == 7
    assert parsed.response.status == 200
    assert parsed.response.message == "OK"
