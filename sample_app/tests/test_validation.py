"""What the API refuses: the length limits and required fields of a note."""

import pytest
from fastapi.testclient import TestClient

from app.main import app, store


@pytest.fixture
def client():
    store.clear()
    return TestClient(app)


def test_note_without_a_title_is_rejected(client):
    response = client.post("/notes", json={"body": "no title"})
    assert response.status_code == 422
    assert client.get("/notes").json() == []


def test_empty_title_is_rejected(client):
    assert client.post("/notes", json={"title": ""}).status_code == 422


def test_title_may_be_100_characters_but_not_101(client):
    assert client.post("/notes", json={"title": "t" * 100}).status_code == 201
    assert client.post("/notes", json={"title": "t" * 101}).status_code == 422


def test_body_may_be_2000_characters_but_not_2001(client):
    assert client.post("/notes", json={"title": "a", "body": "b" * 2000}).status_code == 201
    assert client.post("/notes", json={"title": "a", "body": "b" * 2001}).status_code == 422


def test_note_id_must_be_a_number(client):
    assert client.get("/notes/abc").status_code == 422
    assert client.delete("/notes/abc").status_code == 422
