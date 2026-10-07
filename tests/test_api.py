import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api(tmp_path, monkeypatch):
    main = importlib.import_module("main")
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "test.db"))
    monkeypatch.setattr(main, "ADMIN_MASTER_TOKEN", "test-admin-token")
    monkeypatch.setattr(main, "ADMIN_PASSWORD", "test-admin-password")
    main.init_db()
    return TestClient(main.app), main


def test_todo_crud_and_search(api):
    client, _ = api
    created = client.post("/todos", json={"title": "Buy milk", "description": "2 liters"})
    assert created.status_code == 200
    todo_id = created.json()["todo_id"]

    listed = client.get("/todos")
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    searched = client.get("/todos/search", params={"q": "milk"})
    assert searched.status_code == 200
    assert searched.json()["total"] == 1

    deleted = client.delete(f"/admin/todos/{todo_id}", headers={"X-Auth-Token": "test-admin-token"})
    assert deleted.status_code == 200
    assert client.get("/todos").json()["total"] == 0


def test_sql_injection_input_is_stored_as_data(api):
    client, _ = api
    payload = "'); DROP TABLE todos; --"
    response = client.post("/todos", json={"title": payload})
    assert response.status_code == 200
    assert client.get("/todos").json()["todos"][0]["title"] == payload


def test_invalid_admin_token_is_rejected(api):
    client, _ = api
    response = client.delete("/admin/todos/1", headers={"X-Auth-Token": "wrong-token"})
    assert response.status_code in (401, 403)


def test_empty_title_is_rejected(api):
    client, _ = api
    response = client.post("/todos", json={"title": "   "})
    assert response.status_code == 400


def test_item_create_requires_admin_token(api):
    client, _ = api
    response = client.post("/api/items", json={"title": "private"})
    assert response.status_code in (401, 403)
