"""A small notes API. It exists to give the pipeline something real to evaluate."""

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field

from app import __version__

app = FastAPI(title="Sample App", version=__version__)


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    body: str = Field(default="", max_length=2000)


class Note(NoteIn):
    id: int


class NoteStore:
    """In-memory storage. The sandbox holds no real user data."""

    def __init__(self) -> None:
        self._notes: dict[int, Note] = {}
        self._next_id = 1

    def add(self, note: NoteIn) -> Note:
        saved = Note(id=self._next_id, **note.model_dump())
        self._notes[saved.id] = saved
        self._next_id += 1
        return saved

    def all(self) -> list[Note]:
        return list(self._notes.values())

    def get(self, note_id: int) -> Note | None:
        return self._notes.get(note_id)

    def remove(self, note_id: int) -> bool:
        return self._notes.pop(note_id, None) is not None

    def clear(self) -> None:
        self._notes.clear()
        self._next_id = 1


store = NoteStore()


@app.get("/health")
def health() -> dict[str, str]:
    """Polled by the Monitoring Agent every 10 seconds after a deploy (FR17)."""
    return {"status": "ok", "version": __version__}


@app.get("/notes")
def list_notes() -> list[Note]:
    return store.all()


@app.post("/notes", status_code=status.HTTP_201_CREATED)
def create_note(note: NoteIn) -> Note:
    return store.add(note)


@app.get("/notes/{note_id}")
def get_note(note_id: int) -> Note:
    note = store.get(note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="note not found")
    return note


@app.delete("/notes/{note_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_note(note_id: int) -> None:
    if not store.remove(note_id):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="note not found")
