"""The abstract Agent: run a step, validate its output against a schema, retry (FR9)."""

import logging
from abc import ABC, abstractmethod
from collections.abc import Mapping
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from devsecops.models import AgentResult, AgentStatus
from devsecops.tools.base import ToolError

log = logging.getLogger(__name__)


class Agent(ABC):
    """Subclasses implement ``run``. Callers use ``execute``, which never raises."""

    name: ClassVar[str]
    output_model: ClassVar[type[BaseModel]]

    def __init__(self, schema_retries: int = 2) -> None:
        self._schema_retries = schema_retries

    @abstractmethod
    def run(self, state: Mapping[str, Any], **options: Any) -> Any:
        """Do the work and return the output: an ``output_model`` instance or a dict."""

    def status_of(self, output: Any) -> AgentStatus:
        """OK or FAILED for a valid output. FAILED means the change failed the check."""
        return AgentStatus.OK

    def summarize(self, output: Any) -> str:
        return ""

    def execute(self, state: Mapping[str, Any], **options: Any) -> AgentResult:
        """FR9: output that does not match the schema is retried ``schema_retries`` times.
        After that, or when a tool crashes, the result has status ERROR (which escalates)."""
        errors: list[str] = []
        for attempt in range(1, self._schema_retries + 2):
            try:
                output = self.output_model.model_validate(self.run(state, **options))
            except ValidationError as exc:
                problems = "; ".join(
                    f"{'.'.join(str(p) for p in err['loc'])}: {err['msg']}" for err in exc.errors()
                )
                errors.append(f"attempt {attempt}: output does not match the schema: {problems}")
                continue
            except ToolError as exc:
                return self._error([f"tool error: {exc}"])
            except Exception as exc:  # noqa: BLE001 - an agent must never crash the pipeline
                log.exception("%s agent crashed", self.name)
                return self._error([f"unexpected {type(exc).__name__}: {exc}"])
            return AgentResult(
                agent=self.name,
                status=self.status_of(output),
                summary=self.summarize(output),
                data=output.model_dump(mode="json"),
            )
        retries = self._schema_retries
        return self._error([f"output failed schema validation after {retries} retries", *errors])

    def _error(self, errors: list[str]) -> AgentResult:
        return AgentResult(
            agent=self.name, status=AgentStatus.ERROR, summary=errors[0][:300], errors=errors
        )
