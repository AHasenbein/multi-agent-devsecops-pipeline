"""The reviewer's answer for an escalated run (FR14, invariant 8)."""

import logging
from collections.abc import Callable
from typing import Any

from fastapi import APIRouter, HTTPException, status

from devsecops.api.schemas import ApprovalAccepted, ApprovalRequest
from devsecops.models import Verdict
from devsecops.orchestrator.approval_service import ApprovalRefused, ApprovalService

log = logging.getLogger(__name__)

Submit = Callable[[Callable[[], Any]], Any]


def approvals_router(service: ApprovalService, submit: Submit) -> APIRouter:
    router = APIRouter(prefix="/runs", tags=["approvals"])

    @router.post("/approval")
    def answer_review(request: ApprovalRequest) -> ApprovalAccepted:
        try:
            approval, continue_run = service.submit(
                request.run_id,
                request.commit_sha.lower(),
                request.reviewer,
                Verdict(request.verdict),
            )
        except ApprovalRefused as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc

        def finish() -> None:
            try:
                continue_run()  # an approved push deploys and is monitored here
            except Exception:  # noqa: BLE001 - nothing above us would report it
                log.exception("run %s failed while resuming", approval.run_id)

        submit(finish)
        return ApprovalAccepted(
            run_id=approval.run_id, reviewer=approval.reviewer, verdict=approval.verdict.value
        )

    return router
