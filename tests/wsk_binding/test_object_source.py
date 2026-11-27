"""Guard the prototype's actual provider call sites with source mutations."""

from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).with_name("wsk_binding.c").read_text(encoding="utf-8")


def compact_source(source):
    clean = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    return re.sub(r"\s+", "", clean)


def require_order(source, sequence, failure):
    offset = 0
    for token in sequence:
        found = source.find(token, offset)
        if found == -1:
            raise ValueError(failure)
        offset = found + len(token)


def verify_source(source):
    compact = compact_source(source)
    if not re.search(
        r"listen_dispatch->WskAccept\(listener,0,NULL,NULL,"
        r"\(PSOCKADDR\)&connection->local,NULL,connection->request\);"
        r"if\(!FbWskWait\(connection,started\)\)\{status=STATUS_IO_TIMEOUT;gotoreject;\}"
        r"status=FbWskCollectAcceptedObject\(connection\);",
        compact,
    ) or (
        "status=connection->request->IoStatus.Status;if(status==STATUS_SUCCESS)"
        "connection->bound.accepted=(PWSK_SOCKET)connection->request->IoStatus.Information;"
        not in compact
    ):
        raise ValueError("accepted object must come from WskAccept completion")
    if re.findall(r"connection->bound.accepted=(?!=)([^;]+);", compact) != [
        "(PWSK_SOCKET)connection->request->IoStatus.Information", "NULL"
    ]:
        raise ValueError("accepted object is replaced")
    if not re.search(
        r"dispatch->WskControlSocket\(connection->bound.accepted,WskIoctl,code,0,"
        r"0,NULL,capacity,output,NULL,connection->request\)",
        compact,
    ):
        raise ValueError("query must receive the owned accepted object")
    sequence = (
        "accepted_dispatch=connection->bound.accepted->Dispatch;",
        "FbWskQuery(connection,accepted_dispatch,SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,"
        "sizeof(connection->bound.context),&connection->bound.context,&context_size,started);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "if(context_size!=sizeof(connection->bound.context))",
        "FbWskQuery(connection,accepted_dispatch,SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,"
        "sizeof(connection->bound.records),connection->bound.records,&connection->bound.records_size,started);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "if(!connection->bound.records_size||connection->bound.records_size>sizeof(connection->bound.records))",
        "KeAcquireSpinLock(policy_lock,&irql);",
        "FbWskCommitAcceptedContext(policy_state,listener_epoch,&connection->bound.context)",
        "KeReleaseSpinLock(policy_lock,irql);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "*result=&connection->bound;returnSTATUS_SUCCESS;",
        "reject:*drain=connection;returnstatus;",
    )
    require_order(compact, sequence, "two successful same-object queries must precede the locked claim")


def verify_lifecycle_source(source):
    compact = compact_source(source)
    wait = compact.split("staticintFbWskWait(", 1)[1].split("staticNTSTATUS", 1)[0]
    drain = compact.split("NTSTATUSFbWskDrainBound(", 1)[1].split("NTSTATUSFbWskAcceptBound(", 1)[0]
    accept = compact.split("NTSTATUSFbWskAcceptBound(", 1)[1]
    if not re.search(
        r"timeout.QuadPart=-\(LONGLONG\)\(FB_WSK_WAIT_BUDGET_100NS-elapsed\);"
        r"returnKeWaitForSingleObject\(&connection->finished,Executive,KernelMode,FALSE,&timeout\)"
        r"==STATUS_SUCCESS&&KeQueryInterruptTime\(\)-started<FB_WSK_WAIT_BUDGET_100NS;", wait
    ):
        raise ValueError("caller wait must use the remaining completion budget")
    if compact.count("KeWaitForSingleObject(") != 2 or not re.search(
        r"LARGE_INTEGERno_wait=\{0\};.*?"
        r"KeWaitForSingleObject\(&connection->finished,Executive,KernelMode,FALSE,&no_wait\)", drain
    ):
        raise ValueError("drain may sample completion but cannot wait for it")
    if compact.count("IoCancelIrp(") != 1 or compact.count("->WskCloseSocket(") != 1:
        raise ValueError("provider cancellation and close belong only to the drain owner")
    require_order(accept, (
        "admitted=FbWskGateEnter(&lifetime->gate);",
        "if(!admitted)returnSTATUS_DEVICE_BUSY;",
        "ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*connection),FB_WSK_POOL_TAG);",
        "WskAccept(listener,0,NULL,NULL,(PSOCKADDR)&connection->local,NULL,connection->request);",
        "reject:*drain=connection;returnstatus;",
    ), "admission and nonpaged request storage must precede provider dispatch")
    require_order(drain, (
        "if(complete&&connection->operation==FbWskClose)close_status=connection->request->IoStatus.Status;",
        "FbWskNextDrainStep(connection->operation,complete,connection->cancel_requested,"
        "connection->bound.accepted!=NULL,close_status==STATUS_SUCCESS)",
        "caseFbWskRequestCancel:connection->cancel_requested=TRUE;(void)IoCancelIrp(connection->request);",
        "caseFbWskCollectAccept:(void)FbWskCollectAcceptedObject(connection);returnSTATUS_PENDING;",
        "caseFbWskDiscardQuery:connection->operation=FbWskIdle;returnSTATUS_PENDING;",
        "caseFbWskStartClose:socket=connection->bound.accepted;dispatch=socket->Dispatch;",
        "FbWskPrepare(connection,FbWskClose);connection->bound.accepted=NULL;",
        "(void)dispatch->WskCloseSocket(socket,connection->request);returnSTATUS_PENDING;",
        "caseFbWskHoldCloseFailure:returnclose_status;",
        "caseFbWskFree:returnFbWskFreeDrain(handle);",
    ), "cleanup must retain ownership through completion and quarantine failed close")
    require_order(compact, (
        "staticNTSTATUSFbWskFreeDrain(FbWskDrain**handle)",
        "IoFreeIrp(connection->request);",
        "RtlSecureZeroMemory(connection,sizeof(*connection));",
        "ExFreePoolWithTag(connection,FB_WSK_POOL_TAG);",
        "FbWskLeaveBinding(lifetime);",
    ), "storage must be reclaimed before dropping the drain gate")


class WskSourceTests(unittest.TestCase):
    def test_checked_production_shaped_calls(self):
        verify_source(SOURCE)
        verify_lifecycle_source(SOURCE)

    def test_reject_provider_provenance_and_gate_mutants(self):
        mutations = (
            ("(PWSK_SOCKET)connection->request->IoStatus.Information", "listener"),
            ("WskControlSocket(connection->bound.accepted", "WskControlSocket(bystander"),
            ("accepted_dispatch = connection->bound.accepted->Dispatch;",
             "connection->bound.accepted = bystander; accepted_dispatch = bystander->Dispatch;"),
            ("&connection->bound.context,\n                        &context_size", "caller_context, &context_size"),
            ("SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS", "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT"),
            ("if (!connection->bound.records_size ||", "if (connection->bound.records_size ||"),
            ("FbWskCommitAcceptedContext(policy_state, listener_epoch, &connection->bound.context)",
             "1"),
            ("*drain = connection;", "*drain = NULL;"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, SOURCE)
                with self.assertRaises(ValueError):
                    verify_source(SOURCE.replace(before, after, 1))

    def test_reject_lifetime_mutants(self):
        mutations = (
            ("FALSE, &timeout)", "FALSE, NULL)"),
            ("FB_WSK_WAIT_BUDGET_100NS - elapsed", "FB_WSK_WAIT_BUDGET_100NS"),
            ("LARGE_INTEGER no_wait = {0};", "LARGE_INTEGER no_wait = {-1};"),
            ("admitted = FbWskGateEnter(&lifetime->gate);", "admitted = 1;"),
            ("ExAllocatePool2(POOL_FLAG_NON_PAGED", "ExAllocatePool2(POOL_FLAG_PAGED"),
            ("(PSOCKADDR)&connection->local", "(PSOCKADDR)&temporary_local"),
            ("status = STATUS_IO_TIMEOUT;\n        goto reject;",
             "(void)IoCancelIrp(connection->request); status = STATUS_IO_TIMEOUT; goto reject;"),
            ("connection->cancel_requested = TRUE;", "connection->cancel_requested = FALSE;"),
            ("(void)FbWskCollectAcceptedObject(connection);", "connection->operation = FbWskIdle;"),
            ("FbWskPrepare(connection, FbWskClose);", "FbWskPrepare(connection, FbWskIdle);"),
            ("return close_status;", "return FbWskFreeDrain(handle);"),
            ("RtlSecureZeroMemory(connection, sizeof(*connection));",
             "FbWskLeaveBinding(lifetime);"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, SOURCE)
                with self.assertRaises(ValueError):
                    verify_lifecycle_source(SOURCE.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
