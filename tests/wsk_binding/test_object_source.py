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
        "KeAcquireSpinLock(owner->authority_lock,&irql);",
        "status=FbWskBrokerEpochIsLive(owner->policy.epochs,&owner->broker)&&"
        "FbWskCommitAcceptedContext(&owner->policy,&owner->target,&connection->bound.context)",
        "KeReleaseSpinLock(owner->authority_lock,irql);",
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
    if (wait + drain + accept).count("KeWaitForSingleObject(") != 2 or not re.search(
        r"LARGE_INTEGERno_wait=\{0\};.*?"
        r"KeWaitForSingleObject\(&connection->finished,Executive,KernelMode,FALSE,&no_wait\)", drain
    ):
        raise ValueError("drain may sample completion but cannot wait for it")
    if compact.count("IoCancelIrp(") != 1 or drain.count("->WskCloseSocket(") != 1:
        raise ValueError("provider cancellation and close belong only to the drain owner")
    require_order(accept, (
        "KeAcquireSpinLock(owner->authority_lock,&irql);",
        "admitted=FbWskBrokerEpochIsLive(owner->policy.epochs,&owner->broker)&&"
        "FbWskEnterArmedBinding(&owner->gate,owner->policy.armed);",
        "KeReleaseSpinLock(owner->authority_lock,irql);",
        "if(!admitted)returnSTATUS_DEVICE_BUSY;",
        "listener=owner->listener;",
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
        "FbWskLeaveBinding(owner);",
    ), "storage must be reclaimed before dropping the drain gate")


def verify_owner_source(source):
    compact = compact_source(source)
    create = compact.split("NTSTATUSFbWskCreateOwner(", 1)[1].split("staticNTSTATUSFbWskWaitForStartup", 1)[0]
    start = compact.split("NTSTATUSFbWskStartOwner(", 1)[1].split("NTSTATUSFbWskArmOwner", 1)[0]
    arm = compact.split("NTSTATUSFbWskArmOwner(", 1)[1].split("NTSTATUSFbWskLockOwnerAuthority", 1)[0]
    stop = compact.split("NTSTATUSFbWskStopOwner(", 1)[1].split("NTSTATUSFbWskAdvanceOwnerRundown", 1)[0]
    rundown = compact.split("NTSTATUSFbWskAdvanceOwnerRundown(", 1)[1].split("staticvoidFbWskLeaveBinding", 1)[0]
    require_order(create, (
        "pid=(ULONG_PTR)PsGetProcessId(listener_process);",
        "ExAllocatePool2(POOL_FLAG_NON_PAGED,sizeof(*owner),FB_WSK_OWNER_POOL_TAG);",
        "ObReferenceObject(listener_process);owner->listener_process=listener_process;",
        "owner->policy.auth=&owner->history;",
        "address->sin_port=port_be;address->sin_addr.S_un.S_un_b.s_b1=127;"
        "address->sin_addr.S_un.S_un_b.s_b4=1;",
        "address->sin6_port=port_be;RtlCopyMemory(&address->sin6_addr,FbWskLoopback6,sizeof(FbWskLoopback6));",
        "*result=owner;returnSTATUS_SUCCESS;",
    ), "creator must retain the exact process, loopback endpoint and its fresh history")
    require_order(start, (
        "if(owner->started||owner->gate.stopping)returnSTATUS_INVALID_DEVICE_STATE;",
        "status=WskRegister(&client,&owner->registration);if(status!=STATUS_SUCCESS)returnstatus;"
        "owner->registered=TRUE;",
        "status=WskCaptureProviderNPI(&owner->registration,WSK_NO_WAIT,&owner->provider);"
        "if(status!=STATUS_SUCCESS)returnstatus;owner->captured=TRUE;",
        "owner->provider.Dispatch->WskSocket(owner->provider.Client,owner->target.address_family,"
        "SOCK_STREAM,IPPROTO_TCP,WSK_FLAG_LISTEN_SOCKET,NULL,NULL,owner->listener_process,NULL,NULL,owner->request);",
        "status=FbWskWaitForStartup(owner);if(status!=STATUS_SUCCESS)returnstatus;"
        "owner->listener=(PWSK_SOCKET)owner->request->IoStatus.Information;",
        "dispatch->WskBind(owner->listener,(PSOCKADDR)&owner->local,0,owner->request);"
        "status=FbWskWaitForStartup(owner);owner->ready=status==STATUS_SUCCESS;",
    ), "listener must be created by the captured provider, then bound before arming")
    require_order(arm, (
        "KeAcquireSpinLock(owner->authority_lock,&irql);",
        "if(owner->ready&&!owner->gate.stopping&&!owner->policy.armed&&"
        "FbWskBrokerEpochIsLive(owner->policy.epochs,&owner->broker)){owner->policy.armed=1;",
        "KeReleaseSpinLock(owner->authority_lock,irql);",
    ), "arm must require a bound listener, active owner and live process epoch")
    require_order(stop, (
        "KeAcquireSpinLock(owner->authority_lock,&irql);",
        "count=FbWskDisarmOwner(&owner->gate,&owner->policy.armed);",
        "KeReleaseSpinLock(owner->authority_lock,irql);",
    ), "stop must disarm policy and admission under the authority lock")
    require_order(rundown, (
        "LARGE_INTEGERno_wait={0};",
        "KeAcquireSpinLock(owner->authority_lock,&irql);gate=owner->gate;"
        "KeReleaseSpinLock(owner->authority_lock,irql);",
        "switch(FbWskNextOwnerStep(&gate,owner->progress,owner->listener!=NULL))",
        "caseFbWskOwnerNeedsBindingDrain:returnSTATUS_DEVICE_BUSY;",
        "caseFbWskOwnerJoinUsers:status=owner->join_users(owner->barrier_context);"
        "if(status!=STATUS_SUCCESS)returnstatus;owner->progress=FbWskOwnerUsersJoined;",
        "caseFbWskOwnerCloseListener:",
        "owner->listener=NULL;owner->progress=FbWskOwnerListenerClosing;"
        "(void)dispatch->WskCloseSocket(listener,owner->request);returnSTATUS_PENDING;",
        "caseFbWskOwnerCollectListenerClose:"
        "if(KeWaitForSingleObject(&owner->finished,Executive,KernelMode,FALSE,&no_wait)!=STATUS_SUCCESS)"
        "returnSTATUS_PENDING;owner->listener_close_status=owner->request->IoStatus.Status;"
        "owner->progress=owner->listener_close_status==STATUS_SUCCESS?"
        "FbWskOwnerListenerClosed:FbWskOwnerListenerCloseFailed;",
        "caseFbWskOwnerHoldListenerCloseFailure:returnowner->listener_close_status;",
        "caseFbWskOwnerReleaseProvider:if(owner->captured){WskReleaseProviderNPI(&owner->registration);"
        "owner->captured=FALSE;}owner->progress=FbWskOwnerProviderReleased;",
        "caseFbWskOwnerDeregister:if(owner->registered){WskDeregister(&owner->registration);"
        "owner->registered=FALSE;}owner->progress=FbWskOwnerProviderDeregistered;",
        "caseFbWskOwnerWaitForCallbacks:status=owner->wait_callbacks(owner->barrier_context);"
        "if(status!=STATUS_SUCCESS)returnstatus;owner->progress=FbWskOwnerCallbacksReturned;",
        "caseFbWskOwnerFree:IoFreeIrp(owner->request);ObDereferenceObject(owner->listener_process);"
        "RtlSecureZeroMemory(owner,sizeof(*owner));ExFreePoolWithTag(owner,FB_WSK_OWNER_POOL_TAG);"
        "*handle=NULL;returnSTATUS_SUCCESS;",
    ), "rundown must join callers, close the listener, deregister and wait for callbacks before free")
    if (compact.count("->WskCloseSocket("), compact.count("WskReleaseProviderNPI("),
            compact.count("WskDeregister(")) != (2, 1, 1):
        raise ValueError("rundown operations must have a single call site per owner")


class WskSourceTests(unittest.TestCase):
    def test_checked_production_shaped_calls(self):
        verify_source(SOURCE)
        verify_lifecycle_source(SOURCE)
        verify_owner_source(SOURCE)

    def test_reject_provider_provenance_and_gate_mutants(self):
        mutations = (
            ("(PWSK_SOCKET)connection->request->IoStatus.Information", "listener"),
            ("WskControlSocket(connection->bound.accepted", "WskControlSocket(bystander"),
            ("accepted_dispatch = connection->bound.accepted->Dispatch;",
             "connection->bound.accepted = bystander; accepted_dispatch = bystander->Dispatch;"),
            ("&connection->bound.context,\n                        &context_size", "caller_context, &context_size"),
            ("SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS", "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT"),
            ("if (!connection->bound.records_size ||", "if (connection->bound.records_size ||"),
            ("FbWskCommitAcceptedContext(&owner->policy, &owner->target, &connection->bound.context)",
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
            ("LARGE_INTEGER no_wait = {0};\n    int complete;",
             "LARGE_INTEGER no_wait = {-1};\n    int complete;"),
            ("FbWskEnterArmedBinding(&owner->gate, owner->policy.armed);", "1;"),
            ("ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(*connection)",
             "ExAllocatePool2(POOL_FLAG_PAGED, sizeof(*connection)"),
            ("(PSOCKADDR)&connection->local", "(PSOCKADDR)&temporary_local"),
            ("status = STATUS_IO_TIMEOUT;\n        goto reject;",
             "(void)IoCancelIrp(connection->request); status = STATUS_IO_TIMEOUT; goto reject;"),
            ("connection->cancel_requested = TRUE;", "connection->cancel_requested = FALSE;"),
            ("(void)FbWskCollectAcceptedObject(connection);", "connection->operation = FbWskIdle;"),
            ("FbWskPrepare(connection, FbWskClose);", "FbWskPrepare(connection, FbWskIdle);"),
            ("return close_status;", "return FbWskFreeDrain(handle);"),
            ("RtlSecureZeroMemory(connection, sizeof(*connection));",
             "FbWskLeaveBinding(owner);"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, SOURCE)
                with self.assertRaises(ValueError):
                    verify_lifecycle_source(SOURCE.replace(before, after, 1))

    def test_reject_owner_mutants(self):
        mutations = (
            ("owner->policy.auth = &owner->history;", "owner->policy.auth = prior_generation;"),
            ("address->sin_addr.S_un.S_un_b.s_b1 = 127;", "address->sin_addr.S_un.S_un_b.s_b1 = 0;"),
            ("FbWskLoopback6, sizeof(FbWskLoopback6));", "wildcard6, sizeof(wildcard6));"),
            ("NULL, NULL, owner->listener_process, NULL, NULL, owner->request",
             "NULL, NULL, NULL, NULL, NULL, owner->request"),
            ("owner->listener = (PWSK_SOCKET)owner->request->IoStatus.Information;",
             "owner->listener = caller_listener;"),
            ("owner->ready = status == STATUS_SUCCESS;", "owner->ready = TRUE;"),
            ("owner->ready && !owner->gate.stopping", "owner->ready"),
            ("count = FbWskDisarmOwner(&owner->gate, &owner->policy.armed);",
             "count = FbWskGateStop(&owner->gate);"),
            ("case FbWskOwnerNeedsBindingDrain:\n            return STATUS_DEVICE_BUSY;",
             "case FbWskOwnerNeedsBindingDrain: break;"),
            ("owner->join_users(owner->barrier_context)", "STATUS_SUCCESS"),
            ("LARGE_INTEGER no_wait = {0};", "LARGE_INTEGER no_wait = {-1};"),
            ("FALSE, &no_wait) != STATUS_SUCCESS", "FALSE, &no_wait) == STATUS_SUCCESS"),
            ("? FbWskOwnerListenerClosed : FbWskOwnerListenerCloseFailed;",
             "? FbWskOwnerListenerClosed : FbWskOwnerListenerClosed;"),
            ("return owner->listener_close_status;", "owner->progress = FbWskOwnerListenerClosed; break;"),
            ("WskReleaseProviderNPI(&owner->registration);", "WskDeregister(&owner->registration);"),
            ("WskDeregister(&owner->registration);", "WskReleaseProviderNPI(&owner->registration);"),
            ("owner->wait_callbacks(owner->barrier_context)", "STATUS_SUCCESS"),
            ("case FbWskOwnerFree:\n            IoFreeIrp(owner->request);",
             "case FbWskOwnerFree:\n            return STATUS_SUCCESS;"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, SOURCE)
                with self.assertRaises(ValueError):
                    verify_owner_source(SOURCE.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
