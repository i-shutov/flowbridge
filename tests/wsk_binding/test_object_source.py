"""Guard the prototype's actual provider call sites with source mutations."""

from pathlib import Path
import re
import unittest


SOURCE = Path(__file__).with_name("wsk_binding.c").read_text(encoding="utf-8")


def verify_source(source):
    clean = re.sub(r"/\*.*?\*/", "", source, flags=re.S)
    compact = re.sub(r"\s+", "", clean)
    if not re.search(
        r"listen_dispatch->WskAccept\(listener,0,NULL,NULL,"
        r"\(PSOCKADDR\)&local,NULL,connection->request\);"
        r"completed=FbWskWait\(connection,TRUE\);"
        r"status=connection->request->IoStatus.Status;"
        r"if\(status==STATUS_SUCCESS\)"
        r"connection->accepted=\(PWSK_SOCKET\)connection->request->IoStatus.Information;",
        compact,
    ):
        raise ValueError("accepted object must come from WskAccept completion")
    if len(re.findall(r"connection->accepted=(?!=)", compact)) != 1:
        raise ValueError("accepted object is replaced")
    if not re.search(
        r"dispatch->WskControlSocket\(connection->accepted,WskIoctl,code,0,"
        r"0,NULL,capacity,output,NULL,connection->request\)",
        compact,
    ):
        raise ValueError("query must receive the owned accepted object")
    sequence = (
        "accepted_dispatch=connection->accepted->Dispatch;",
        "FbWskQuery(connection,accepted_dispatch,SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,"
        "sizeof(connection->context),&connection->context,&context_size);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "if(context_size!=sizeof(connection->context))",
        "FbWskQuery(connection,accepted_dispatch,SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,"
        "sizeof(connection->records),connection->records,&connection->records_size);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "if(!connection->records_size||connection->records_size>sizeof(connection->records))",
        "KeAcquireSpinLock(policy_lock,&irql);",
        "FbWskCommitAcceptedContext(policy_state,listener_epoch,&connection->context)",
        "KeReleaseSpinLock(policy_lock,irql);",
        "if(status!=STATUS_SUCCESS)gotoreject;",
        "*result=connection;returnSTATUS_SUCCESS;",
        "reject:(void)FbWskReleaseBound(connection);returnstatus;",
    )
    offset = 0
    for token in sequence:
        found = compact.find(token, offset)
        if found == -1:
            raise ValueError("two successful same-object queries must precede the locked claim")
        offset = found + len(token)


class WskSourceTests(unittest.TestCase):
    def test_checked_production_shaped_calls(self):
        verify_source(SOURCE)

    def test_reject_provider_provenance_and_gate_mutants(self):
        mutations = (
            ("(PWSK_SOCKET)connection->request->IoStatus.Information", "listener"),
            ("WskControlSocket(connection->accepted", "WskControlSocket(bystander"),
            ("accepted_dispatch = connection->accepted->Dispatch;",
             "connection->accepted = bystander; accepted_dispatch = bystander->Dispatch;"),
            ("&connection->context, &context_size", "caller_context, &context_size"),
            ("SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS", "SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT"),
            ("if (!connection->records_size ||", "if (connection->records_size ||"),
            ("FbWskCommitAcceptedContext(policy_state, listener_epoch, &connection->context)",
             "1"),
            ("(void)FbWskReleaseBound(connection);", "(void)0;"),
        )
        for before, after in mutations:
            with self.subTest(before=before):
                self.assertIn(before, SOURCE)
                with self.assertRaises(ValueError):
                    verify_source(SOURCE.replace(before, after, 1))


if __name__ == "__main__":
    unittest.main()
