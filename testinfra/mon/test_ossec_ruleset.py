def test_ossec_keep_alive_mark_does_not_produce_alert(Command, Sudo):
    """Check that OSSEC keep alive messages sent to the OSSEC manager
    do not produce OSSEC alerts.

    For more information see:
    https://github.com/ossec/ossec-hids/issues/466
    http://ossec-docs.readthedocs.io/en/latest/faq/alerts.html
    """

    # Example alert from:
    # https://groups.google.com/forum/#!msg/ossec-list/dE3klm84JMU/kGZkRdSl3ZkJ
    test_alert = ("Dec 02 09:48:40 app-staging ossec-keepalive: --MARK--: "
                  "&pQSW__BPa5S?%tyDTJ3-iCG2lz2dU))r(F%6tjp8wqpf=]IKFT%ND2k"
                  "P]ua/W)3-6'eHduX$;$Axqq7Vr.dVZ1SUDSaH)4xTXCIieaEKv47LD-b"
                  "U)SXMnXO/jPGKn3.!NGBR_5]jD2UoSV9)h%z8G%7.xhI;s)267.rV214"
                  "O@t2#w)Z(k'UQp9]MyDERrOrG[-,e?iS@B3Rg/kGiR[g6mc0K)/]S]0'"
                  "+?+'/.[r$fqBR^7iAjoPv4j6SWjeRsLGr%$3#p+buf&u_RC3i/mE3vS3*"
                  "jp&B1qSJM431TmEg,YJ][ge;6-dJI69?-TB?!BI4?Uza63V3vMY3ake6a"
                  "hj-%A-m_5lgab!OVR,!pR+;L]eLgilU")

    with Sudo():
        c = Command('echo "{}" | /var/ossec/bin/ossec-logtest'.format(
                    test_alert))

        assert "Alert to be generated" not in c.stderr
