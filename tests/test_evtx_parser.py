"""Tests for the EVTX parser (XML-to-dict and record parsing)."""

from datetime import datetime

from threatlens.parsers.evtx_parser import _parse_evtx_record, _xml_to_dict

SAMPLE_XML = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <TimeCreated SystemTime="2025-01-15T08:30:01Z"/>
    <Computer>WS-PC01</Computer>
    <Channel>Security</Channel>
  </System>
  <EventData>
    <Data Name="TargetUserName">admin</Data>
    <Data Name="IpAddress">10.0.1.50</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>
"""

SAMPLE_XML_USERDATA = """\
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Some-Provider"/>
    <EventID>5156</EventID>
    <TimeCreated SystemTime="2025-03-10T07:10:00Z"/>
    <Computer>WEB-SVR01</Computer>
  </System>
  <UserData>
    <EventXML xmlns="http://custom/ns">
      <SourceAddress>203.0.113.50</SourceAddress>
      <DestPort>443</DestPort>
    </EventXML>
  </UserData>
</Event>
"""


class TestXmlToDict:
    def test_basic_event(self):
        result = _xml_to_dict(SAMPLE_XML)
        assert result["EventID"] == "4625"
        assert result["Computer"] == "WS-PC01"
        assert result["Source"] == "Microsoft-Windows-Security-Auditing"
        assert result["EventData"]["TargetUserName"] == "admin"
        assert result["EventData"]["IpAddress"] == "10.0.1.50"

    def test_userdata_fallback(self):
        result = _xml_to_dict(SAMPLE_XML_USERDATA)
        assert result["EventID"] == "5156"
        assert result["EventData"]["SourceAddress"] == "203.0.113.50"

    def test_invalid_xml_returns_empty(self):
        result = _xml_to_dict("not valid xml")
        assert result == {}


class TestParseEvtxRecord:
    def test_parse_basic_record(self):
        record_dict = _xml_to_dict(SAMPLE_XML)
        event = _parse_evtx_record(record_dict)
        assert event.event_id == 4625
        assert event.computer == "WS-PC01"
        assert event.target_username == "admin"
        assert event.source_ip == "10.0.1.50"
        assert event.logon_type == 3
        assert event.timestamp.year == 2025

    def test_parse_with_missing_fields(self):
        record_dict = {"EventID": "4688", "TimeCreated": "2025-01-15T09:00:00Z"}
        event = _parse_evtx_record(record_dict)
        assert event.event_id == 4688
        assert event.username == ""
        assert event.source_ip == ""

    def test_parse_invalid_event_id(self):
        record_dict = {"EventID": "abc", "TimeCreated": "2025-01-15T09:00:00Z"}
        event = _parse_evtx_record(record_dict)
        assert event.event_id == 0

    def test_parse_invalid_timestamp(self):
        record_dict = {"EventID": "4624", "TimeCreated": "invalid"}
        event = _parse_evtx_record(record_dict)
        assert event.timestamp == datetime.min

    def test_get_reads_from_top_level(self):
        """_get should find values at the record_dict top level too."""
        record_dict = {
            "EventID": "4624",
            "TimeCreated": "2025-01-15T09:00:00Z",
            "Source": "Security",
            "Computer": "WS-01",
            "SubjectUserName": "admin",
        }
        event = _parse_evtx_record(record_dict)
        assert event.username == "admin"


class TestEnsureEvtxAvailable:
    def test_evtx_not_installed(self):
        from unittest.mock import patch

        from threatlens.parsers.evtx_parser import _ensure_evtx_available

        with (
            patch.dict("sys.modules", {"Evtx": None}),
            patch("builtins.__import__", side_effect=ImportError("no evtx")),
        ):
            result = _ensure_evtx_available()
        assert result is False


class TestLoadEvtxEvents:
    def test_load_without_evtx(self):
        from pathlib import Path
        from unittest.mock import patch

        from threatlens.parsers.evtx_parser import load_evtx_events

        with patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=False):
            result = load_evtx_events(Path("fake.evtx"))
        assert result == []

    def test_load_mocked_evtx(self):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from threatlens.parsers.evtx_parser import load_evtx_events

        xml = SAMPLE_XML
        mock_record = MagicMock()
        mock_record.xml.return_value = xml

        mock_log = MagicMock()
        mock_log.__enter__ = MagicMock(return_value=mock_log)
        mock_log.__exit__ = MagicMock(return_value=False)
        mock_log.records.return_value = [mock_record]

        mock_evtx_mod = MagicMock()
        mock_evtx_mod.Evtx.return_value = mock_log

        with (
            patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=True),
            patch.dict("sys.modules", {"Evtx.Evtx": mock_evtx_mod}),
        ):
            events = load_evtx_events(Path("fake.evtx"))
        assert len(events) == 1
        assert events[0].event_id == 4625

    def test_load_evtx_exception_in_record(self):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from threatlens.parsers.evtx_parser import load_evtx_events

        mock_record = MagicMock()
        mock_record.xml.side_effect = RuntimeError("corrupt record")

        mock_log = MagicMock()
        mock_log.__enter__ = MagicMock(return_value=mock_log)
        mock_log.__exit__ = MagicMock(return_value=False)
        mock_log.records.return_value = [mock_record]

        mock_evtx_mod = MagicMock()
        mock_evtx_mod.Evtx.return_value = mock_log

        with (
            patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=True),
            patch.dict("sys.modules", {"Evtx.Evtx": mock_evtx_mod}),
        ):
            events = load_evtx_events(Path("fake.evtx"))
        assert events == []


class TestStreamEvtxEvents:
    def test_stream_without_evtx(self):
        from pathlib import Path
        from unittest.mock import patch

        from threatlens.parsers.evtx_parser import stream_evtx_events

        with patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=False):
            result = list(stream_evtx_events(Path("fake.evtx")))
        assert result == []

    def test_stream_mocked_evtx(self):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from threatlens.parsers.evtx_parser import stream_evtx_events

        xml = SAMPLE_XML
        mock_record = MagicMock()
        mock_record.xml.return_value = xml

        mock_log = MagicMock()
        mock_log.__enter__ = MagicMock(return_value=mock_log)
        mock_log.__exit__ = MagicMock(return_value=False)
        mock_log.records.return_value = [mock_record]

        mock_evtx_mod = MagicMock()
        mock_evtx_mod.Evtx.return_value = mock_log

        with (
            patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=True),
            patch.dict("sys.modules", {"Evtx.Evtx": mock_evtx_mod}),
        ):
            events = list(stream_evtx_events(Path("fake.evtx")))
        assert len(events) == 1
        assert events[0].event_id == 4625

    def test_stream_evtx_exception_in_record(self):
        from pathlib import Path
        from unittest.mock import MagicMock, patch

        from threatlens.parsers.evtx_parser import stream_evtx_events

        mock_record = MagicMock()
        mock_record.xml.side_effect = RuntimeError("corrupt")

        mock_log = MagicMock()
        mock_log.__enter__ = MagicMock(return_value=mock_log)
        mock_log.__exit__ = MagicMock(return_value=False)
        mock_log.records.return_value = [mock_record]

        mock_evtx_mod = MagicMock()
        mock_evtx_mod.Evtx.return_value = mock_log

        with (
            patch("threatlens.parsers.evtx_parser._ensure_evtx_available", return_value=True),
            patch.dict("sys.modules", {"Evtx.Evtx": mock_evtx_mod}),
        ):
            events = list(stream_evtx_events(Path("fake.evtx")))
        assert events == []
